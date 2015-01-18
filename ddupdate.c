/*
 * ddupdate.c - update the external ip on DNSdynamic.org
 *
 * COPYRIGHT
 *
 * Copyright (C) 2014 David Azarewicz <david@88watts.net>
 *
 * LICENSE
 *
 * This source code is provided to you with absolutely no warranty whatsoever.
 * There is no guarantee that you will be able to use this code, or build the
 * program, or use it in any way. It is provided solely as a reference so that
 * you may understand how the program works.
 *
 * You may copy this source code, use it in derivative works, or use it in any
 * other way, provided the copyright notice above is not removed.
 *
 * The author is not responsible in any way for any problem caused by this
 * software, whether it is used correctly or not.
 */

#define INCL_WINSHELLDATA
#include <os2.h>

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <time.h>

#include <types.h>
#include <netdb.h>
#include <sys/socket.h>
#include "e:\os2tk40\h\netinet/in.h"
#include <tcpustd.h>
//#include <sys/itypes.h>
#include <azarproto.h>


struct _global {
  short sForce;
  short sShow;
  short sVerbose;
  char achHost[256];
  char achLogin[64];
  char achPassword[32];
} Global;

CMDARGS CmdArgs[] = {
  "f",   0, CARG_TYPE_SHORT_FLAG,   &Global.sForce, " : force an update even if not needed.",
  "s",   0, CARG_TYPE_SHORT_FLAG,   &Global.sShow, " : show stored data only. No update attempted.",
  "v",   2, CARG_TYPE_SHORT,      &Global.sVerbose, "<n> : verbose output (0-9). Default=1",
  NULL,  0, sizeof(Global.achHost),   Global.achHost, "Host",
  NULL,  0, sizeof(Global.achLogin),  Global.achLogin, "Login",
  NULL,  0, sizeof(Global.achPassword), Global.achPassword, "Password",
};
#define N_CMDARGS (sizeof(CmdArgs)/sizeof(CMDARGS))

#define APP_VERSION "1.1"
#define PRF_APP_NAME "DDUpdate"
#define PRF_KEY "Settings"
#define DNS_PORT 80
#define ECHO_PORT 80
static struct sockaddr_in saSockAdrIn;
static struct hostent *phHost;
static int iSocket;
static int iLength;
static char achBuf[4096];
static char achAuthorization[128];
static char achUserAgent[] = PRF_APP_NAME "/" APP_VERSION " david@88watts.net";
static char achMyIpServer[] = "myip.dnsdynamic.org";
static char achMyIpURL[] = "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n";
static char achDnsServer[] = "www.dnsdynamic.org";
// https://username:password@www.dnsdynamic.org/api/?hostname=techno.ns360.info&myip=127.0.0.1
static char achDnsURL[] = "GET /api/?hostname=%s&myip=%s HTTP/1.1\r\nHost: %s\r\nAuthorization: Basic %s\r\nUser-Agent: %s\r\n\r\n";
static char achMyDotIP[24];
static unsigned short usHostId;
static time_t ttTimeNow;

#define MAX_HOSTS 4
static struct _Settings {
  unsigned short usSize;
  unsigned short usnHosts;
  unsigned long ulMyIP;
  time_t ttLastIPQueryTime;
  struct _host {
    char achHost[64];
    unsigned long ulHostIP;
    time_t ttLastDNSQueryTime;
    time_t ttLastUpdateTime;
  } Host[MAX_HOSTS];
} Settings;

static char achCmdMsg[] =
"DDUPDATE V" APP_VERSION " 29-May-2014 Updates a dynamic host on DNSdynamic.org\n\
Written by David Azarewicz www.88watts.net\n\
Usage: ddupdate [options] host username password\n\
       ddupdate -s\n";

static char HelpMsg[] =
"\nGets the external IP address, checks it against the given host, and updates\n\
DNSdynamic.org if necessary. Information on the last 4 hosts are saved in\n\
OS2.INI.\n\n\
This is a single execution updater, not a stay-resident looping program. It\n\
is intended to be executed once daily as needed and is not intended to be\n\
included in a program loop. This program will not permit DNS or IP lookups\n\
more frequently than 10 minutes.\n";


unsigned short FindHost(char *pchHost) {
  unsigned short usTmp, usOldest;
  time_t ttTime;

  ttTime = 0xffffffff;
  usOldest = 0;
  for (usTmp=0; usTmp<Settings.usnHosts; usTmp++) {
    if (stricmp(Settings.Host[usTmp].achHost, pchHost) == 0) return(usTmp);
    if (Settings.Host[usTmp].ttLastUpdateTime < ttTime) {
      usOldest = usTmp;
      ttTime = Settings.Host[usTmp].ttLastUpdateTime;
    }
  }
  if (Settings.usnHosts < MAX_HOSTS) {
    usOldest = Settings.usnHosts;
    Settings.usnHosts++;
  }
  memset(&Settings.Host[usOldest], 0, sizeof(Settings.Host[0]));
  strcpy(Settings.Host[usOldest].achHost, pchHost);
  Settings.Host[usOldest].ttLastUpdateTime = ttTimeNow;
  return(usOldest);
}

void PrintIPadr(char *str, unsigned long IPadr) {
  union _u1 {
    unsigned long ul;
    unsigned char uc[4];
  } cv;

  cv.ul = IPadr;
  printf("%s: %u.%u.%u.%u\n", str, cv.uc[0], cv.uc[1], cv.uc[2], cv.uc[3]);
}

void FormatIPadr(char *str, unsigned long IPadr) {
  union _u1 {
    unsigned long ul;
    unsigned char uc[4];
  } cv;

  cv.ul = IPadr;
  sprintf(str, "%u.%u.%u.%u", cv.uc[0], cv.uc[1], cv.uc[2], cv.uc[3]);
}

int main(int argc, char **argv) {
  unsigned short usTmp;
  short sTmp;
  char *pCh, *pCh2;
  unsigned long ulSize;
  long rc;


  memset(&Global, 0, sizeof(Global));
  Global.sVerbose = 1;
  sTmp = ParseCmdArgs(argv, &CmdArgs, N_CMDARGS, stdout);
  if (!Global.sShow) {
    if (*Global.achHost == 0) sTmp = 1;
    if (*Global.achLogin == 0) sTmp = 1;
    if (*Global.achPassword == 0) sTmp = 1;
  }

  if (sTmp) {
    printf(achCmdMsg);
    ParseCmdPrintSwitchHelp(&CmdArgs, N_CMDARGS, stdout);
    printf(HelpMsg);
    exit(0);
  }

  if (Global.sShow) Global.sVerbose = 5;

  ttTimeNow = time(NULL);

  /* get settings from INI */
  ulSize = sizeof(Settings);
  rc =  PrfQueryProfileData(HINI_USERPROFILE, PRF_APP_NAME, PRF_KEY, &Settings, &ulSize);
  if ((!rc) || Settings.usSize != sizeof(Settings)) {
    memset(&Settings, 0, sizeof(Settings));
    Settings.usSize = sizeof(Settings);
  }
  if (Global.sVerbose >= 5) {
    printf("Stored Data:\n");
    PrintIPadr(" My IP", Settings.ulMyIP);
    printf(" Last IP query: %s", ctime(&Settings.ttLastIPQueryTime));

    for (usTmp=0; usTmp<Settings.usnHosts; usTmp++) {
      printf("\n Host: %s\n", Settings.Host[usTmp].achHost);
      PrintIPadr("  IP", Settings.Host[usTmp].ulHostIP);
      printf("  Last DNS query: %s", ctime(&Settings.Host[usTmp].ttLastDNSQueryTime));
      printf("  Last Host update: %s", ctime(&Settings.Host[usTmp].ttLastUpdateTime));
    }
  }
  if (Global.sShow) exit(0);
  usHostId = FindHost(Global.achHost);

  sock_init(); /* Initialize sockets */

  if ( (Settings.Host[usHostId].ulHostIP == 0) || Global.sForce ||
    (ttTimeNow > (Settings.Host[usHostId].ttLastDNSQueryTime+600)) ) {
    /* get Host's IP address */
    if (Global.sVerbose >= 2) printf("Performing DNS query for %s\n", Global.achHost);
    phHost = gethostbyname(Global.achHost);
    if (phHost == NULL) {
      printf("Can't find address for server %s\n", Global.achHost);
      exit(1);
    }
    Settings.Host[usHostId].ulHostIP = *(unsigned long *)phHost->h_addr_list[0];
    if (Global.sVerbose >= 3) PrintIPadr(phHost->h_name, Settings.Host[usHostId].ulHostIP);
    Settings.Host[usHostId].ttLastDNSQueryTime = ttTimeNow;
    PrfWriteProfileData(HINI_USERPROFILE, PRF_APP_NAME, PRF_KEY, &Settings, sizeof(Settings));
  }

  if ((Settings.ulMyIP == 0) || (ttTimeNow > (Settings.ttLastIPQueryTime+600)) || Global.sForce) {
    /* get our external IP address */
    if (Global.sVerbose >= 2) printf("Performing My IP lookup\n");
    phHost = gethostbyname(achMyIpServer);
    if (phHost == NULL) {
      printf("Can't find address for server %s\n", achMyIpServer);
      exit(1);
    }
    if (Global.sVerbose >= 4) PrintIPadr(phHost->h_name, *(unsigned long *)phHost->h_addr_list[0]);

    memset(&saSockAdrIn, 0, sizeof(saSockAdrIn));
    saSockAdrIn.sin_family = phHost->h_addrtype;
    saSockAdrIn.sin_addr.s_addr = *(unsigned long*)phHost->h_addr_list[0];
    saSockAdrIn.sin_port = htons(ECHO_PORT);

    /* Now, create socket */
    if ( (iSocket = socket(PF_INET, SOCK_STREAM, 0) ) < 0) { /* Get a socket */
      psock_errno("Socket creation error");
      return(EXIT_FAILURE);
    }
    if (connect(iSocket, (struct sockaddr *)&saSockAdrIn, sizeof(saSockAdrIn) ) < 0) {
      sprintf(achBuf, "Failed to connect to %s", achMyIpServer);
      psock_errno(achBuf);
      soclose(iSocket);
      return(EXIT_FAILURE);
    }
    sprintf(achBuf, achMyIpURL, achMyIpServer, achUserAgent);
    if (Global.sVerbose >= 8) printf("---------- Sending ----------\n%s------------------------------\n", achBuf);
    if (send(iSocket, achBuf, strlen(achBuf), 0) < 0) {
      sprintf(achBuf, "Failed to send data to %s", achMyIpServer);
      psock_errno(achBuf);
      soclose(iSocket);
      return(EXIT_FAILURE);
    }
    if ( (iLength = recv(iSocket, achBuf, sizeof(achBuf)-1, 0)) <= 0) {
      sprintf(achBuf, "No response from %s", achMyIpServer);
      psock_errno(achBuf);
      soclose(iSocket);
      return(EXIT_FAILURE);
    }
    achBuf[iLength] = '\0'; /* terminate msg  */

    /* And close socket, free allocated space */
    soclose(iSocket);
    if (Global.sVerbose >= 8) printf("---------- Received ----------\n%s------------------------------\n", achBuf);

    /* get the IP from the message */
    if ((pCh = strstr(achBuf, "\r\n\r\n")) == NULL) {
      printf("Invalid response from %s\n", achMyIpServer);
      exit(1);
    }
    pCh += 4; /* Skip the \r\n\r\n */
    Settings.ulMyIP = inet_addr(pCh);
    if (Global.sVerbose >= 3) PrintIPadr("My IP", Settings.ulMyIP);
    Settings.ttLastIPQueryTime = ttTimeNow;
    PrfWriteProfileData(HINI_USERPROFILE, PRF_APP_NAME, PRF_KEY, &Settings, sizeof(Settings));
  }

  while (Settings.ulMyIP == Settings.Host[usHostId].ulHostIP) {
    if (Global.sVerbose >= 1) printf("IPs are the same. No update needed.\n");
    if (Global.sForce) break;
    #ifdef UPDATE_28DAYS
    if (ttTimeNow > (Settings.Host[usHostId].ttLastUpdateTime+(28*24*60*60))) {
      if (Global.sVerbose >= 1) printf("It has been longer than 28 days. Updating to prevent timeout.\n");
      break;
    }
    #endif
    exit(0);
  }
  if (Global.sVerbose >= 1) printf("Updating Host.\n");

  /* update the DNSdynamic */
  phHost = gethostbyname(achDnsServer);
  if (phHost == NULL) {
    printf("Can't find address for server %s\n", achDnsServer);
    exit(1);
  }
  if (Global.sVerbose >= 5) PrintIPadr(phHost->h_name, *(unsigned long *)phHost->h_addr_list[0]);

  memset(&saSockAdrIn, 0, sizeof(saSockAdrIn));
  saSockAdrIn.sin_family = phHost->h_addrtype;
  saSockAdrIn.sin_addr.s_addr = *(unsigned long*)phHost->h_addr_list[0];
  saSockAdrIn.sin_port = htons(DNS_PORT);
  if (Global.sVerbose >= 9) DumpBuffer(stdout, "Connect:\n", (PBYTE)&saSockAdrIn, sizeof(saSockAdrIn));

  /* Now, create socket */
  if ( (iSocket = socket(AF_INET, SOCK_STREAM, 0) ) < 0) { /* Get a socket */
      psock_errno("Socket creation error");
      return(EXIT_FAILURE);
  }
  if (connect(iSocket, (struct sockaddr *)&saSockAdrIn, sizeof(saSockAdrIn) ) < 0) {
    sprintf(achBuf, "Failed to connect to %s", achDnsServer);
    psock_errno(achBuf);
    soclose(iSocket);
    return(EXIT_FAILURE);
  }
  FormatIPadr(achMyDotIP, Settings.ulMyIP);
  /* calculate authorization */
  sprintf(achBuf, "%s:%s", Global.achLogin, Global.achPassword);
  Base64Encode(achBuf, strlen(achBuf), achAuthorization, sizeof(achAuthorization));
  if (Global.sVerbose >= 9) printf("Encoded: '%s' to '%s'\n", achBuf, achAuthorization);
  sprintf(achBuf, achDnsURL, Global.achHost, achMyDotIP, achDnsServer, achAuthorization, achUserAgent);
  if (Global.sVerbose >= 8) printf("---------- Sending -----------\n%s------------------------------\n", achBuf);
  if (Global.sVerbose >= 9) DumpBuffer(stdout, "", achBuf, strlen(achBuf));
  if (send(iSocket, achBuf, strlen(achBuf), 0) < 0) {
    sprintf(achBuf, "Failed to send data to %s", achDnsServer);
    psock_errno(achBuf);
    soclose(iSocket);
    return(EXIT_FAILURE);
  }
  if ( (iLength = recv(iSocket, achBuf, sizeof(achBuf)-1, 0)) <= 0) {
    sprintf(achBuf, "No response from %s", achDnsServer);
      psock_errno(achBuf);
      soclose(iSocket);
      return(EXIT_FAILURE);
  }
  achBuf[iLength] = '\0'; /* terminate msg  */

  /* And close socket, free allocated space */
  soclose(iSocket);

  /* process output */
  if (Global.sVerbose >= 8) printf("---------- Received ----------\n%s------------------------------\n", achBuf);
  if (Global.sVerbose >= 5) DumpBuffer(stdout, "", achBuf, strlen(achBuf));

  pCh = strstr(achBuf, "\r\n\r\n");
  if (pCh == NULL) {
    printf("Invalid response received. Update failed.\n");
    exit(1);
  }
  pCh += 4;
  pCh2 = pCh;
  while (*pCh2 && (*pCh2 > 0x20)) pCh2++;
  *pCh2 = 0;

  if (strcmp(pCh, "badsys") == 0) {
    printf("The system parameter given was not valid. Update failed.\n");
    exit(1);
  }
  if (strcmp(pCh, "badagent") == 0) {
    printf("The program has been blocked by DNSdyanmic. Update failed.\n");
    exit(1);
  }
  if (strcmp(pCh, "badauth") == 0) {
    printf("The username or password specified are not correct. Update failed.\n");
    exit(1);
  }
  if (strcmp(pCh, "!donator") == 0) {
    printf("The option specified requires a credited user. Update failed.\n");
    exit(1);
  }
  if (strcmp(pCh, "notfqdn") == 0) {
    printf("The hostname specified is not a fully-qualified domain name, or is\nnot a DNSdynamic host. Update failed.\n");
    exit(1);
  }
  if (strcmp(pCh, "nohost") == 0) {
    printf("The hostname specified does not exist in the DNSdynamic system. Update failed.\n");
    exit(1);
  }
  if (strcmp(pCh, "!yours") == 0) {
    printf("The hostname specified is not in the specified account. Update failed.\n");
    exit(1);
  }
  if (strcmp(pCh, "numhost") == 0) {
    printf("Too many or too few hosts found. Update failed.\n");
    exit(1);
  }
  if (strcmp(pCh, "abuse") == 0) {
    printf("The hostname specified is blocked for update abuse. Update failed.\n");
    exit(1);
  }
  if (strcmp(pCh, "dnserr") == 0) {
    printf("DNS error encountered. Please contact DNSdynamic support. Update failed.\n");
    exit(1);
  }
  if (strcmp(pCh, "911") == 0) {
    printf("There is a serious problem at DNSdynamic. Please contact DNSdynamic support. Update failed.\n");
    exit(1);
  }
  if (strcmp(pCh, "good") == 0) {
    if (Global.sVerbose >= 1) printf("Update was successful.\n");
    Settings.Host[usHostId].ttLastUpdateTime = ttTimeNow;
    Settings.Host[usHostId].ulHostIP = Settings.ulMyIP;
    PrfWriteProfileData(HINI_USERPROFILE, PRF_APP_NAME, PRF_KEY, &Settings, sizeof(Settings));
    exit(0);
  }
  if (strcmp(pCh, "nochg") == 0) {
    if (Global.sVerbose >= 1) printf("Update resulted in NO CHANGE. Repeated NO CHANGE updates are considered abusive.\n");
    Settings.Host[usHostId].ttLastUpdateTime = ttTimeNow;
    Settings.Host[usHostId].ulHostIP = Settings.ulMyIP;
    PrfWriteProfileData(HINI_USERPROFILE, PRF_APP_NAME, PRF_KEY, &Settings, sizeof(Settings));
    exit(0);
  }
  printf("Unknown result code received: %s\n", pCh);
  return(1);
}
