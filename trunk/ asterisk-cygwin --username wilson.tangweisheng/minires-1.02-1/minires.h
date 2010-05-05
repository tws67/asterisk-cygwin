/************************************************************
 *
 minires 1.01         stub synchronous resolver for Cygwin
 Pierre A. Humblet
 December 2006

 Copyright (c) 2001, 2002, 2003, 2004, 2006 Pierre A. Humblet
 This program is free software; you can redistribute it and/or modify it
 under the terms of the GNU General Public License as published by the Free
 Software Foundation; either version 2 of the License, or (at your option)
 any later version

************************************************************/
#include <string.h>
#include <malloc.h>
#include <stdlib.h>
#include <netdb.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/unistd.h>
#include <netdb.h> 

/* The following two are not part of CYGWIN.
   They were taken from bind 9.2.1 */
#include <arpa/nameser.h>
#include <resolv.h>

/* Number of elements is an array */
#define DIM(x) (sizeof(x) / sizeof(*(x)))

/* Definitions to parse the messages */
#define RD (1<<8) /* Offset in a short */
#define RA (1<<7)
#define QR (1<<7) /* Offsets in a char */
#define TC (1<<1)
#define ERR_MASK 0xF

/* Type for os specific res_lookup */
typedef int (os_query_t) (res_state, const char *, int, int, u_char *, int);

/* Special use of state elements */
#define sockfd _vcsock
#define mypid _flags
#define os_query qhook
#define use_os pfcode

#define DPRINTF(cond, format...)  if (cond) minires_dprintf(format)

/* Utility functions */
void minires_dprintf(char * format, ...);
void minires_get_search(char * string, res_state statp);
void get_dns_info(res_state statp);
