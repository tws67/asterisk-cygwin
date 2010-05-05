/**********************************************************************
 *
 minires 1.01         stub synchronous resolver for Cygwin
 Pierre A. Humblet
 # December 2006

 Copyright (c) 2001, 2002, 2003, 2004, 2005, 2006 Pierre A. Humblet
 This program is free software; you can redistribute it and/or modify it
 under the terms of the GNU General Public License as published by the Free
 Software Foundation; either version 2 of the License, or (at your option)
 any later version

**********************************************************************/
/* To exercise the program */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>
#include <resolv.h>
#include "minires.h"

/*
 * Decode error code
 */
char * error_msg(int x)
{
  switch (x) {
  case NOERROR: return "OK";  
  case FORMERR: return "Format error";
  case SERVFAIL: return "Server failed";
  case NXDOMAIN: return "No such domain";
  case NOTIMP: return "Not implemented";
  case REFUSED: return "Refused";
  default: return "Unknown error";
  }
}
/*
 * Decodes a valid message
 */

/* Number of elements is an array */
#define DIM(x) (sizeof(x) / sizeof(*(x)))

/*
 * Decodes a valid message
 */
void decode_msg(char * msg, int msglength)
{
  char *hdr = msg, *ptr = &msg[12];
  unsigned short id, code, count;
  int i, j;
    
  GETSHORT(id, hdr);
  GETSHORT(code, hdr);
  fprintf(stderr, "\nId: %d. Code %x %s\n", id, code, error_msg(code& ERR_MASK));
  for (i = 0; i < 4; i++) {
    GETSHORT(count, hdr);
    fprintf(stderr, "SECTION %d. Count %d.\n", i, count);
    for (j = 0; j < count; j++) {
      unsigned char domain[MAXDNAME], domain2[MAXDNAME], *tptr;
      ns_type type;
      ns_class class;
      short rdlength, length;
      int ttl;
      
      length = dn_expand(msg, msg + msglength, ptr, domain, sizeof(domain));
      if (length < 0) {
	fprintf(stderr, "Invalid record\n");
	break;
      }
      ptr += length;
      GETSHORT(type, ptr);
      GETSHORT(class, ptr);
      /* Query */
      if (i == 0) { 
	fprintf(stderr, "%d) %s Type %d. Class %d.\n",
	       j, domain, type, class);
	continue;
      }
      /* Other sections */
      GETLONG(ttl, ptr);
      GETSHORT(rdlength, ptr);
      fprintf(stderr, "%d) %s Type %d. Class %d. TTL %d. Rdlength %d.\n",
	     j, domain, type, class, ttl, rdlength);
      tptr = ptr;
      length = rdlength;

      switch (type) {
      case T_A:      /* 1 Host address. */
      {
	union {
	  unsigned int a;
	  unsigned char d[4];
	} address;
	GETLONG(address.a, tptr);
	fprintf(stderr, "%d.%d.%d.%d\n", address.d[3], address.d[2], address.d[1], address.d[0]);
	break;
      }
      case T_NS:     /* 2 Authoritative server. */
      case T_MD:     /* 3 Mail destination. */
      case T_MF:     /* 4 Mail forwarder. */
      case T_CNAME:  /* 5 Canonical name. */
      case T_MB:     /* 7 Mailbox domain name. */
      case T_MG:     /* 8 Mail group member. */
      case T_MR:     /* 9 Mail rename name. */
      case T_PTR:    /* 12 Domain name pointer. */
	length = dn_expand(msg, msg + msglength, tptr, domain, sizeof(domain));
	if (length < 0) {
	  fprintf(stderr, "Invalid record\n");
	  break;
	}
	fprintf(stderr, "%s\n", domain);
	break;
      case T_SOA:    /* 6 Start of authority zone. */
      {
	int serial, refresh, retry, expire, minimum;
	length = dn_expand(msg, msg + msglength, tptr, domain, sizeof(domain));
	if (length < 0) {
	  fprintf(stderr, "Invalid record\n");
	  break;
	}
	tptr += length;
	length = dn_expand(msg, msg + msglength, tptr, domain2, sizeof(domain2));
	if (length < 0) {
	  fprintf(stderr, "Invalid record\n");
	  break;
	}
	tptr += length;
	GETLONG(serial, tptr);
	GETLONG(refresh, tptr);
	GETLONG(retry, tptr);
	GETLONG(expire, tptr);
	GETLONG(minimum, tptr);
	fprintf(stderr, "Server %s Person %s\n", domain, domain2);
	fprintf(stderr, "Serial %d. Refresh %d. Retry %d. Expire %d. Minimum %d.\n",
	       serial, refresh, retry, expire, minimum);
	break;
      }
      case T_HINFO:  /* 13 Host information. */
      case T_TXT:    /* 16 Text strings. */
      {
        unsigned len;
	while (length > 0) {
	  len = *tptr++;
	  length -= len + 1;
	  while (len--) fputc(*tptr++, stderr);
	  fputc('\n', stderr);
	}
	break;
      } 
      case T_MINFO:  /* 14 Mailbox information. */
	length = dn_expand(msg, msg + msglength, tptr, domain, sizeof(domain));
	if (length < 0) {
	  fprintf(stderr, "Invalid record\n");
	  break;
	}
	tptr += length;
	length = dn_expand(msg, msg + msglength, tptr, domain2, sizeof(domain2));
	if (length < 0) {
	  fprintf(stderr, "Invalid record\n");
	  break;
	}
	fprintf(stderr, "%s %s\n", domain, domain2);
	break;
      case T_WKS:    /* 11 Well known service. */
      {
	union {
	  unsigned int a;
	  unsigned char d[4];
	} address;
	GETLONG(address.a, tptr);
	fprintf(stderr, "%d.%d.%d.%d %d\n", 
	       address.d[3], address.d[2], address.d[1], address.d[0], *tptr++);
	break;
      }
      case T_MX:     /* 15 Mail routing information. */
      {
	short preference;
	GETSHORT(preference, tptr);
	length = dn_expand(msg, msg + msglength, tptr, domain, sizeof(domain));
	if (length < 0) {
	  fprintf(stderr, "Invalid record\n");
	  break;
	}
	fprintf(stderr, "%s Preference %d\n", domain, preference);
	break;
      }
      case T_AAAA:   /* 28 Ip6 Address. */
	if (length != 16)
	  fprintf(stderr, "Unexpected length\n");
	else {
	  do {
	    fprintf(stderr, "%02x", *tptr++);
	    length--;
	    if (length && !(length & 1))
	      fputc(':', stderr);
	  } while (length > 0);
	  fputc('\n', stderr);
	}
	break;
      case T_SRV:    /* 33 SRV */
      {
	short int priority, weight, port;
	GETSHORT(priority, tptr);
	GETSHORT(weight, tptr);
	GETSHORT(port, tptr);
	length = dn_expand(msg, msg + msglength, tptr, domain, sizeof(domain));
	if (length < 0) {
	  fprintf(stderr, "Invalid record\n");
	  break;
	}
	tptr += length;
	fprintf(stderr, "Priority %d. Weight %d. Port %d. Target %s\n",
		priority, weight, port, domain);
	break;
      }	
      case T_NULL:   /* 10 Null resource record. */
      default:
	while (length-- > 0)
	  fprintf(stderr, "%02x ", *tptr++);
	fprintf(stderr,"\n");
      }
      ptr += rdlength;
    }
  }
}
    
#if 0
	T_INVALID = 0,	/* Cookie. */
	T_RP = 17,		/* Responsible person. */
	T_afsdb = 18,	/* AFS cell database. */
	T_x25 = 19,		/* X_25 calling address. */
	T_isdn = 20,		/* ISDN calling address. */
	T_rt = 21,		/* Router. */
	T_nsap = 22,		/* NSAP address. */
	T_nsap_ptr = 23,	/* Reverse NSAP lookup (deprecated). */
	T_sig = 24,		/* Security signature. */
	T_key = 25,		/* Security key. */
	T_px = 26,		/* X.400 mail mapping. */
	T_gpos = 27,		/* Geographical position (withdrawn). */
	T_loc = 29,		/* Location Information. */
	T_nxt = 30,		/* Next domain (security). */
	T_eid = 31,		/* Endpoint identifier. */
	T_nimloc = 32,	/* Nimrod Locator. */
	T_srv = 33,		/* Server Selection. */
	T_atma = 34,		/* ATM Address */
	T_naptr = 35,	/* Naming Authority PoinTeR */
	T_kx = 36,		/* Key Exchange */
	T_cert = 37,		/* Certification record */
      case T_A6:     /* 38 IPv6 address (deprecates AAAA) */
	T_dname = 39,	/* Non-terminal DNAME (for IPv6) */
	T_sink = 40,		/* Kitchen sink (experimentatl) */
	T_opt = 41,		/* EDNS0 option (meta-RR) */
	T_tkey = 249,	/* Transaction key */
	T_tsig = 250,	/* Transaction signature. */
	T_ixfr = 251,	/* Incremental zone transfer. */
	T_axfr = 252,	/* Transfer zone of authority. */
	T_mailb = 253,	/* Transfer mailbox records. */
	T_maila = 254,	/* Transfer mail agent records. */
	T_any = 255,		/* Wildcard match. */
	T_zxfr = 256,	/* BIND-specific, nonstandard. */
#endif

int main(int argc, char * argv[])
{
  unsigned short pack[4*PACKETSZ/sizeof(short)];
  int i;
  char * host;
  int type;

  if (argc > 2) {
    host = argv[1];
    type = atoi(argv[2]);
  }
  else if (argc == 2) {
    /* Use "interesting" hosts when known.
       This list may change with time, we have no control. */
    if ((type = atoi(argv[1]))) {
      switch (type) {
	case T_TXT: /* 16 */
	host = "2.0.0.127.dnsbl.njabl.org";
	break;
	case T_HINFO: /* 13 */
	host = "lids.mit.edu";
	break;
	case T_MX: /* 15 */
	host = "gmail.com";
	break;
	case T_AAAA: /* 28 */ /* jazz.viagenie.qc.ca */
	host = "6bone.net";
	break;
	case T_SRV: /* 33 */
	host = "_sip._udp.yalin.tw";
	break;
	case 44: /* SSHFP */
	host = "ok.schlyter.net";
	break;
	default:
	host = "mit.edu";
      }
    }
    else {
      host = argv[1];
      type = T_A;
    }
  }
  else {
    fprintf(stderr, "Usage: %s host [type]\n", argv[0]);
    exit(0);
  }
  
  _res.options |= RES_DEBUG;
  res_init();

  fprintf(stderr, "%d _res.options %lx\n", 
	  getpid(), _res.options);
  for (i = 0; i < DIM(pack); i++) pack[i] = 'X';
 

  fprintf(stderr, "argc %d\n", argc);
  if (type >= 0)
    i = res_search(host, C_IN, type, (char *) pack, sizeof(pack)); 
  else
    i = res_query(host, C_IN, -type, (char *) pack, sizeof(pack)); 

  fprintf(stderr, "res = %d, h_errno: %d, flags: %x\n", 
	  i, h_errno, ntohs(pack[1]));
  
  decode_msg((char *) pack, MIN(i, sizeof(pack)));
  
  fflush(stderr);

  if (argc > 3) { /* Test mode. Check behavior under fork */
      fprintf(stderr, "argc %d\n", argc);
    if (fork() == 0) {
      fprintf(stderr, "%d _res.options %lx\n", 
  	      getpid(), _res.options);
      i = res_query(host, C_IN, type , (char *) pack, sizeof(pack)); 
      fprintf(stderr, "res = %d, h_errno: %d, flags: %x\n", 
	      i, h_errno, ntohs(pack[1]));
      fflush(stderr);
      _exit(0);
    }
    sleep(5);
  }
#if 0
  /* Change the 0 above to print the packet on stdout */ 
  for (i = 0; i < sizeof(pack); i++)
  fputc(*((char *)pack + i), stdout);
#endif
  exit(0);
}

