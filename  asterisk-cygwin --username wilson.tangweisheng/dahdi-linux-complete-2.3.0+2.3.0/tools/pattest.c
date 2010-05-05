/*
 * Written by Mark Spencer <markster@digium.com>
 * Based on previous works, designs, and architectures conceived and
 * written by Jim Dixon <jim@lambdatel.com>.
 *
 * Copyright (C) 2001 Jim Dixon / Zapata Telephony.
 * Copyright (C) 2001-2008 Digium, Inc.
 *
 * All rights reserved.
 *
 * Primary Author: Mark Spencer <markster@digium.com>
 * Radio Support by Jim Dixon <jim@lambdatel.com>
 */

/*
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2 as published by the
 * Free Software Foundation. See the LICENSE file included with
 * this program for more details.
 */

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <linux/types.h>
#include <linux/ppp_defs.h> 
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>
#include "bittest.h"

#include <dahdi/user.h>
#include "dahdi_tools_version.h"

#define BLOCK_SIZE 2039
#define DEVICE	  "/dev/dahdi/channel"

static const char	rcsid[] = "$Id: pattest.c 7658 2009-12-02 19:45:45Z tzafrir $";
char			*prog_name;

static void usage(void)
{
	fprintf(stderr, "Usage: %s <dahdi_chan>\n", prog_name);
	fprintf(stderr, "   e.g.: %s /dev/dahdi/55\n", prog_name);
	fprintf(stderr, "         %s 455\n", prog_name);
	fprintf(stderr, "%s version %s\n", prog_name, rcsid);
	exit(1);
}

void print_packet(unsigned char *buf, int len)
{
	int x;
	printf("{ ");
	for (x=0;x<len;x++)
		printf("%02x ",buf[x]);
	printf("}\n");
}

int channel_open(char *name, int *bs)
{
	int 			channo;
	int			fd;
	struct 			dahdi_params tp;
	char 			*dev;

	channo = atoi(name);
	/* channo==0: The user passed a file name to be opened. */
	dev = channo ? DEVICE : name;

	fd = open(dev, O_RDWR, 0600);

	if (fd < 0) {
		perror(DEVICE);
		return -1;
	}

	/* If we got a channel number, get it from /dev/dahdi/channel: */
	if(channo && ioctl(fd, DAHDI_SPECIFY, &channo) < 0) {
		perror("SPECIFY");
		return -1;
	}
	if(ioctl(fd, DAHDI_SET_BLOCKSIZE, bs) < 0) {
		perror("SET_BLOCKSIZE");
		return -1;
	}

	if (ioctl(fd, DAHDI_GET_PARAMS, &tp)) {
		fprintf(stderr, "Unable to get channel parameters\n");
		return -1;
	}

	return fd;
}

int main(int argc, char *argv[])
{
	int fd;
	int res, x;
	int bs = BLOCK_SIZE;
	unsigned char c=0;
	unsigned char outbuf[BLOCK_SIZE];
	int setup=0;
	int errors=0;
	int bytes=0;

	prog_name = argv[0];

	if (argc < 2) {
		usage();
	}

	fd = channel_open(argv[1], &bs);
	if (fd < 0)
		exit(1);

	ioctl(fd, DAHDI_GETEVENT);
	for(;;) {
		res = bs;
		res = read(fd, outbuf, res);
		if (res < bs) {
			int e;
			struct dahdi_spaninfo zi;
			res = ioctl(fd,DAHDI_GETEVENT,&e);
			if (res == -1)
			{
				perror("DAHDI_GETEVENT");
				exit(1);
			}
			if (e == DAHDI_EVENT_NOALARM)
				printf("ALARMS CLEARED\n");
			if (e == DAHDI_EVENT_ALARM)
			{
				zi.spanno = 0;
				res = ioctl(fd,DAHDI_SPANSTAT,&zi);
				if (res == -1)
				{
					perror("DAHDI_SPANSTAT");
					exit(1);
				}
				printf("Alarm mask %x hex\n",zi.alarms);
			}
			continue;
		}
		if (!setup) {
			c = outbuf[0];
			setup++;
		}
		for (x=0;x<bs;x++)  {
			if (outbuf[x] != c) {
				printf("(Error %d): Unexpected result, %d != %d, %d bytes since last error.\n", ++errors, outbuf[x], c, bytes); 
				c = outbuf[x];
				bytes=0;
			}
			c = bit_next(c);
			bytes++;
		}
#if 0
		printf("(%d) Wrote %d bytes\n", packets++, res);
#endif
	}
	
}
