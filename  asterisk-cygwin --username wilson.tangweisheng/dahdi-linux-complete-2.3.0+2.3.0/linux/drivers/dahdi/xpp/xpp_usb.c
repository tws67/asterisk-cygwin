/*
 * Written by Oron Peled <oron@actcom.co.il>
 * Copyright (C) 2004-2006, Xorcom
 *
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/delay.h>	/* for udelay */
#include <linux/seq_file.h>
#include <asm/uaccess.h>
#include <asm/atomic.h>
#include <asm/timex.h>
#include <linux/proc_fs.h>
#include <linux/usb.h>
#include "xpd.h"
#include "xproto.h"
#include "xbus-core.h"
#include "xframe_queue.h"
#ifdef	DEBUG
#include "card_fxs.h"
#include "card_fxo.h"
#endif
#include "parport_debug.h"

static const char rcsid[] = "$Id: xpp_usb.c 6995 2009-08-13 20:25:16Z sruffell $";

static DEF_PARM(int, debug, 0, 0644, "Print DBG statements");	/* must be before dahdi_debug.h */
static DEF_PARM(int, usb1, 0, 0644, "Allow using USB 1.1 interfaces");
static DEF_PARM(uint, tx_sluggish, 2000, 0644, "A sluggish transmit (usec)");
static DEF_PARM(uint, drop_pcm_after, 6, 0644, "Number of consecutive tx_sluggish to drop a PCM frame");

#include "dahdi_debug.h"


#define	XUSB_PRINTK(level, xusb, fmt, ...)	\
	printk(KERN_ ## level "%s-%s: xusb-%d (%s) [%s]: " fmt, #level,	\
		THIS_MODULE->name, (xusb)->index, xusb->path, xusb->serial, ## __VA_ARGS__)

#define	XUSB_DBG(bits, xusb, fmt, ...)	\
			((void)((debug & (DBG_ ## bits)) && XUSB_PRINTK(DEBUG, xusb, "%s: " fmt, __FUNCTION__, ## __VA_ARGS__)))
#define	XUSB_ERR(xusb, fmt, ...)		XUSB_PRINTK(ERR, xusb, fmt, ## __VA_ARGS__)
#define	XUSB_NOTICE(xusb, fmt, ...)		XUSB_PRINTK(NOTICE, xusb, fmt, ## __VA_ARGS__)
#define	XUSB_INFO(xusb, fmt, ...)		XUSB_PRINTK(INFO, xusb, fmt, ## __VA_ARGS__)

/* FIXME: A flag that was deprecated at some point, and rather useless */
/* anyway. Only used in the code or-ed to other flags                  */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
#  define URB_ASYNC_UNLINK 0
#endif
/* Get a minor range for your devices from the usb maintainer */
#define USB_SKEL_MINOR_BASE	192

#ifdef CONFIG_PROC_FS
#define	PROC_USBXPP_SUMMARY	"xpp_usb"
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#  warning "This module is tested only with 2.6 kernels"
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,12)
#  undef USB_FIELDS_MISSING
#else
#  define USB_FIELDS_MISSING

#  define USB_MAX_STRING	128
#  define USB_GET_STRING(udev,field,buf)		\
	do {						\
		if((udev)->descriptor.field) {		\
			char	tmp[USB_MAX_STRING];	\
			if(usb_string((udev), (udev)->descriptor.field, tmp, sizeof(tmp)) > 0) \
				snprintf((buf), USB_MAX_STRING, "%s", tmp); \
		}					\
	} while(0);
#  define USB_GET_IFACE_NAME(udev,iface,buf)		\
	do {						\
		if((iface)->desc.iInterface) {		\
			char	tmp[USB_MAX_STRING];	\
			if(usb_string((udev), (iface)->desc.iInterface, tmp, sizeof(tmp)) > 0) \
				snprintf((buf), USB_MAX_STRING, "%s", tmp); \
		}					\
	} while(0);
#endif

#ifdef	DEBUG_PCM_TIMING
static cycles_t	stamp_last_pcm_read;
static cycles_t accumulate_diff;
#endif

struct xusb_model_info;

struct xusb_endpoint {
	int		ep_addr;
	int		max_size;
	usb_complete_t	callback;
};

enum xusb_dir {
	XUSB_RECV = 0,
	XUSB_SEND = 1,
};

static __must_check int xframe_send_pcm(xbus_t *xbus, xframe_t *xframe);
static __must_check int xframe_send_cmd(xbus_t *xbus, xframe_t *xframe);
static __must_check xframe_t *alloc_xframe(xbus_t *xbus, gfp_t flags);
static void free_xframe(xbus_t *xbus, xframe_t *frm);

static struct xbus_ops	xusb_ops = {
	.xframe_send_pcm = xframe_send_pcm,
	.xframe_send_cmd = xframe_send_cmd,
	.alloc_xframe = alloc_xframe,
	.free_xframe = free_xframe,
};

enum {
	XUSB_N_RX_FRAMES,
	XUSB_N_TX_FRAMES,
	XUSB_N_RX_ERRORS,
	XUSB_N_TX_ERRORS,
	XUSB_N_RCV_ZERO_LEN,
};

#define	XUSB_COUNTER(xusb, counter)	((xusb)->counters[XUSB_N_ ## counter])

#define	C_(x)	[ XUSB_N_ ## x ] = { #x }

static struct xusb_counters {
	char	*name;
} xusb_counters[] = {
	C_(RX_FRAMES),
	C_(TX_FRAMES),
	C_(RX_ERRORS),
	C_(TX_ERRORS),
	C_(RCV_ZERO_LEN),
};

#undef C_

#define	XUSB_COUNTER_MAX	ARRAY_SIZE(xusb_counters)

#define	MAX_PENDING_WRITES	100

static KMEM_CACHE_T	*xusb_cache = NULL;

typedef	struct xusb	xusb_t;

/*
 * A uframe is our low level representation of a frame.
 * 
 * It contains the metadata for the usb stack (a urb)
 * and the metadata for the xbus-core (an xframe)
 * as well as pointing to the data (transfer_buffer, transfer_buffer_length)
 * directionality (send/receive) and ownership (xusb).
 */
struct uframe {
	unsigned long		uframe_magic;
#define	UFRAME_MAGIC	654321L
	struct urb		urb;
	xframe_t		xframe;
	size_t			transfer_buffer_length;
	void			*transfer_buffer;	/* max XFRAME_DATASIZE */
	xusb_t			*xusb;
};

#define	urb_to_uframe(urb)		container_of(urb, struct uframe, urb)
#define	xframe_to_uframe(xframe)	container_of(xframe, struct uframe, xframe)
#define	xusb_of(xbus)			((xusb_t *)((xbus)->transport.priv))

#define	USEC_BUCKET		100	/* usec */
#define	NUM_BUCKETS		15
#define	BUCKET_START		(500/USEC_BUCKET)	/* skip uninteresting */

/*
 * USB XPP Bus (a USB Device)
 */
struct xusb {
	uint			xbus_num;
	struct usb_device	*udev;			/* save off the usb device pointer */
	struct usb_interface	*interface;		/* the interface for this device */
	unsigned char		minor;			/* the starting minor number for this device */
	uint			index;
	char			path[XBUS_DESCLEN];	/* a unique path */

	struct xusb_model_info	*model_info;
	struct xusb_endpoint	endpoints[2];		/* RECV/SEND endpoints */

	int			present;		/* if the device is not disconnected */
	atomic_t		pending_writes;		/* submited but not out yet */
	atomic_t		pending_reads;		/* submited but not in yet */
	struct semaphore	sem;			/* locks this structure */
	int			counters[XUSB_COUNTER_MAX];

	/* metrics */
	struct timeval		last_tx;
	unsigned int		max_tx_delay;
	uint			usb_tx_delay[NUM_BUCKETS];
	uint			sluggish_debounce;
	bool			drop_next_pcm;	/* due to sluggishness */
	atomic_t		pcm_tx_drops;
	atomic_t		usb_sluggish_count;

#ifdef USB_FIELDS_MISSING
	/* storage for missing strings in old kernels */
	char			manufacturer[USB_MAX_STRING];
	char			product[USB_MAX_STRING];
	char			serial[USB_MAX_STRING];
	char			interface_name[USB_MAX_STRING];
#else
	const char		*manufacturer;
	const char		*product;
	const char		*serial;
	const char		*interface_name;
#endif

};

static	spinlock_t	xusb_lock = SPIN_LOCK_UNLOCKED;
static xusb_t *xusb_array[MAX_BUSES] = {};
static unsigned bus_count = 0;


/* prevent races between open() and disconnect() */
static DECLARE_MUTEX (disconnect_sem);

/*
 * AsteriskNow kernel has backported the "lean" callback from 2.6.20
 * to 2.6.19 without any macro to notify of this fact -- how lovely.
 * Debian-Etch and Centos5 are using 2.6.18 for now (lucky for us).
 * Fedora6 jumped from 2.6.18 to 2.6.20. So far luck is on our side ;-)
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
#define	USB_PASS_CB(u)	struct urb *u, struct pt_regs *regs
#else
#define	USB_PASS_CB(u)	struct urb *u
#endif

static void xpp_send_callback(USB_PASS_CB(urb));
static void xpp_receive_callback(USB_PASS_CB(urb));
static int xusb_probe		(struct usb_interface *interface, const struct usb_device_id *id);
static void xusb_disconnect	(struct usb_interface *interface);
static int xusb_read_proc(char *page, char **start, off_t off, int count, int *eof, void *data);

/*------------------------------------------------------------------*/

/*
 * Updates the urb+xframe metadata from the uframe information.
 */
static void uframe_recompute(struct uframe *uframe, enum xusb_dir dir)
{
	struct urb		*urb = &uframe->urb;
	xusb_t			*xusb = uframe->xusb;
	struct usb_device	*udev = xusb->udev;
	struct xusb_endpoint	*xusb_ep = &xusb->endpoints[dir];
	unsigned int		ep_addr = xusb_ep->ep_addr;
	usb_complete_t		urb_cb = xusb_ep->callback;
	unsigned int		epnum = ep_addr & USB_ENDPOINT_NUMBER_MASK;
	int			pipe = usb_pipein(ep_addr)
					? usb_rcvbulkpipe(udev, epnum)
					: usb_sndbulkpipe(udev, epnum);

	BUG_ON(uframe->uframe_magic != UFRAME_MAGIC);
	usb_fill_bulk_urb(urb, udev, pipe, uframe->transfer_buffer, uframe->transfer_buffer_length, urb_cb, uframe);
	urb->transfer_flags = (URB_NO_TRANSFER_DMA_MAP | URB_ASYNC_UNLINK);
}

static xframe_t *alloc_xframe(xbus_t *xbus, gfp_t gfp_flags)
{
	struct uframe	*uframe;
	xusb_t		*xusb;
	void		*p;
	int		size;
	static int	rate_limit;

	BUG_ON(!xbus);
	xusb = xusb_of(xbus);
	BUG_ON(!xusb);
	if(!xusb->present) {
		if((rate_limit++ % 1003) == 0)
			XUSB_ERR(xusb,
				"abort allocations during device disconnect (%d)\n", rate_limit);
		return NULL;
	}
	size = min(xusb->endpoints[XUSB_SEND].max_size, xusb->endpoints[XUSB_RECV].max_size); 
	uframe = kmem_cache_alloc(xusb_cache, gfp_flags);
	if(!uframe) {
		if((rate_limit++ % 1003) == 0)
			XUSB_ERR(xusb, "frame allocation failed (%d)\n", rate_limit);
		return NULL;
	}
	usb_init_urb(&uframe->urb);
	p = usb_buffer_alloc(xusb->udev, size, gfp_flags, &uframe->urb.transfer_dma);
	if(!p) {
		if((rate_limit++ % 1003) == 0)
			XUSB_ERR(xusb, "buffer allocation failed (%d)\n", rate_limit);
		kmem_cache_free(xusb_cache, uframe);
		return NULL;
	}
	uframe->uframe_magic = UFRAME_MAGIC;
	uframe->transfer_buffer_length = size;
	uframe->transfer_buffer = p;
	uframe->xusb = xusb;
	xframe_init(xbus, &uframe->xframe, uframe->transfer_buffer, uframe->transfer_buffer_length, uframe);
	return &uframe->xframe;
}

static void free_xframe(xbus_t *xbus, xframe_t *xframe)
{
	struct uframe	*uframe = xframe_to_uframe(xframe);
	struct urb	*urb = &uframe->urb;

	BUG_ON(xbus->transport.priv != uframe->xusb);
	//XUSB_INFO(uframe->xusb, "frame_free\n");
	usb_buffer_free(urb->dev, uframe->transfer_buffer_length,
			urb->transfer_buffer,
			urb->transfer_dma);
	memset(uframe, 0, sizeof(*uframe));
	kmem_cache_free(xusb_cache, uframe);
}

/*------------------------------------------------------------------*/

/*
 * Actuall frame sending -- both PCM and commands.
 */
static int do_send_xframe(xbus_t *xbus, xframe_t *xframe)
{
	struct urb		*urb;
	xusb_t			*xusb;
	int			ret = 0;
	struct uframe		*uframe;

	BUG_ON(!xframe);
	BUG_ON(xframe->xframe_magic != XFRAME_MAGIC);
	xusb = xusb_of(xbus);
	BUG_ON(!xusb);
	if(!xusb->present) {
		static int	rate_limit;

		if((rate_limit++ % 1003) == 0)
			XUSB_ERR(xusb,
				"abort do_send_xframe during device disconnect (%d)\n", rate_limit);
		ret = -ENODEV;
		goto failure;
	}
	/*
	 * If something really bad happend, do not overflow the USB stack
	 */
	if(atomic_read(&xusb->pending_writes) > MAX_PENDING_WRITES) {
		static	int rate_limit;

		if((rate_limit++ % 5000) == 0)
			XUSB_ERR(xusb,
				"USB device is totaly stuck. Dropping packets (#%d).\n",
				rate_limit);
		ret = -ENODEV;
		goto failure;
	}
	uframe = xframe->priv;
	BUG_ON(!uframe);
	BUG_ON(uframe->uframe_magic != UFRAME_MAGIC);
	uframe_recompute(uframe, XUSB_SEND);
	urb = &uframe->urb;
	BUG_ON(!urb);
	/* update urb length */
	urb->transfer_buffer_length = XFRAME_LEN(xframe);
	do_gettimeofday(&xframe->tv_submitted);
	ret = usb_submit_urb(urb, GFP_ATOMIC);
	if(ret < 0) {
		static int rate_limit;

		if((rate_limit++ % 1000) == 0)
			XBUS_ERR(xbus, "%s: usb_submit_urb failed: %d\n",
				__FUNCTION__, ret);
		ret = -EBADF;
		goto failure;
	}
//	if (debug)
//		dump_xframe("USB_FRAME_SEND", xbus, xframe, debug);
	atomic_inc(&xusb->pending_writes);
	return 0;
failure:
	XUSB_COUNTER(xusb, TX_ERRORS)++;
	FREE_SEND_XFRAME(xbus, xframe);	/* return to pool */
	return ret;
}

/*
 * PCM wrapper
 */
static int xframe_send_pcm(xbus_t *xbus, xframe_t *xframe)
{
	xusb_t	*xusb;

	BUG_ON(!xbus);
	BUG_ON(!xframe);
	xusb = xusb_of(xbus);
	BUG_ON(!xusb);
	if(xusb->drop_next_pcm) {
		FREE_SEND_XFRAME(xbus, xframe);	/* return to pool */
		xusb->drop_next_pcm = 0;
		return -EIO;
	}
	return do_send_xframe(xbus, xframe);
}

/*
 * commands wrapper
 */
static int xframe_send_cmd(xbus_t *xbus, xframe_t *xframe)
{
	BUG_ON(!xbus);
	BUG_ON(!xframe);
	//XBUS_INFO(xbus, "%s:\n", __FUNCTION__);
	return do_send_xframe(xbus, xframe);
}

/*
 * get a urb from the receive_pool and submit it on the read endpoint.
 */
static bool xusb_listen(xusb_t *xusb)
{
	xbus_t			*xbus = xbus_num(xusb->xbus_num);
	xframe_t		*xframe;
	struct uframe		*uframe;
	int			ret = 0;

	BUG_ON(!xbus);
	xframe = ALLOC_RECV_XFRAME(xbus);
	if(!xframe) {
		XBUS_ERR(xbus, "Empty receive_pool\n");
		goto out;
	}
	uframe = xframe_to_uframe(xframe);
	uframe_recompute(uframe, XUSB_RECV);
	ret = usb_submit_urb(&uframe->urb, GFP_ATOMIC);
	if(ret < 0) {
		static int rate_limit;

		if((rate_limit++ % 1000) == 0)
			XBUS_ERR(xbus, "%s: usb_submit_urb failed: %d\n",
				__FUNCTION__, ret);
		FREE_RECV_XFRAME(xbus, xframe);
		goto out;
	}
	atomic_inc(&xusb->pending_reads);
	ret = 1;
out:
	return ret;
}

/*------------------------- XPP USB Bus Handling -------------------*/

enum XUSB_MODELS {
	MODEL_FPGA_XPD
};

static const struct xusb_model_info {
	const char		*desc;
	int			iface_num;
	struct xusb_endpoint	in;
	struct xusb_endpoint	out;
} model_table[] = {
	[MODEL_FPGA_XPD] = {
		.iface_num = 0,
		.in = { .ep_addr = 0x86 },
		.out = { .ep_addr = 0x02 },
		.desc = "FPGA_XPD"
	},
};

/* table of devices that work with this driver */
static const struct usb_device_id xusb_table [] = {
	{ USB_DEVICE(0xE4E4, 0x1132), .driver_info=(kernel_ulong_t)&model_table[MODEL_FPGA_XPD] }, // FPGA_FXS
	{ USB_DEVICE(0xE4E4, 0x1142), .driver_info=(kernel_ulong_t)&model_table[MODEL_FPGA_XPD] }, // FPGA_1141
	{ USB_DEVICE(0xE4E4, 0x1152), .driver_info=(kernel_ulong_t)&model_table[MODEL_FPGA_XPD] }, // FPGA_1151
	{ USB_DEVICE(0xE4E4, 0x1162), .driver_info=(kernel_ulong_t)&model_table[MODEL_FPGA_XPD] }, // FPGA_1161
	{ }					/* Terminating entry */
};

MODULE_DEVICE_TABLE (usb, xusb_table);


/* usb specific object needed to register this driver with the usb subsystem */
static struct usb_driver xusb_driver = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)
	.owner =	THIS_MODULE,
#endif
	.name =		"xpp_usb",
	.probe =	xusb_probe,
	.disconnect =	xusb_disconnect,
	.id_table =	xusb_table,
};

/*
 * File operations needed when we register this driver.
 * This assumes that this driver NEEDS file operations,
 * of course, which means that the driver is expected
 * to have a node in the /dev directory. If the USB
 * device were for a network interface then the driver
 * would use "struct net_driver" instead, and a serial
 * device would use "struct tty_driver".
 */
static struct file_operations xusb_fops = {
	/*
	 * The owner field is part of the module-locking
	 * mechanism. The idea is that the kernel knows
	 * which module to increment the use-counter of
	 * BEFORE it calls the device's open() function.
	 * This also means that the kernel can decrement
	 * the use-counter again before calling release()
	 * or should the open() function fail.
	 */
	.owner =	THIS_MODULE,
};

/* 
 * usb class driver info in order to get a minor number from the usb core,
 * and to have the device registered with devfs and the driver core
 */
static struct usb_class_driver xusb_class = {
	.name =		"usb/xpp_usb%d",
	.fops =		&xusb_fops,
/* FIXME: The sysfs class interfase seems to have chaged around here */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)
	.mode =		S_IFCHR | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH,
#endif
	.minor_base =	USB_SKEL_MINOR_BASE,
};

/*
 * Check that an endpoint's wMaxPacketSize attribute is 512. This
 * indicates that it is a USB2's high speed end point. 
 *
 * If it is 64, it means we have a USB1 controller. By default we do not
 * support it and just fail the probe of the device. However if the user
 * has set usb1=1, we continue and just put a notice.
 *
 * Returns true if all OK, false otherwise.
 */
static int check_usb1(struct usb_endpoint_descriptor *endpoint)
{
	const char *msg = (usb_pipein(endpoint->bEndpointAddress))?"input":"output";

	if(endpoint->wMaxPacketSize >= sizeof(xpacket_t))
		return 1;

	if(usb1) {
		NOTICE("USB1 endpoint detected: USB %s endpoint 0x%X support only wMaxPacketSize=%d.\n", 
				msg, endpoint->bEndpointAddress, endpoint->wMaxPacketSize);
		return 1;
	}
	NOTICE("USB1 endpoint detected. Device disabled. To enable: usb1=1, and read docs. (%s, endpoint %d, size %d).\n", 
			msg, endpoint->bEndpointAddress, endpoint->wMaxPacketSize);
	return 0;
}

/*
 * set up the endpoint information
 * check out the endpoints
 * FIXME: Should be simplified (above 2.6.10) to use usb_dev->ep_in[0..16] and usb_dev->ep_out[0..16]
 */
static int set_endpoints(xusb_t *xusb, struct usb_host_interface *iface_desc, struct xusb_model_info *model_info)
{
	struct usb_endpoint_descriptor	*endpoint;
	struct xusb_endpoint		*xusb_ep;
	int				ep_addr;
	int i;

#define	BULK_ENDPOINT(ep) (((ep)->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK) == USB_ENDPOINT_XFER_BULK)

	for (i = 0; i < iface_desc->desc.bNumEndpoints; ++i) {
		endpoint = &iface_desc->endpoint[i].desc;
		ep_addr = endpoint->bEndpointAddress;
		
		if(!BULK_ENDPOINT(endpoint)) {
			DBG(DEVICES, "endpoint 0x%x is not bulk: mbAttributes=0x%X\n",
					ep_addr, endpoint->bmAttributes);
			continue;
		}
		if(usb_pipein(ep_addr)) {	// Input
			if(ep_addr == model_info->in.ep_addr) {
				if (!check_usb1(endpoint))
					return 0;
				xusb_ep = &xusb->endpoints[XUSB_RECV];
				xusb_ep->ep_addr = ep_addr;
				xusb_ep->max_size = endpoint->wMaxPacketSize;
				xusb_ep->callback = xpp_receive_callback;
			}
		} else {			// Output
			if(ep_addr == model_info->out.ep_addr) {
				if (!check_usb1(endpoint))
					return 0;
				xusb_ep = &xusb->endpoints[XUSB_SEND];
				xusb_ep->ep_addr = ep_addr;
				xusb_ep->max_size = endpoint->wMaxPacketSize;
				xusb_ep->callback = xpp_send_callback;
			}
		}
	}
	if (!xusb->endpoints[XUSB_RECV].ep_addr || !xusb->endpoints[XUSB_SEND].ep_addr) {
		XUSB_ERR(xusb, "Couldn't find bulk-in or bulk-out endpoints\n");
		return 0;
	}
	DBG(DEVICES, "in=0x%02X out=0x%02X\n", xusb->endpoints[XUSB_RECV].ep_addr, xusb->endpoints[XUSB_SEND].ep_addr);
	return 1;
}

/*
 * The USB stack before 2.6.10 seems to be a bit shoddy. It seems that when
 * being called from the probe we may already have the lock to udev (the Usb DEVice).
 * Thus we call the internal __usb_reset_device instead.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10)
#define	DO_USB_RESET_DEVICE(dev)	__usb_reset_device(dev)
#else
#define	DO_USB_RESET_DEVICE(dev)	usb_reset_device(dev)
#endif

/**
 *	xusb_probe
 *
 *	Called by the usb core when a new device is connected that it thinks
 *	this driver might be interested in.
 */
static int xusb_probe(struct usb_interface *interface, const struct usb_device_id *id)
{
	struct usb_device		*udev = interface_to_usbdev(interface);
	struct usb_host_interface	*iface_desc = usb_altnum_to_altsetting(interface, 0);
	xusb_t			*xusb = NULL;
	struct xusb_model_info	*model_info = (struct xusb_model_info*)id->driver_info;
	struct proc_dir_entry	*procsummary = NULL;
	xbus_t			*xbus = NULL;
	unsigned long		flags;
	int			retval = -ENOMEM;
	int			i;
	
	DBG(DEVICES, "New XUSB device MODEL=%s\n", model_info->desc);
	if(iface_desc->desc.bInterfaceNumber != model_info->iface_num) {
		DBG(DEVICES, "Skip interface #%d != #%d\n",
			iface_desc->desc.bInterfaceNumber, model_info->iface_num);
		return -ENODEV;
	}
	if((retval = DO_USB_RESET_DEVICE(udev)) < 0) {
		ERR("usb_reset_device failed: %d\n", retval);
		goto probe_failed;
	}
	if (!model_info) {
		ERR("Missing endpoint setup for this device %d:%d\n", 
				udev->descriptor.idVendor,udev->descriptor.idProduct);
		retval = -ENODEV;
		goto probe_failed;
	}

	/* allocate memory for our device state and initialize it */
	xusb = KZALLOC(sizeof(xusb_t), GFP_KERNEL);
	if (xusb == NULL) {
		ERR("xpp_usb: Unable to allocate new xpp usb bus\n");
		retval = -ENOMEM;
		goto probe_failed;
	}
	init_MUTEX (&xusb->sem);
	atomic_set(&xusb->pending_writes, 0);
	atomic_set(&xusb->pending_reads, 0);
	atomic_set(&xusb->pcm_tx_drops, 0);
	atomic_set(&xusb->usb_sluggish_count, 0);
	xusb->udev = udev;
	xusb->interface = interface;
	xusb->model_info = model_info;

	if(!set_endpoints(xusb, iface_desc, model_info)) {
		retval = -ENODEV;
		goto probe_failed;
	}
#ifndef USB_FIELDS_MISSING
	xusb->serial = udev->serial;
	xusb->manufacturer = udev->manufacturer;
	xusb->product = udev->product;
	xusb->interface_name = iface_desc->string;
#else
	USB_GET_STRING(udev, iSerialNumber, xusb->serial);
	USB_GET_STRING(udev, iManufacturer, xusb->manufacturer);
	USB_GET_STRING(udev, iProduct, xusb->product);
	USB_GET_IFACE_NAME(udev, iface_desc, xusb->interface_name);
#endif
	INFO("XUSB: %s -- %s -- %s\n",
		xusb->manufacturer, xusb->product, xusb->interface_name);

	/* allow device read, write and ioctl */
	xusb->present = 1;

	/* we can register the device now, as it is ready */
	usb_set_intfdata(interface, xusb);
	retval = usb_register_dev (interface, &xusb_class);
	if (retval) {
		/* something prevented us from registering this driver */
		ERR ("Not able to get a minor for this device.\n");
		goto probe_failed;
	}

	xusb->minor = interface->minor;

	/* let the user know what node this device is now attached to */
	DBG(DEVICES, "USB XPP device now attached to minor %d\n", xusb->minor);
	xbus = xbus_new(&xusb_ops, min(xusb->endpoints[XUSB_SEND].max_size, xusb->endpoints[XUSB_RECV].max_size), &udev->dev, xusb);
	if(!xbus) {
		retval = -ENOMEM;
		goto probe_failed;
	}
	spin_lock_irqsave(&xusb_lock, flags);
	for(i = 0; i < MAX_BUSES; i++) {
		if(xusb_array[i] == NULL)
			break;
	}
	spin_unlock_irqrestore(&xusb_lock, flags);
	if(i >= MAX_BUSES) {
		ERR("xpp_usb: Too many XPP USB buses\n");
		retval = -ENOMEM;
		goto probe_failed;
	}
	usb_make_path(udev, xusb->path, XBUS_DESCLEN);	// May trunacte... ignore
	snprintf(xbus->connector, XBUS_DESCLEN, "%s", xusb->path);
	if(xusb->serial && xusb->serial[0])
		snprintf(xbus->label, LABEL_SIZE, "usb:%s", xusb->serial);
	xusb->index = i;
	xusb_array[i] = xusb;
	XUSB_DBG(DEVICES, xusb, "GOT XPP USB BUS: %s\n", xbus->connector);

#ifdef CONFIG_PROC_FS
	DBG(PROC, "Creating proc entry " PROC_USBXPP_SUMMARY " in bus proc dir.\n");
	procsummary = create_proc_read_entry(PROC_USBXPP_SUMMARY, 0444, xbus->proc_xbus_dir,
			xusb_read_proc, xusb);
	if (!procsummary) {
		XBUS_ERR(xbus, "Failed to create proc file '%s'\n", PROC_USBXPP_SUMMARY);
		// FIXME: better error handling
		retval = -EIO;
		goto probe_failed;
	}
	SET_PROC_DIRENTRY_OWNER(procsummary);
#endif
	bus_count++;
	xusb->xbus_num = xbus->num;
	/* prepare several pending frames for receive side */
	for(i = 0; i < 10; i++)
			xusb_listen(xusb);
	xbus_connect(xbus);
	return retval;
probe_failed:
	ERR("Failed to initialize xpp usb bus: %d\n", retval);
	usb_set_intfdata(interface, NULL);
	if(xusb) {
		if(xusb->minor) {	// passed registration phase
			ERR("Calling usb_deregister_dev()\n");
			usb_deregister_dev(interface, &xusb_class);
		}
		ERR("Removing failed xusb\n");
		KZFREE(xusb);
	}
	if(xbus) {
		if(procsummary) {
			XBUS_DBG(PROC, xbus, "Remove proc_entry: " PROC_USBXPP_SUMMARY "\n");
			remove_proc_entry(PROC_USBXPP_SUMMARY, xbus->proc_xbus_dir);
			procsummary = NULL;
		}
		ERR("Calling xbus_disconnect()\n");
		xbus_disconnect(xbus);		// Blocking until fully deactivated!
	}
	return retval;
}

/**
 *	xusb_disconnect
 *
 *	Called by the usb core when the device is removed from the system.
 *
 *	This routine guarantees that the driver will not submit any more urbs
 *	by clearing dev->udev.  It is also supposed to terminate any currently
 *	active urbs.  Unfortunately, usb_bulk_msg(), used in xusb_read(), does
 *	not provide any way to do this.  But at least we can cancel an active
 *	write.
 */
static void xusb_disconnect(struct usb_interface *interface)
{
	struct usb_host_interface	*iface_desc = usb_altnum_to_altsetting(interface, 0);
	xusb_t			*xusb;
	xbus_t			*xbus;
	int			minor;
	int			i;

	DBG(DEVICES, "CALLED on interface #%d\n", iface_desc->desc.bInterfaceNumber);
	/* prevent races with open() */
	down (&disconnect_sem);

	xusb = usb_get_intfdata(interface);
	usb_set_intfdata(interface, NULL);
	xusb->present = 0;
	xbus = xbus_num(xusb->xbus_num);

	/* find our xusb */
	for(i = 0; i < MAX_BUSES; i++) {
		if(xusb_array[i] == xusb)
			break;
	}
	BUG_ON(i >= MAX_BUSES);
	xusb_array[i] = NULL;

#ifdef CONFIG_PROC_FS
	if(xbus->proc_xbus_dir) {
		XBUS_DBG(PROC, xbus, "Remove proc_entry: " PROC_USBXPP_SUMMARY "\n");
		remove_proc_entry(PROC_USBXPP_SUMMARY, xbus->proc_xbus_dir);
	}
#endif
	xbus_disconnect(xbus);		// Blocking until fully deactivated!

	down (&xusb->sem);
	minor = xusb->minor;

	/* give back our minor */
	usb_deregister_dev(interface, &xusb_class);

	up (&xusb->sem);
	DBG(DEVICES, "Semaphore released\n");
	XUSB_INFO(xusb, "now disconnected\n");
	KZFREE(xusb);

	up (&disconnect_sem);
}

static void xpp_send_callback(USB_PASS_CB(urb))
{
	struct uframe	*uframe = urb_to_uframe(urb);
	xframe_t	*xframe = &uframe->xframe;
	xusb_t		*xusb = uframe->xusb;
	xbus_t		*xbus = xbus_num(xusb->xbus_num);
	struct timeval	now;
	long		usec;
	int		writes = atomic_read(&xusb->pending_writes);
	int		i;

	if(!xbus) {
		XUSB_ERR(xusb, "Sent URB does not belong to a valid xbus anymore...\n");
		return;
	}
	//flip_parport_bit(6);
	atomic_dec(&xusb->pending_writes);
	do_gettimeofday(&now);
	xusb->last_tx = xframe->tv_submitted;
	usec = usec_diff(&now, &xframe->tv_submitted);
	if(usec > xusb->max_tx_delay)
		xusb->max_tx_delay = usec;
	i = usec / USEC_BUCKET;
	if(i >= NUM_BUCKETS)
		i = NUM_BUCKETS - 1;
	xusb->usb_tx_delay[i]++;
	if(unlikely(usec > tx_sluggish)) {
		atomic_inc(&xusb->usb_sluggish_count);
		if(xusb->sluggish_debounce++ > drop_pcm_after) {
			static int	rate_limit;

			if((rate_limit++ % 1003) == 500)	/* skip first messages */
				XUSB_NOTICE(xusb,
					"Sluggish USB. Dropping next PCM frame (pending_writes=%d)\n",
					writes);
			atomic_inc(&xusb->pcm_tx_drops);
			xusb->drop_next_pcm = 1;
			xusb->sluggish_debounce = 0;
		}
	} else
		xusb->sluggish_debounce = 0;
	/* sync/async unlink faults aren't errors */
	if (urb->status && !(urb->status == -ENOENT || urb->status == -ECONNRESET)) {
		static	int rate_limit;
		if((rate_limit++ % 1000) < 10) {
			XUSB_ERR(xusb,
				"nonzero write bulk status received: %d (pending_writes=%d)\n",
				urb->status, writes);
			dump_xframe("usb-write-error", xbus, xframe, DBG_ANY);
		}
		XUSB_COUNTER(xusb, TX_ERRORS)++;
	} else
		XUSB_COUNTER(xusb, TX_FRAMES)++;
	FREE_SEND_XFRAME(xbus, xframe);
	if(!xusb->present)
		XUSB_ERR(xusb, "A urb from non-connected device?\n");
}

static void xpp_receive_callback(USB_PASS_CB(urb))
{
	struct uframe	*uframe = urb_to_uframe(urb);
	xframe_t	*xframe = &uframe->xframe;
	xusb_t		*xusb = uframe->xusb;
	xbus_t		*xbus = xbus_num(xusb->xbus_num);
	size_t		size;
	bool		do_resubmit = 1;
	bool		is_inuse = 0;
	struct timeval	now;

	do_gettimeofday(&now);
	atomic_dec(&xusb->pending_reads);
	if(!xbus) {
		XUSB_ERR(xusb, "Received URB does not belong to a valid xbus anymore...\n");
		return;
	}
	is_inuse = 1;
	if(!xusb->present) {
		do_resubmit = 0;
		goto err;
	}
	if (urb->status) {
		DBG(GENERAL, "nonzero read bulk status received: %d\n", urb->status);
		XUSB_COUNTER(xusb, RX_ERRORS)++;
		goto err;
	}
	size = urb->actual_length;
	if(size == 0) {
		static int	rate_limit;

		if((rate_limit++ % 5003) == 0)
			XUSB_NOTICE(xusb, "Received a zero length URBs (%d)\n", rate_limit);
		XUSB_COUNTER(xusb, RCV_ZERO_LEN)++;
		goto err;
	}
	atomic_set(&xframe->frame_len, size);
	xframe->tv_received = now;

//	if (debug)
//		dump_xframe("USB_FRAME_RECEIVE", xbus, xframe, debug);
	XUSB_COUNTER(xusb, RX_FRAMES)++;
	/* Send UP */
	xbus_receive_xframe(xbus, xframe);
end:
	if(do_resubmit)
		xusb_listen(xusb);
	return;
err:
	FREE_RECV_XFRAME(xbus, xframe);
	goto end;
}


/*------------------------- Initialization -------------------------*/

static void xpp_usb_cleanup(void)
{
	if(xusb_cache) {
		kmem_cache_destroy(xusb_cache);
		xusb_cache = NULL;
	}
}

static int __init xpp_usb_init(void)
{
	int	ret;
	//xusb_t *xusb;

	INFO("revision %s\n", XPP_VERSION);
	xusb_cache = kmem_cache_create("xusb_cache",
			sizeof(xframe_t) + XFRAME_DATASIZE,
#if (LINUX_VERSION_CODE == KERNEL_VERSION(2,6,22)) && defined(CONFIG_SLUB)
			0, SLAB_STORE_USER,
#else
			0, 0,
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
			NULL, 
#endif
			NULL);
	if(!xusb_cache) {
		ret = -ENOMEM;
		goto failure;
	}

	/* register this driver with the USB subsystem */
	ret = usb_register(&xusb_driver);
	if (ret) {
		ERR("usb_register failed. Error number %d\n", ret);
		goto failure;
	}
	return 0;
failure:
	xpp_usb_cleanup();
	return ret;
}


static void __exit xpp_usb_shutdown(void)
{
	DBG(GENERAL, "\n");
	/* deregister this driver with the USB subsystem */
	usb_deregister(&xusb_driver);
	xpp_usb_cleanup();
}



#ifdef CONFIG_PROC_FS

static int xusb_read_proc(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	int 		len = 0;
	unsigned long	flags;
	int		i;
	//unsigned long stamp = jiffies;
	xusb_t		*xusb = data;
	uint		usb_tx_delay[NUM_BUCKETS];
	const int	mark_limit = tx_sluggish/USEC_BUCKET;

	if(!xusb)
		goto out;
	// TODO: probably needs a per-xusb lock:
	spin_lock_irqsave(&xusb_lock, flags);
	len += sprintf(page + len, "Device: %03d/%03d\n",
		xusb->udev->bus->busnum,
		xusb->udev->devnum
		);
	len += sprintf(page + len, "USB: manufacturer=%s\n", xusb->manufacturer);
	len += sprintf(page + len, "USB: product=%s\n", xusb->product);
	len += sprintf(page + len, "USB: serial=%s\n", xusb->serial);
	len += sprintf(page + len, "Minor: %d\nModel Info: %s\n",
		xusb->minor, xusb->model_info->desc);
	len += sprintf(page + len, "Endpoints:\n"
		"\tIn:  0x%02X  - Size: %d)\n"
		"\tOut: 0x%02X  - Size: %d)\n",
		xusb->endpoints[XUSB_RECV].ep_addr,
		xusb->endpoints[XUSB_RECV].max_size,
		xusb->endpoints[XUSB_SEND].ep_addr,
		xusb->endpoints[XUSB_SEND].max_size
		);
	len += sprintf(page + len, "\npending_writes=%d\n", atomic_read(&xusb->pending_writes));
	len += sprintf(page + len, "pending_reads=%d\n", atomic_read(&xusb->pending_reads));
	len += sprintf(page + len, "max_tx_delay=%d\n", xusb->max_tx_delay);
	xusb->max_tx_delay = 0;
#ifdef	DEBUG_PCM_TIMING
	len += sprintf(page + len, "\nstamp_last_pcm_read=%lld accumulate_diff=%lld\n", stamp_last_pcm_read, accumulate_diff);
#endif
	memcpy(usb_tx_delay, xusb->usb_tx_delay, sizeof(usb_tx_delay));
	len += sprintf(page + len, "usb_tx_delay[%d,%d,%d]: ",
		USEC_BUCKET, BUCKET_START, NUM_BUCKETS);
	for(i = BUCKET_START; i < NUM_BUCKETS; i++) {
		len += sprintf(page + len, "%6d ",
			usb_tx_delay[i]);
		if(i == mark_limit)
			len += sprintf(page + len, "| ");
	}
	len += sprintf(page + len, "\nPCM_TX_DROPS: %5d (sluggish: %d)\n",
		atomic_read(&xusb->pcm_tx_drops),
		atomic_read(&xusb->usb_sluggish_count)
		);
	len += sprintf(page + len, "\nCOUNTERS:\n");
	for(i = 0; i < XUSB_COUNTER_MAX; i++) {
		len += sprintf(page + len, "\t%-15s = %d\n", xusb_counters[i].name, xusb->counters[i]);
	}
#if 0
	len += sprintf(page + len, "<-- len=%d\n", len);
#endif
	spin_unlock_irqrestore(&xusb_lock, flags);
out:
	if (len <= off+count)
		*eof = 1;
	*start = page + off;
	len -= off;
	if (len > count)
		len = count;
	if (len < 0)
		len = 0;
	return len;

}

#endif



MODULE_DESCRIPTION("XPP USB Transport Driver");
MODULE_AUTHOR("Oron Peled <oron@actcom.co.il>");
MODULE_LICENSE("GPL");
MODULE_VERSION(XPP_VERSION);

module_init(xpp_usb_init);
module_exit(xpp_usb_shutdown);
