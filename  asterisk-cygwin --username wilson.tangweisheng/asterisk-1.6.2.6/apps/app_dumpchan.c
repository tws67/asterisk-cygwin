/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2004 - 2005, Anthony Minessale II.
 *
 * Anthony Minessale <anthmct@yahoo.com>
 *
 * A license has been granted to Digium (via disclaimer) for the use of
 * this code.
 *
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Application to dump channel variables
 *
 * \author Anthony Minessale <anthmct@yahoo.com>
 *
 * \ingroup applications
 */

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision: 184707 $")

#include "asterisk/pbx.h"
#include "asterisk/module.h"
#include "asterisk/channel.h"
#include "asterisk/app.h"

/*** DOCUMENTATION
	<application name="DumpChan" language="en_US">
		<synopsis>
			Dump Info About The Calling Channel.
		</synopsis>
		<syntax>
			<parameter name="level">
				<para>Minimun verbose level</para>
			</parameter>
		</syntax>
		<description>
			<para>Displays information on channel and listing of all channel
			variables. If <replaceable>level</replaceable> is specified, output is only
			displayed when the verbose level is currently set to that number
			or greater.</para>
		</description>
		<see-also>
			<ref type="application">NoOp</ref>
			<ref type="application">Verbose</ref>
		</see-also>
	</application>
 ***/

static char *app = "DumpChan";

static int serialize_showchan(struct ast_channel *c, char *buf, size_t size)
{
	struct timeval now;
	long elapsed_seconds = 0;
	int hour = 0, min = 0, sec = 0;
	char cgrp[BUFSIZ/2];
	char pgrp[BUFSIZ/2];
	char formatbuf[BUFSIZ/2];

	now = ast_tvnow();
	memset(buf, 0, size);
	if (!c)
		return 0;

	if (c->cdr) {
		elapsed_seconds = now.tv_sec - c->cdr->start.tv_sec;
		hour = elapsed_seconds / 3600;
		min = (elapsed_seconds % 3600) / 60;
		sec = elapsed_seconds % 60;
	}

	snprintf(buf,size,
			"Name=               %s\n"
			"Type=               %s\n"
			"UniqueID=           %s\n"
			"CallerIDNum=        %s\n"
			"CallerIDName=       %s\n"
			"DNIDDigits=         %s\n"
			"RDNIS=              %s\n"
			"Parkinglot=         %s\n"
			"Language=           %s\n"
			"State=              %s (%d)\n"
			"Rings=              %d\n"
			"NativeFormat=       %s\n"
			"WriteFormat=        %s\n"
			"ReadFormat=         %s\n"
			"RawWriteFormat=     %s\n"
			"RawReadFormat=      %s\n"
			"1stFileDescriptor=  %d\n"
			"Framesin=           %d %s\n"
			"Framesout=          %d %s\n"
			"TimetoHangup=       %ld\n"
			"ElapsedTime=        %dh%dm%ds\n"
			"Context=            %s\n"
			"Extension=          %s\n"
			"Priority=           %d\n"
			"CallGroup=          %s\n"
			"PickupGroup=        %s\n"
			"Application=        %s\n"
			"Data=               %s\n"
			"Blocking_in=        %s\n",
			c->name,
			c->tech->type,
			c->uniqueid,
			S_OR(c->cid.cid_num, "(N/A)"),
			S_OR(c->cid.cid_name, "(N/A)"),
			S_OR(c->cid.cid_dnid, "(N/A)"),
			S_OR(c->cid.cid_rdnis, "(N/A)"),
			c->parkinglot,
			c->language,
			ast_state2str(c->_state),
			c->_state,
			c->rings,
			ast_getformatname_multiple(formatbuf, sizeof(formatbuf), c->nativeformats),
			ast_getformatname_multiple(formatbuf, sizeof(formatbuf), c->writeformat),
			ast_getformatname_multiple(formatbuf, sizeof(formatbuf), c->readformat),
			ast_getformatname_multiple(formatbuf, sizeof(formatbuf), c->rawwriteformat),
			ast_getformatname_multiple(formatbuf, sizeof(formatbuf), c->rawreadformat),
			c->fds[0], c->fin & ~DEBUGCHAN_FLAG, (c->fin & DEBUGCHAN_FLAG) ? " (DEBUGGED)" : "",
			c->fout & ~DEBUGCHAN_FLAG, (c->fout & DEBUGCHAN_FLAG) ? " (DEBUGGED)" : "", (long)c->whentohangup.tv_sec,
			hour,
			min,
			sec,
			c->context,
			c->exten,
			c->priority,
			ast_print_group(cgrp, sizeof(cgrp), c->callgroup),
			ast_print_group(pgrp, sizeof(pgrp), c->pickupgroup),
			( c->appl ? c->appl : "(N/A)" ),
			( c-> data ? S_OR(c->data, "(Empty)") : "(None)"),
			(ast_test_flag(c, AST_FLAG_BLOCKING) ? c->blockproc : "(Not Blocking)"));

	return 0;
}

static int dumpchan_exec(struct ast_channel *chan, void *data)
{
	struct ast_str *vars = ast_str_thread_get(&ast_str_thread_global_buf, 16);
	char info[1024];
	int level = 0;
	static char *line = "================================================================================";

	if (!ast_strlen_zero(data))
		level = atoi(data);

	if (option_verbose >= level) {
		serialize_showchan(chan, info, sizeof(info));
		pbx_builtin_serialize_variables(chan, &vars);
		ast_verbose("\nDumping Info For Channel: %s:\n%s\nInfo:\n%s\nVariables:\n%s%s\n", chan->name, line, info, ast_str_buffer(vars), line);
	}

	return 0;
}

static int unload_module(void)
{
	return ast_unregister_application(app);
}

static int load_module(void)
{
	return ast_register_application_xml(app, dumpchan_exec);
}

AST_MODULE_INFO_STANDARD(ASTERISK_GPL_KEY, "Dump Info About The Calling Channel");
