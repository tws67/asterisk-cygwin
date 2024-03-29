#
# Makefile
#
# Make file for OpenH323 support layer
#

.PHONY: Makefile.ast clean

default::	

# Verify those options with main Makefile
STDCCFLAGS	= -DNDEBUG
STDCCFLAGS	+= -I../../include -include ../../include/asterisk/autoconfig.h
STDCCFLAGS	+= -fPIC
#OPTCCFLAGS	+=
CFLAGS		= -pipe
TARGET		= libchanh323.a
TARGET		+= Makefile.ast
SOURCES		= ast_h323.cxx compat_h323.cxx cisco-h225.cxx caps_h323.cxx
OBJDIR		= .
OBJS		=

ifndef OPENH323DIR
OPENH323DIR=
endif

ifneq ($(wildcard $(OPENH323DIR)/openh323u.mak),)
include $(OPENH323DIR)/openh323u.mak
endif

notrace::
	$(MAKE) NOTRACE=1 opt

$(SOURCES)::	Makefile ../../Makefile
	touch $@

libchanh323.a:	$(OBJS)
	ar crv $@ $(OBJS)

cisco-h225.cxx::	cisco-h225.asn
	asnparser -m CISCO_H225 -c $<

Makefile.ast:
	@echo H323CFLAGS  = $(STDCCFLAGS) $(OPTCCFLAGS) $(CFLAGS) >$@.tmp
	@echo H323LDFLAGS = $(CFLAGS) $(LDFLAGS) >>$@.tmp
	@echo H323LDLIBS  = $(LDLIBS) $(ENDLDLIBS) $(ENDLDFLAGS) >>$@.tmp
	@if [ -r $@ ] && cmp -s $@ $@.tmp; then rm -f $@.tmp; else mv -f $@.tmp $@; fi

clean::
	rm -f $(TARGET) $(OBJS) Makefile.ast *.dep
