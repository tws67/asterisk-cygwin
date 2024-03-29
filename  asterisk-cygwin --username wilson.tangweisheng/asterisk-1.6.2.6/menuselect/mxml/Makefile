#
# "$Id: Makefile.in 23382 2006-04-29 15:44:02Z russell $"
#
# Makefile for Mini-XML, a small XML-like file parsing library.
#
# Copyright 2003-2005 by Michael Sweet.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Library General Public
# License as published by the Free Software Foundation; either
# version 2, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#

#
# Compiler tools definitions...
#

AR		=	/usr/bin/ar
ARFLAGS		=	crvs
CC		=	gcc
CFLAGS		=	$(OPTIM) -Wall -Os -g -Wall -Os -g -Wall -Os -g -Wall -Os -g -Wall      
CP		=	/usr/bin/cp
DSO		=	:
DSOFLAGS	=	
LDFLAGS		=	$(OPTIM) 
INSTALL		=	/usr/bin/install -c
LIBMXML		=	libmxml.a
LN		=	/usr/bin/ln -s
MKDIR		=	/usr/bin/mkdir
NROFF		=	@NROFF@
OPTIM		=	-Os -g
RANLIB		=	ranlib
RM		=	/usr/bin/rm -f
SHELL		=	/bin/sh


#
# Configured directories...
#

prefix		=	/usr/local
exec_prefix	=	/usr/local
bindir		=	${exec_prefix}/bin
includedir	=	${prefix}/include
libdir		=	${exec_prefix}/lib
mandir		=	${datarootdir}/man
docdir		=	${datarootdir}/doc/mxml
datarootdir =	${prefix}/share
BUILDROOT	=	$(DSTROOT)


#
# Manpage extensions...
#

CAT1EXT		=	@CAT1EXT@
CAT3EXT		=	@CAT3EXT@
MAN1EXT		=	@MAN1EXT@
MAN3EXT		=	@MAN3EXT@


#
# Install commands...
#

INSTALL_BIN	=	$(LIBTOOL) $(INSTALL) -m 755 -s
INSTALL_DATA	=	$(INSTALL) -m 644
INSTALL_DIR	=	$(INSTALL) -d
INSTALL_LIB	=	$(LIBTOOL) $(INSTALL) -m 755
INSTALL_MAN	=	$(INSTALL) -m 644
INSTALL_SCRIPT	=	$(INSTALL) -m 755


#
# Rules...
#

.SUFFIXES:	.0 .1 .3 .c .man .o
.c.o:
	$(CC) $(CFLAGS) -c $<
.man.0 .man.1 .man.3:
	$(RM) $@
	$(NROFF) -man $< >$@


#
# Targets...
#

DOCFILES	=	doc/mxml.html doc/mxmldoc.xsd \
			README COPYING CHANGES
PUBLIBOBJS	=	mxml-attr.o mxml-entity.o mxml-file.o mxml-index.o \
			mxml-node.o mxml-search.o mxml-set.o
LIBOBJS		=	$(PUBLIBOBJS) mxml-private.o mxml-string.o
OBJS		=	mxmldoc.o testmxml.o $(LIBOBJS)
TARGETS		=	$(LIBMXML) mxmldoc doc/mxml.$(CAT3EXT) \
			doc/mxmldoc.$(CAT1EXT) testmxml mxml.xml


#
# Make everything...
#

all:		Makefile configure config.h $(TARGETS)


#
# Clean everything...
#

clean:
	$(RM) $(OBJS) $(TARGETS)
	$(RM) mxmldoc-static libmxml.a
	$(RM) *.bck *.bak
	$(RM) config.cache config.log config.status config.h
	$(RM) -r autom4te*.cache

distclean: clean
	$(RM) mxml.list Makefile

#
# Install everything...
#

install:	$(TARGETS) install-$(LIBMXML) install-libmxml.a
	$(INSTALL_DIR) $(BUILDROOT)$(bindir)
	$(INSTALL_BIN) mxmldoc $(BUILDROOT)$(bindir) 
	$(INSTALL_DIR) $(BUILDROOT)$(docdir)
	for file in $(DOCFILES); do \
		$(INSTALL_MAN) $$file $(BUILDROOT)$(docdir); \
	done
	$(INSTALL_DIR) $(BUILDROOT)$(includedir)
	$(INSTALL_DATA) mxml.h $(BUILDROOT)$(includedir)
	$(INSTALL_DIR) $(BUILDROOT)$(libdir)/pkgconfig
	$(INSTALL_DATA) mxml.pc $(BUILDROOT)$(libdir)/pkgconfig
	$(INSTALL_DIR) $(BUILDROOT)$(mandir)/cat1
	$(INSTALL_MAN) doc/mxmldoc.$(CAT1EXT) $(BUILDROOT)$(mandir)/cat1/mxmldoc.$(CAT1EXT)
	$(INSTALL_DIR) $(BUILDROOT)$(mandir)/cat3
	$(INSTALL_MAN) doc/mxml.$(CAT3EXT) $(BUILDROOT)$(mandir)/cat3/mxml.$(CAT3EXT)
	$(INSTALL_DIR) $(BUILDROOT)$(mandir)/man1
	$(INSTALL_MAN) doc/mxmldoc.man $(BUILDROOT)$(mandir)/man1/mxmldoc.$(MAN1EXT)
	$(INSTALL_DIR) $(BUILDROOT)$(mandir)/man3
	$(INSTALL_MAN) doc/mxml.man $(BUILDROOT)$(mandir)/man3/mxml.$(MAN3EXT)

install-libmxml.a:
	$(INSTALL_DIR) $(BUILDROOT)$(libdir)
	$(INSTALL_LIB) libmxml.a $(BUILDROOT)$(libdir)

install-libmxml.so.1.0:
	$(INSTALL_DIR) $(BUILDROOT)$(libdir)
	$(INSTALL_LIB) libmxml.so.1.0 $(BUILDROOT)$(libdir)
	$(RM) $(BUILDROOT)$(libdir)/libmxml.so
	$(LN) libmxml.so.1.0 $(BUILDROOT)$(libdir)/libmxml.so
	$(RM) $(BUILDROOT)$(libdir)/libmxml.so.1
	$(LN) libmxml.so.1.0 $(BUILDROOT)$(libdir)/libmxml.so.1

install-libmxml.sl.1:
	$(INSTALL_DIR) $(BUILDROOT)$(libdir)
	$(INSTALL_LIB) libmxml.sl.1 $(BUILDROOT)$(libdir)
	$(RM) $(BUILDROOT)$(libdir)/libmxml.so
	$(LN) libmxml.sl.1 $(BUILDROOT)$(libdir)/libmxml.sl

install-libmxml.1.dylib:
	$(INSTALL_DIR) $(BUILDROOT)$(libdir)
	$(INSTALL_LIB) libmxml.1.dylib $(BUILDROOT)$(libdir)
	$(RM) $(BUILDROOT)$(libdir)/libmxml.dylib
	$(LN) libmxml.1.dylib $(BUILDROOT)$(libdir)/libmxml.dylib


#
# Uninstall everything...
#

uninstall: uninstall-$(LIBMXML) uninstall-libmxml.a
	$(RM) $(BUILDROOT)$(bindir)/mxmldoc
	$(RM) -r $(BUILDROOT)$(docdir)
	$(RM) $(BUILDROOT)$(includedir)/mxml.h
	$(RM) $(BUILDROOT)$(libdir)/pkgconfig/mxml.pc
	$(RM) $(BUILDROOT)$(mandir)/cat1/mxmldoc.$(CAT1EXT)
	$(RM) $(BUILDROOT)$(mandir)/cat3/mxml.$(CAT3EXT)
	$(RM) $(BUILDROOT)$(mandir)/man1/mxmldoc.$(MAN1EXT)
	$(RM) $(BUILDROOT)$(mandir)/man3/mxml.$(MAN3EXT)

uninstall-libmxml.a:
	$(RM) $(BUILDROOT)$(libdir)/libmxml.a

uninstall-libmxml.so.1.0:
	$(RM) $(BUILDROOT)$(libdir)/libmxml.so
	$(RM) $(BUILDROOT)$(libdir)/libmxml.so.1
	$(RM) $(BUILDROOT)$(libdir)/libmxml.so.1.0

uninstall-libmxml.sl.1:
	$(RM) $(BUILDROOT)$(libdir)/libmxml.sl
	$(RM) $(BUILDROOT)$(libdir)/libmxml.sl.1

uninstall-libmxml.1.dylib:
	$(RM) $(BUILDROOT)$(libdir)/libmxml.dylib
	$(RM) $(BUILDROOT)$(libdir)/libmxml.1.dylib


#
# Make packages using EPM (http://www.easysw.com/epm/)
#

epm:	all
	epm --output-dir dist -v -f native mxml
	epm --output-dir dist -v -f portable mxml


#
# autoconf stuff...
#

Makefile:	Makefile.in
	if test -f config.status; then \
		./config.status --recheck; \
		./config.status; \
	else \
		./configure; \
	fi
	touch config.h


config.h:	configure config.h.in
	if test -f config.status; then \
		./config.status --recheck; \
		./config.status; \
	else \
		./configure; \
	fi
	touch config.h


#
# libmxml.a
#

libmxml.a:	$(LIBOBJS)
	$(RM) $@
	$(AR) $(ARFLAGS) $@ $(LIBOBJS)
	$(RANLIB) $@

$(LIBOBJS):	mxml.h


#
# libmxml.so.1.0
#

libmxml.so.1.0:	$(LIBOBJS)
	$(DSO) $(DSOFLAGS) -o libmxml.so.1.0 $(LIBOBJS)
	$(RM) libmxml.so libmxml.so.1
	$(LN) libmxml.so.1.0 libmxml.so
	$(LN) libmxml.so.1.0 libmxml.so.1


#
# libmxml.sl.1
#

libmxml.sl.1:	$(LIBOBJS)
	$(DSO) $(DSOFLAGS) -o libmxml.sl.1 $(LIBOBJS)
	$(RM) libmxml.sl libmxml.sl.1
	$(LN) libmxml.sl.1 libmxml.sl


#
# libmxml.1.dylib
#

libmxml.1.dylib:	$(LIBOBJS)
	$(DSO) $(DSOFLAGS) -o libmxml.1.dylib \
		-install_name $(libdir)/libmxml.dylib \
		-current_version 1.0.0 \
		-compatibility_version 1.0.0 \
		$(LIBOBJS)
	$(RM) libmxml.dylib libmxml.1.dylib
	$(LN) libmxml.1.dylib libmxml.dylib


#
# mxmldoc
#

mxmldoc:	$(LIBMXML) mxmldoc.o
	$(CC) $(LDFLAGS) -o $@ mxmldoc.o -L. -lmxml

mxmldoc-static:	libmxml.a mxmldoc.o
	$(CC) $(LDFLAGS) -o $@ mxmldoc.o libmxml.a

mxmldoc.o:	mxml.h


#
# testmxml
#

testmxml:	libmxml.a testmxml.o
	$(CC) $(LDFLAGS) -o $@ testmxml.o libmxml.a
	@echo Testing library...
	./testmxml test.xml >temp1.xml 2>temp1s.xml
	./testmxml temp1.xml >temp2.xml 2>temp2s.xml
	@if cmp temp1.xml temp2.xml; then \
		echo Stdio file test passed!; \
		$(RM) temp2.xml temp2s.xml; \
	else \
		echo Stdio file test failed!; \
	fi
	@if cmp temp1.xml temp1s.xml; then \
		echo String test passed!; \
		$(RM) temp1.xml temp1s.xml; \
	else \
		echo String test failed!; \
	fi
	@if cmp test.xml test.xmlfd; then \
		echo File descriptor test passed!; \
		$(RM) test.xmlfd; \
	else \
		echo File descriptor test failed!; \
	fi

testmxml.o:	mxml.h


#
# mxml.xml
#

mxml.xml:	mxmldoc-static mxml.h $(PUBLIBOBJS:.o=.c)
	$(RM) mxml.xml
	./mxmldoc-static mxml.xml mxml.h $(PUBLIBOBJS:.o=.c) >doc/reference.html

valgrind:	mxmldoc-static
	$(RM) valgrind.xml
	valgrind --tool=memcheck --leak-check=yes ./mxmldoc-static \
		valgrind.xml mxml.h $(PUBLIBOBJS:.o=.c) \
		>valgrind.html 2>valgrind.out


#
# All object files depend on the makefile...
#

$(OBJS):	Makefile config.h


#
# End of "$Id: Makefile.in 23382 2006-04-29 15:44:02Z russell $".
#
