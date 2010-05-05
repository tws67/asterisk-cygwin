# makefile for the minires resolver, version 1.00
#
# Pierre A. Humblet
# October 2008
#
MAJOR = 1
MINOR = 02
BINDIR = /usr/local/bin
LIBDIR = /usr/local/lib
CFLAGS = -I . -Wall
LDFLAGS = -s
INSTALLFLAGS =

objects = minires.o os-interface.o

# Libraries and dll
all: libminires.dll.a libminires.a cygminires.dll

libminires.dll.a cygminires.dll: minires.h $(objects) minires.def
	rm -f libminires.dll.a cygminires.dll
	gcc $(objects) -shared -Wl,--enable-auto-image-base,--out-implib,libminires.dll.a \
	 -Wl,--major-image-version,${MAJOR},--minor-image-version,${MINOR} \
	 minires.def -o cygminires.dll

libminires.a: minires.h $(objects)
	rm -f libminires.a
	ar cr libminires.a $(objects)

# Test code
.PHONY: try
try: try_stat.exe try_dll.exe

try_dll.exe: try.c libminires.dll.a
	gcc ${CFLAGS} -o try_dll try.c  -L. -lminires 

try_stat.exe: try.c libminires.a
	gcc ${CFLAGS} -o try_stat try.c -L.  -static -lminires

#Install
.PHONY: install
install: libminires.dll.a libminires.a cygminires.dll
	install -d $(BINDIR) $(LIBDIR)
	install -s $(INSTALLFLAGS) cygminires.dll $(BINDIR)
	install $(INSTALLFLAGS) libminires.dll.a libminires.a $(LIBDIR)
	echo "Include files must be installed by hand. See README."

#Clean
.PHONY: clean
clean:
	rm -f *.o *.a *.dll *.exe \#* *~ *.flc *.i *.s *.stackdump
	cd arpa; rm -f *.o *.a *.dll *.exe \#* *~ *.flc *.i *.s *.stackdump
