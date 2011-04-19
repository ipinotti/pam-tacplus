include ../../common.mk

CFLAGS= -O2 -Wall -I. -I$(ROOTDIR)/include -I$(ROOTDIR)/$(FSDIR)/include
LDFLAGS= -L$(ROOTDIR)/$(FSDIR)/lib

export CFLAGS LDFLAGS

all: Makefile
	$(MAKE) all

Makefile:
	./configure --prefix='$(ROOTDIR)/$(FSDIR)' --host='powerpc-linux-gnu' --build='i386'

install:
	$(MAKE) install

clean:
	$(MAKE) clean

distclean: clean
