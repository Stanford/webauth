# Temporary hand-made makefile for webauthldap module
# $Id$

srcdir		= .
top_srcdir	= ../../..
top_builddir	= ../../../


APXS		= /usr/local/apache2/bin/apxs

APXS_CFLAGS	= -Wc,-Wall -Wc,-g
CPPFLAGS	=   

LDFLAGS		= 
LDLIBS		= -lkrb4 -ldes425 -lkrb5 -lk5crypto -lcom_err -lldap -llber -lsasl2 -lssl -lcrypto -lnsl -lsocket -lresolv

SOURCES		= mod_webauthldap.c

all: mod_webauth.o

mod_webauth.o: $(SOURCES) mod_webauthldap.h
	$(APXS) -c $(APXS_CFLAGS) $(CPPFLAGS) $(LDFLAGS) $(LDLIBS) $(SOURCES)

install:
	$(APXS) -n webauthldap -i mod_webauthldap.la; ldd /usr/local/apache2/modules/mod_webauthldap.so

clean:
	rm -rf *.o *.la *.lo *.slo .libs *~ core \#*
