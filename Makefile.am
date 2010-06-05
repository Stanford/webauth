# Makefile.am -- Automake makefile for WebAuth.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2009 Board of Trustees, Leland Stanford Jr. University
#
# See README for licensing terms.

# These files are needed for the Perl module builds.  They're listed here to
# be added to EXTRA_DIST and so that they can be copied over properly for
# builddir != srcdir builds.
PERL_FILES = perl/WebAuth.xs perl/lib/WebAuth.pm perl/lib/WebKDC.pm \
	perl/lib/WebKDC/Config.pm perl/lib/WebKDC/Token.pm \
	perl/lib/WebKDC/WebKDCException.pm perl/lib/WebKDC/WebRequest.pm \
	perl/lib/WebKDC/WebResponse.pm perl/lib/WebKDC/XmlDoc.pm \
	perl/lib/WebKDC/XmlElement.pm perl/test.pl perl/typemap

AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = .gitignore HACKING LICENSE autogen conf/README		   \
	conf/debian/webauth.conf conf/debian/webauth.load		   \
	conf/debian/webauthldap.conf conf/debian/webauthldap.load	   \
	conf/debian/webkdc.conf conf/debian/webkdc.load			   \
	conf/sample-webauth.conf conf/stanford-ldap.conf		   \
	conf/stanford-webauth.conf conf/token.acl docs/install-spnego	   \
	docs/install-webkdc docs/mod_webauth.html.en docs/mod_webauth.xml  \
	docs/mod_webauthldap.html.en docs/mod_webauthldap.xml		   \
	docs/mod_webkdc.html.en docs/mod_webkdc.xml docs/protocol.html	   \
	docs/protocol.txt docs/protocol.xml docs/test-plan docs/userauth   \
	docs/weblogin-config docs/weblogin-cookies docs/weblogin-flow	   \
	lib/mapfile lib/mkheader lib/webauth.h.in modules/webauth/krb5.c   \
	modules/webauth/mod_webauth.c modules/webauth/mod_webauth.h	   \
	modules/webauth/util.c modules/webauth/webkdc.c			   \
	modules/webauthldap/mod_webauthldap.c				   \
	modules/webauthldap/mod_webauthldap.h modules/webkdc/acl.c	   \
	modules/webkdc/mod_webkdc.c modules/webkdc/mod_webkdc.h		   \
	modules/webkdc/util.c perl/README perl/MANIFEST perl/MANIFEST.SKIP \
	tests/TESTS tests/mod_webauth tools/wa_keyring.pod		   \
	tools/weblogin-passcheck weblogin/images/confirm.xcf		   \
	weblogin/images/error.xcf weblogin/images/help.xcf		   \
	weblogin/images/login.xcf weblogin/images/logout.xcf $(PERL_FILES)

lib_LTLIBRARIES = lib/libwebauth.la
lib_libwebauth_la_SOURCES = lib/attrs.c lib/base64.c lib/key.c \
	lib/krb5.c lib/misc.c lib/random.c lib/token.c lib/webauth.h \
	lib/webauthp.h
EXTRA_lib_libwebauth_la_SOURCES = lib/krb5-heimdal.c lib/krb5-mit.c
lib_libwebauth_la_CPPFLAGS = $(CRYPTO_CPPFLAGS) $(KRB5_CPPFLAGS)
lib_libwebauth_la_LDFLAGS = -version-info 4:0:0 $(VERSION_LDFLAGS) \
	$(CRYPTO_LDFLAGS) $(KRB5_LDFLAGS)
lib_libwebauth_la_LIBADD = $(CRYPTO_LIBS) $(KRB5_LIBS)

bin_PROGRAMS = tools/wa_keyring
tools_wa_keyring_LDADD = lib/libwebauth.la $(CRYPTO_LIBS)
dist_man_MANS = tools/wa_keyring.1

# Only install the WebLogin script and configuration if configured to build
# and install mod_webkdc.  These don't have to go together, but that's the
# strongly recommended configuration and this is simpler than adding yet
# another configure option.
if BUILD_WEBKDC
weblogindir = $(datadir)/weblogin
imagedir    = $(weblogindir)/generic/images
templatedir = $(weblogindir)/generic/templates
dist_weblogin_DATA = weblogin/login.fcgi weblogin/logout.fcgi
dist_image_DATA = weblogin/images/confirm.png weblogin/images/error.png	\
	weblogin/images/help.png weblogin/images/login.png		\
	weblogin/images/logout.png
dist_template_DATA = weblogin/templates/confirm.tmpl			\
	weblogin/templates/error.tmpl weblogin/templates/help.html	\
	weblogin/templates/login.tmpl weblogin/templates/logout.tmpl
endif

# Build and install the Perl bindings if desired.
BINDINGS =
BINDINGS_INSTALL =
if BUILD_PERL
BINDINGS += perl/WebAuth.o
BINDINGS_INSTALL += install-data-local-perl
endif

# The following section sets up the Perl module build properly.  Most of the
# complexity is here to handle building outside of the source directory, in
# which case we need to copy various files from the source directory and make
# sure they're up to date since Perl can't handle VPATH builds.
perl/WebAuth.o: $(srcdir)/perl/lib/WebAuth.pm $(srcdir)/perl/WebAuth.xs \
		$(srcdir)/perl/typemap
	set -e; if [ x"$(builddir)" != x"$(srcdir)" ] ; then \
	    for d in lib lib/WebKDC ; do \
		[ ! -d "$(builddir)/$$d" ] || mkdir "$(builddir)/$$d" ; \
	    done ; \
	    for f in $(PERL_FILES) ; do \
		cp "$(srcdir)/$$f" "$(builddir)/$$f" ; \
	    done \
	fi
	cd perl && perl Makefile.PL
	cd perl && $(MAKE) OPTIMIZE="$(CFLAGS) $(PERL_WARNINGS)"

install-data-local-perl: perl/WebAuth.o
	cd perl && $(MAKE) install DESTDIR=$(DESTDIR)

# These are the source files for the Apache modules for passing to apxs.
# They are prefixed with $(srcdir) since that's what we want the dependency
# to be on.  Due to apxs misfeatures, we have to copy them into the build
# directory before building.  The mod_*.c file must be listed first or apxs
# will generate the module under the wrong name.
#
# Header files aren't included here, since apxs doesn't recognize them as
# headers and passes them along to the linker.
MOD_WEBAUTH_FILES = modules/webauth/mod_webauth.c modules/webauth/krb5.c \
	modules/webauth/util.c modules/webauth/webkdc.c
MOD_WEBAUTH_FILES_SRC = $(srcdir)/modules/webauth/mod_webauth.c \
	$(srcdir)/modules/webauth/krb5.c $(srcdir)/modules/webauth/util.c \
	$(srcdir)/modules/webauth/webkdc.c
MOD_WEBAUTHLDAP_FILES = modules/webauthldap/mod_webauthldap.c
MOD_WEBAUTHLDAP_FILES_SRC = $(srcdir)/modules/webauthldap/mod_webauthldap.c
MOD_WEBKDC_FILES = modules/webkdc/mod_webkdc.c modules/webkdc/acl.c \
	modules/webkdc/util.c
MOD_WEBKDC_FILES_SRC = $(srcdir)/modules/webkdc/mod_webkdc.c \
	$(srcdir)/modules/webkdc/acl.c $(srcdir)/modules/webkdc/util.c

# Automake can't handle apxs directly, so we do the module builds via explicit
# rules.  Installation is handled by an install-exec-local rule.
MODULES =
MODULES_INSTALL =

if BUILD_WEBAUTH
MODULES += modules/webauth/mod_webauth.la
MODULES_INSTALL += install-exec-local-webauth
endif

if BUILD_WEBAUTHLDAP
MODULES += modules/webauthldap/mod_webauthldap.la
MODULES_INSTALL += install-exec-local-webauthldap
endif

if BUILD_WEBKDC
MOD_WEBKDC = modules/webkdc/mod_webkdc.la
MOD_WEBKDC_INSTALL = install-exec-local-webkdc
endif

if BUILD_WEBKDC
MODULES += modules/webkdc/mod_webkdc.la
MODULES_INSTALL += install-exec-local-webkdc
endif

modules/webauth/mod_webauth.la: lib/libwebauth.la lib/webauth.h \
		$(MOD_WEBAUTH_FILES_SRC) modules/webauth/mod_webauth.h
	set -e; if [ x"$(srcdir)" != x"$(builddir)" ] ; then \
	    [ -d modules ] || mkdir modules ; \
	    [ -d modules/webauth ] || mkdir modules/webauth ; \
	    for f in $(MOD_WEBAUTH_FILES_SRC) ; do \
		cp $$f modules/webauth/ ; \
	    done ; \
	fi
	$(APXS) -c $(APXS_CFLAGS) -I. -I$(srcdir) $(CPPFLAGS) \
	    $(CURL_CPPFLAGS) $(LDFLAGS) $(CURL_LDFLAGS) lib/libwebauth.la \
	    $(CURL_LIBS) $(APXS_DEPEND_LIBS) $(LIBS) $(MOD_WEBAUTH_FILES)

modules/webauthldap/mod_webauthldap.la: lib/libwebauth.la lib/webauth.h \
		$(MOD_WEBAUTHLDAP_FILES_SRC) \
		modules/webauthldap/mod_webauthldap.h
	set -e; if [ x"$(srcdir)" != x"$(builddir)" ] ; then \
	    [ -d modules ] || mkdir modules ; \
	    [ -d modules/webauthldap ] || mkdir modules/webauthldap ; \
	    for f in $(MOD_WEBAUTHLDAP_FILES_SRC) ; do \
		cp $$f modules/webauthldap/ ; \
	    done ; \
	fi
	$(APXS) -c $(APXS_CFLAGS) -I. -I$(srcdir) $(CPPFLAGS) \
	    $(KRB5_CPPFLAGS) $(LDAP_CPPFLAGS) $(LDFLAGS) $(KRB5_LDFLAGS) \
	    $(LDAP_LDFLAGS) $(APXS_KRB5_LIBS) $(LDAP_LIBS) $(LIBS) \
	    $(MOD_WEBAUTHLDAP_FILES)

modules/webkdc/mod_webkdc.la: lib/libwebauth.la lib/webauth.h \
		$(MOD_WEBKDC_FILES_SRC) modules/webkdc/mod_webkdc.h
	set -e; if [ x"$(srcdir)" != x"$(builddir)" ] ; then \
	    [ -d modules ] || mkdir modules ; \
	    [ -d modules/webkdc ] || mkdir modules/webkdc ; \
	    for f in $(MOD_WEBKDC_FILES_SRC) ; do \
		cp $$f modules/webkdc/ ; \
	    done ; \
	fi
	$(APXS) -c $(APXS_CFLAGS) -I. -I$(srcdir) $(CPPFLAGS) $(LDFLAGS) \
	    lib/libwebauth.la $(APXS_DEPEND_LIBS) $(LIBS) $(MOD_WEBKDC_FILES)

install-exec-local-webauth: modules/webauth/mod_webauth.la
	$(APXS) -i modules/webauth/mod_webauth.la

install-exec-local-webauthldap: modules/webauthldap/mod_webauthldap.la
	$(APXS) -i modules/webauthldap/mod_webauthldap.la

install-exec-local-webkdc: modules/webkdc/mod_webkdc.la
	$(APXS) -i modules/webkdc/mod_webkdc.la

# Run the hooks for bindings and Apache modules.
all-local: $(BINDINGS) $(MODULES)
install-exec-local: $(BINDINGS_INSTALL) $(MODULES_INSTALL)

CLEANFILES = tests/webauth_keyring tests/webauth_keyring2
DISTCLEANFILES = perl/Makefile lib/webauth.h
MAINTAINERCLEANFILES = Makefile.in aclocal.m4 config.h.in config.h.in~ \
	configure docs/protocol.html docs/protocol.txt m4/libtool.m4 \
	m4/ltoptions.m4 m4/ltsugar.m4 m4/ltversion.m4 m4/lt~obsolete.m4 \
	tests/webauth_keyring tests/webauth_keyring2 tools/wa_keyring.1

# Also run make clean in the perl directory if needed and clean up the module
# directories.
clean-local:
	set -e; if [ x"$(builddir)" != x"$(srcdir)" ] ; then \
	    rm -rf modules/webauth modules/webauthldap modules/webkdc ; \
	else \
	    rm -rf modules/*/.libs modules/*/*.la modules/*/*.lo \
		modules/*/*.slo ; \
	fi
	set -e; if [ -f "perl/Makefile" ] ; then \
	    cd perl && $(MAKE) clean ; \
	    cd perl && [ ! -f Makefile.old ] || mv Makefile.old Makefile ; \
	fi

# Remove the Perl files we copied over if srcdir != builddir.
distclean-local:
	set -e; if [ x"$(builddir)" != x"$(srcdir)" ] ; then \
	    for f in $(PERL_FILES) ; do \
		rm -f "$(builddir)/$$f" ; \
	    done ; \
	    rmdir perl/WebKDC 2>/dev/null || true ; \
	fi

# A set of flags for warnings.  Add -O because gcc won't find some warnings
# without optimization turned on, and add -DDEBUG=1 so we'll also compile all
# debugging code and test it.
WARNINGS = -g -O -DDEBUG=1 -Wall -W -Wendif-labels -Wpointer-arith \
        -Wbad-function-cast -Wwrite-strings -Wstrict-prototypes \
        -Wmissing-prototypes -Wnested-externs -Werror
APXS_WARNINGS = -Wc,-g -Wc,-O -Wc,-DDEBUG=1 -Wc,-Wall -Wc,-W \
	-Wc,-Wendif-labels -Wc,-Wpointer-arith -Wc,-Wbad-function-cast \
	-Wc,-Wwrite-strings -Wc,-Wstrict-prototypes -Wc,-Wmissing-prototypes \
	-Wc,-Wnested-externs -Wc,-Werror

warnings:
	$(MAKE) CFLAGS='$(WARNINGS)'
	$(MAKE) CFLAGS='$(WARNINGS)' $(check_PROGRAMS)

# The bits below are for the test suite, not for the main package.
check_PROGRAMS = tests/runtests tests/libwebauth/attrs_test \
	tests/libwebauth/base64_test tests/libwebauth/hex_test \
	tests/libwebauth/key_test tests/libwebauth/krb5_test \
	tests/libwebauth/krb5_tgt_test tests/libwebauth/random_test \
	tests/libwebauth/token_test

# All of the test programs.
tests_libwebauth_attrs_test_SOURCES = tests/libwebauth/attrs_test.c \
	tests/libwebauth/webauthtest.h
tests_libwebauth_attrs_test_LDADD = lib/libwebauth.la
tests_libwebauth_base64_test_SOURCES = tests/libwebauth/base64_test.c \
	tests/libwebauth/webauthtest.h
tests_libwebauth_base64_test_LDADD = lib/libwebauth.la
tests_libwebauth_hex_test_SOURCES = tests/libwebauth/hex_test.c \
	tests/libwebauth/webauthtest.h
tests_libwebauth_hex_test_LDADD = lib/libwebauth.la
tests_libwebauth_key_test_SOURCES = tests/libwebauth/key_test.c \
	tests/libwebauth/webauthtest.h
tests_libwebauth_key_test_LDADD = lib/libwebauth.la
tests_libwebauth_krb5_test_SOURCES = tests/libwebauth/krb5_test.c \
	tests/libwebauth/webauthtest.h
tests_libwebauth_krb5_test_LDADD = lib/libwebauth.la
tests_libwebauth_krb5_tgt_test_SOURCES = tests/libwebauth/krb5_tgt_test.c \
	tests/libwebauth/webauthtest.h
tests_libwebauth_krb5_tgt_test_LDADD = lib/libwebauth.la
tests_libwebauth_random_test_SOURCES = tests/libwebauth/random_test.c \
	tests/libwebauth/webauthtest.h
tests_libwebauth_random_test_LDADD = lib/libwebauth.la
tests_libwebauth_token_test_SOURCES = tests/libwebauth/token_test.c \
	tests/libwebauth/webauthtest.h
tests_libwebauth_token_test_LDADD = lib/libwebauth.la

check-local: $(check_PROGRAMS) $(srcdir)/tests/TESTS
	cd tests && ./runtests $(abs_top_srcdir)/tests/TESTS
	@set -e; if [ -f perl/Makefile ] ; then \
	    echo '' ; \
	    cd perl && LD_LIBRARY_PATH=$(abs_top_builddir)/lib/.libs \
		$(MAKE) test ; \
	fi
