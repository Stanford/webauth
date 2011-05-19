# Automake makefile for WebAuth.
#
# Written by Russ Allbery <rra@stanford.edu>
# Copyright 2009, 2010, 2011
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

# These files are needed for the Perl module builds.  They're listed here to
# be added to EXTRA_DIST and so that they can be copied over properly for
# builddir != srcdir builds.
PERL_FILES = perl/WebAuth.xs perl/lib/WebAuth.pm perl/lib/WebKDC.pm	    \
	perl/lib/WebKDC/Config.pm perl/lib/WebKDC/Token.pm		    \
	perl/lib/WebKDC/WebKDCException.pm perl/lib/WebKDC/WebRequest.pm    \
	perl/lib/WebKDC/WebResponse.pm perl/lib/WebKDC/XmlDoc.pm	    \
	perl/lib/WebKDC/XmlElement.pm perl/lib/WebLogin.pm perl/t/TODO	    \
	perl/t/changepw.t perl/t/config.t perl/t/data/README		    \
	perl/t/data/kadmin-fake perl/t/data/kadmin.conf			    \
	perl/t/data/templates/confirm.tmpl perl/t/data/templates/error.tmpl \
	perl/t/data/templates/login.tmpl perl/t/data/templates/logout.tmpl  \
	perl/t/data/templates/pwchange.tmpl perl/t/data/token.acl	    \
	perl/t/data/webkdc.conf perl/t/krb5.t perl/t/lib/Util.pm	    \
	perl/t/misc.t perl/t/page-pwchange.t perl/t/pending-expire.t	    \
	perl/t/webauth.t perl/t/webkdc.t perl/t/weblogin.t perl/typemap

AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = .gitignore HACKING LICENSE autogen conf/README		   \
	conf/debian/webauth.conf conf/debian/webauth.load		   \
	conf/debian/webauthldap.conf conf/debian/webauthldap.load	   \
	conf/debian/webkdc.conf conf/debian/webkdc.load			   \
	conf/sample-webauth.conf conf/stanford-ldap.conf		   \
	conf/stanford-webauth.conf conf/token.acl docs/design-pwchange	   \
	docs/install-spnego docs/install-stanford docs/install-webkdc	   \
	docs/mod_webauth.html.en docs/mod_webauth.xml			   \
	docs/mod_webauthldap.html.en docs/mod_webauthldap.xml		   \
	docs/mod_webkdc.html.en docs/mod_webkdc.xml docs/protocol.html	   \
	docs/protocol.txt docs/protocol.xml docs/test-plan docs/userauth   \
	docs/weblogin-config docs/weblogin-cookies docs/weblogin-flow	   \
	lib/libwebauth.map lib/libwebauth.pc.in lib/libwebauth.sym	   \
	lib/mkheader lib/webauth.h.in perl/README perl/MANIFEST		   \
	perl/MANIFEST.SKIP tests/TESTS tests/data/README tests/mod_webauth \
	tests/tap/libtap.sh tests/tools/wa_keyring-t tests/util/xmalloc-t  \
	tools/wa_keyring.pod tools/weblogin-passcheck			   \
	weblogin/images/confirm.xcf weblogin/images/error.xcf		   \
	weblogin/images/help.xcf weblogin/images/login.xcf		   \
	weblogin/images/logout.xcf $(PERL_FILES)

noinst_LTLIBRARIES = portable/libportable.la
portable_libportable_la_SOURCES = portable/dummy.c portable/krb5-extra.c \
        portable/krb5.h portable/macros.h portable/stdbool.h		 \
        portable/system.h
portable_libportable_la_CPPFLAGS = $(KRB5_CPPFLAGS)
portable_libportable_la_LIBADD = $(LTLIBOBJS)
noinst_LIBRARIES = util/libutil.a
util_libutil_a_SOURCES = util/concat.c util/concat.h util/macros.h \
        util/messages.c util/messages.h util/xmalloc.c util/xmalloc.h

if HAVE_LD_VERSION_SCRIPT
    VERSION_LDFLAGS = -Wl,--version-script=${srcdir}/lib/libwebauth.map
else
    VERSION_LDFLAGS = -export-symbols ${srcdir}/lib/libwebauth.sym
endif

lib_LTLIBRARIES = lib/libwebauth.la
nodist_include_HEADERS = lib/webauth.h
lib_libwebauth_la_SOURCES = lib/attrs.c lib/base64.c lib/key.c lib/krb5.c \
	lib/misc.c lib/random.c lib/token.c lib/webauth.h
EXTRA_lib_libwebauth_la_SOURCES = lib/krb5-heimdal.c lib/krb5-mit.c
lib_libwebauth_la_CPPFLAGS = $(KRB5_CPPFLAGS) $(CRYPTO_CPPFLAGS)
lib_libwebauth_la_LDFLAGS = -version-info 4:0:0 $(VERSION_LDFLAGS) \
	$(KRB5_LDFLAGS) $(CRYPTO_LDFLAGS)
lib_libwebauth_la_LIBADD = portable/libportable.la $(KRB5_LIBS) -lcom_err \
	$(CRYPTO_LIBS)

apachedir = $(libexecdir)/apache2/modules
apache_LTLIBRARIES =
if BUILD_WEBAUTH
    apache_LTLIBRARIES += modules/webauth/mod_webauth.la
endif
if BUILD_WEBAUTHLDAP
    apache_LTLIBRARIES += modules/ldap/mod_webauthldap.la
endif
if BUILD_WEBKDC
    apache_LTLIBRARIES += modules/webkdc/mod_webkdc.la
endif

modules_ldap_mod_webauthldap_la_SOURCES = modules/ldap/mod_webauthldap.c \
	modules/ldap/mod_webauthldap.h
modules_ldap_mod_webauthldap_la_CPPFLAGS = $(APACHE_CPPFLAGS) \
	$(KRB5_CPPFLAGS) $(LDAP_CPPFLAGS)
modules_ldap_mod_webauthldap_la_LDFLAGS = -module -shared -avoid-version \
	$(APACHE_LDFLAGS) $(KRB5_LDFLAGS) $(LDAP_LDFLAGS)
modules_ldap_mod_webauthldap_la_LIBADD = portable/libportable.la \
	$(APACHE_LIBS) $(KRB5_LIBS) $(LDAP_LIBS)
modules_webauth_mod_webauth_la_SOURCES = modules/webauth/krb5.c \
	modules/webauth/mod_webauth.c modules/webauth/mod_webauth.h \
	modules/webauth/util.c modules/webauth/webkdc.c
modules_webauth_mod_webauth_la_CPPFLAGS = $(APACHE_CPPFLAGS) $(CURL_CPPFLAGS)
modules_webauth_mod_webauth_la_LDFLAGS = -module -shared -avoid-version \
	$(APACHE_LDFLAGS) $(CURL_LDFLAGS)
modules_webauth_mod_webauth_la_LIBADD = lib/libwebauth.la $(APACHE_LIBS) \
	$(CURL_LIBS)
modules_webkdc_mod_webkdc_la_SOURCES = modules/webkdc/acl.c \
	modules/webkdc/mod_webkdc.c modules/webkdc/mod_webkdc.h \
	modules/webkdc/util.c
modules_webkdc_mod_webkdc_la_CPPFLAGS = $(APACHE_CPPFLAGS)
modules_webkdc_mod_webkdc_la_LDFLAGS = -module -shared -avoid-version \
	$(APACHE_LDFLAGS)
modules_webkdc_mod_webkdc_la_LIBADD = lib/libwebauth.la $(APACHE_LIBS)

bin_PROGRAMS = tools/wa_keyring
tools_wa_keyring_LDADD = lib/libwebauth.la util/libutil.a \
	portable/libportable.la $(CRYPTO_LIBS)
dist_man_MANS = tools/wa_keyring.1

pkgconfigdir = $(libdir)/pkgconfig
nodist_pkgconfig_DATA = lib/libwebauth.pc

lib/libwebauth.pc: $(srcdir)/lib/libwebauth.pc.in
	sed -e 's![@]prefix[@]!$(prefix)!g' \
	    -e 's![@]exec_prefix[@]!$(exec_prefix)!g' \
	    -e 's![@]includedir[@]!$(includedir)!g' \
	    -e 's![@]libdir[@]!$(libdir)!g' \
	    -e 's![@]PACKAGE_VERSION[@]!$(PACKAGE_VERSION)!g' \
	    -e 's![@]KRB5_LDFLAGS[@]!$(KRB5_LDFLAGS)!g' \
	    -e 's![@]KRB5_LIBS[@]!$(KRB5_LIBS)!g' \
	    -e 's![@]CRYPTO_LDFLAGS[@]!$(CRYPTO_LDFLAGS)!g' \
	    -e 's![@]CRYPTO_LIBS[@]!$(CRYPTO_LIBS)!g' \
	    $(srcdir)/lib/libwebauth.pc.in > $@

# Only install the WebLogin script and configuration if configured to build
# and install mod_webkdc.  These don't have to go together, but that's the
# strongly recommended configuration and this is simpler than adding yet
# another configure option.
if BUILD_WEBKDC
    weblogindir = $(datadir)/weblogin
    imagedir    = $(weblogindir)/generic/images
    templatedir = $(weblogindir)/generic/templates
    dist_weblogin_DATA = weblogin/login.fcgi weblogin/logout.fcgi	\
	weblogin/pwchange.fcgi
    dist_image_DATA = weblogin/images/confirm.png weblogin/images/error.png \
	weblogin/images/help.png weblogin/images/login.png		    \
	weblogin/images/logout.png
    dist_template_DATA = weblogin/templates/confirm.tmpl		\
	weblogin/templates/error.tmpl weblogin/templates/help.html	\
	weblogin/templates/login.tmpl weblogin/templates/logout.tmpl	\
	weblogin/templates/pwchange.tmpl
endif

# Build and install the Perl bindings if desired.
BINDINGS =
BINDINGS_INSTALL =
if BUILD_PERL
    BINDINGS += perl/WebAuth.o
    BINDINGS_INSTALL += install-data-local-perl
endif

# Suppress some warnings for Perl code because the auto-generated code
# doesn't pass them.
if GCC
    PERL_WARNINGS = -Wno-write-strings -Wno-nested-externs \
	-Wno-strict-prototypes -Wno-redundant-decls -Wno-shadow \
	-Wno-unused-variable
else
    PERL_WARNINGS =
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

# Run the hooks for bindings and Apache modules.
all-local: $(BINDINGS) $(MODULES)
install-exec-local: $(BINDINGS_INSTALL)

CLEANFILES = lib/libwebauth.pc
DISTCLEANFILES = perl/Makefile lib/webauth.h
MAINTAINERCLEANFILES = Makefile.in aclocal.m4 config.h.in config.h.in~ \
	configure docs/protocol.html docs/protocol.txt m4/libtool.m4 \
	m4/ltoptions.m4 m4/ltsugar.m4 m4/ltversion.m4 m4/lt~obsolete.m4 \
	tools/wa_keyring.1

# Also run make clean in the perl directory if needed and clean up the module
# directories.
clean-local:
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
# without optimization turned on.  Desirable warnings that can't be turned
# on due to other problems:
#
#     -Wconversion	http://bugs.debian.org/488884 (htons warnings)
#
# Last checked against gcc 4.6.1 (2011-05-04).
WARNINGS = -g -O -Wall -Wextra -Wendif-labels -Wformat=2 -Winit-self	\
	-Wswitch-enum -Wdeclaration-after-statement -Wshadow		\
	-Wpointer-arith -Wbad-function-cast -Wwrite-strings		\
	-Wjump-misses-init -Wlogical-op -Wstrict-prototypes		\
	-Wmissing-prototypes -Wredundant-decls -Wnested-externs -Werror

warnings:
	$(MAKE) V=0 CFLAGS='$(WARNINGS)'
	$(MAKE) V=0 CFLAGS='$(WARNINGS)' $(check_PROGRAMS)

# The bits below are for the test suite, not for the main package.
check_PROGRAMS = tests/runtests tests/lib/attrs-t tests/lib/base64-t	   \
	tests/lib/hex-t tests/lib/key-t tests/lib/krb5-t		   \
	tests/lib/krb5-tgt-t tests/lib/random-t tests/lib/token-t	   \
	tests/portable/asprintf-t tests/portable/mkstemp-t		   \
	tests/portable/snprintf-t tests/portable/strlcat-t		   \
	tests/portable/strlcpy-t tests/util/concat-t tests/util/messages-t \
	tests/util/xmalloc
tests_runtests_CPPFLAGS = -DSOURCE='"$(abs_top_srcdir)/tests"' \
	-DBUILD='"$(abs_top_builddir)/tests"'
check_LIBRARIES = tests/tap/libtap.a
tests_tap_libtap_a_CPPFLAGS = -I$(abs_top_srcdir)/tests $(KRB5_CPPFLAGS)
tests_tap_libtap_a_SOURCES = tests/tap/basic.c tests/tap/basic.h	\
	tests/tap/kerberos.c tests/tap/kerberos.h tests/tap/messages.c	\
	tests/tap/messages.h tests/tap/process.c tests/tap/process.h

# All of the test programs.
tests_lib_attrs_t_LDADD = tests/tap/libtap.a lib/libwebauth.la
tests_lib_base64_t_LDADD = tests/tap/libtap.a lib/libwebauth.la
tests_lib_hex_t_LDADD = tests/tap/libtap.a lib/libwebauth.la
tests_lib_key_t_LDADD = tests/tap/libtap.a lib/libwebauth.la
tests_lib_krb5_t_LDADD = tests/tap/libtap.a lib/libwebauth.la
tests_lib_krb5_tgt_t_LDFLAGS = $(KRB5_LDFLAGS)
tests_lib_krb5_tgt_t_LDADD = tests/tap/libtap.a lib/libwebauth.la \
	util/libutil.a portable/libportable.la $(KRB5_LIBS)
tests_lib_random_t_LDADD = tests/tap/libtap.a lib/libwebauth.la
tests_lib_token_t_LDADD = tests/tap/libtap.a lib/libwebauth.la
tests_portable_asprintf_t_SOURCES = tests/portable/asprintf-t.c \
	tests/portable/asprintf.c
tests_portable_asprintf_t_LDADD = tests/tap/libtap.a portable/libportable.la
tests_portable_mkstemp_t_SOURCES = tests/portable/mkstemp-t.c \
	tests/portable/mkstemp.c
tests_portable_mkstemp_t_LDADD = tests/tap/libtap.a portable/libportable.la
tests_portable_snprintf_t_SOURCES = tests/portable/snprintf-t.c \
	tests/portable/snprintf.c
tests_portable_snprintf_t_LDADD = tests/tap/libtap.a portable/libportable.la
tests_portable_strlcat_t_SOURCES = tests/portable/strlcat-t.c \
	tests/portable/strlcat.c
tests_portable_strlcat_t_LDADD = tests/tap/libtap.a portable/libportable.la
tests_portable_strlcpy_t_SOURCES = tests/portable/strlcpy-t.c \
	tests/portable/strlcpy.c
tests_portable_strlcpy_t_LDADD = tests/tap/libtap.a portable/libportable.la
tests_util_concat_t_LDADD = tests/tap/libtap.a util/libutil.a \
	portable/libportable.la
tests_util_messages_t_LDADD = tests/tap/libtap.a util/libutil.a \
	portable/libportable.la
tests_util_xmalloc_LDADD = util/libutil.a portable/libportable.la

check-local: $(check_PROGRAMS) $(srcdir)/tests/TESTS
	cd tests && ./runtests $(abs_top_srcdir)/tests/TESTS
	@set -e; if [ -f perl/Makefile ] ; then \
	    echo '' ; \
	    cd perl && LD_LIBRARY_PATH=$(abs_top_builddir)/lib/.libs \
		$(MAKE) test ; \
	fi
