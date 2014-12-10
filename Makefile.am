# Automake makefile for WebAuth.
#
# Written by Russ Allbery <eagle@eyrie.org>
# Copyright 2009, 2010, 2011, 2012, 2013, 2014
#     The Board of Trustees of the Leland Stanford Junior University
#
# See LICENSE for licensing terms.

# These variables exist only for the use of the Debian packaging and similar
# situations and aren't normally set.  We want to honor them if they're set
# in the environment, as well as via make arguments.
#
# WEBAUTH_PERL_FLAGS are additional flags to pass to Makefile.PL when
# building the Makefile.
WEBAUTH_PERL_FLAGS ?=

# These files are needed for the Perl module builds.  They're listed here to
# be added to EXTRA_DIST and so that they can be copied over properly for
# builddir != srcdir builds.
PERL_FILES = perl/Build.PL perl/MANIFEST perl/MANIFEST.SKIP		    \
	perl/lib/WebAuth.pm perl/lib/WebAuth.xs				    \
	perl/lib/WebAuth/Exception.pm perl/lib/WebAuth/Key.pm		    \
	perl/lib/WebAuth/Keyring.pm perl/lib/WebAuth/KeyringEntry.pod	    \
	perl/lib/WebAuth/Krb5.pm perl/lib/WebAuth/Tests.pm		    \
	perl/lib/WebAuth/Token.pm perl/lib/WebAuth/Token/App.pm		    \
	perl/lib/WebAuth/Token/Cred.pm perl/lib/WebAuth/Token/Error.pm	    \
	perl/lib/WebAuth/Token/Id.pm perl/lib/WebAuth/Token/Login.pm	    \
	perl/lib/WebAuth/Token/Proxy.pm perl/lib/WebAuth/Token/Request.pm   \
	perl/lib/WebAuth/Token/WebKDCFactor.pm				    \
	perl/lib/WebAuth/Token/WebKDCProxy.pm				    \
	perl/lib/WebAuth/Token/WebKDCService.pm perl/lib/WebKDC.pm	    \
	perl/lib/WebKDC/Config.pm perl/lib/WebKDC/WebKDCException.pm	    \
	perl/lib/WebKDC/WebRequest.pm perl/lib/WebKDC/WebResponse.pm	    \
	perl/lib/WebKDC/XmlDoc.pm perl/lib/WebKDC/XmlElement.pm		    \
	perl/lib/WebLogin.pm perl/t/TODO perl/t/cookies/cookies.t	    \
	perl/t/cookies/factor-token.t perl/t/data/README		    \
	perl/t/data/cmd-password perl/t/data/conf-password		    \
	perl/t/data/pages/confirm/device-expiring			    \
	perl/t/data/pages/confirm/expired-password			    \
	perl/t/data/pages/confirm/no-pwexpiration			    \
	perl/t/data/pages/confirm/pending-pwchange			    \
	perl/t/data/pages/confirm/public-computer			    \
	perl/t/data/pages/confirm/remote-user-checkbox			    \
	perl/t/data/pages/error/return-url				    \
	perl/t/data/pages/error/stale-token				    \
	perl/t/data/pages/error/unrecoverable				    \
	perl/t/data/pages/error/unrecoverable-webauth			    \
	perl/t/data/pages/login/empty-username				    \
	perl/t/data/pages/login/failed perl/t/data/pages/login/forced	    \
	perl/t/data/pages/login/forced-no-wpt				    \
	perl/t/data/pages/login/no-password				    \
	perl/t/data/pages/login/no-username				    \
	perl/t/data/pages/login/no-username-password			    \
	perl/t/data/pages/login/pass-required				    \
	perl/t/data/pages/login/pass-required-no-remuser		    \
	perl/t/data/pages/login/pass-required-not-error			    \
	perl/t/data/pages/login/rejected				    \
	perl/t/data/pages/login/remote-user perl/t/data/pages/pwchange/bare \
	perl/t/data/pages/pwchange/cpt perl/t/data/perl.conf		    \
	perl/t/data/templates/confirm.tmpl perl/t/data/templates/error.tmpl \
	perl/t/data/templates/login.tmpl perl/t/data/templates/logout.tmpl  \
	perl/t/data/templates/pwchange.tmpl perl/t/data/token.acl	    \
	perl/t/data/webkdc.conf perl/t/docs/pod-spelling.t		    \
	perl/t/docs/pod.t perl/t/kerberos/changepw.t perl/t/kerberos/krb5.t \
	perl/t/kerberos/webkdc.t perl/t/kerberos/weblogin.t		    \
	perl/t/keyring/keyring.t perl/t/keyring/keys.t			    \
	perl/t/keyring/token-decode.t perl/t/keyring/token-encode.t	    \
	perl/t/keyring/token-errs.t perl/t/keyring/token-rights.t	    \
	perl/t/lib/Util.pm perl/t/misc/config.t perl/t/misc/exception.t	    \
	perl/t/misc/webkdcexception.t perl/t/misc/weblogin.t		    \
	perl/t/pages/confirmation.t perl/t/pages/error.t		    \
	perl/t/pages/global-errors.t perl/t/pages/login.t		    \
	perl/t/pages/pwchange.t perl/t/style/minimum-version.t		    \
	perl/t/style/strict.t perl/t/token/misc.t			    \
	perl/t/webkdc/web-request.t perl/t/webkdc/web-response.t	    \
	perl/t/webkdc/xml.t perl/typemap

# Directories that have to be created in builddir != srcdir builds before
# copying PERL_FILES over.
PERL_DIRECTORIES = perl/lib perl/lib/WebAuth perl/lib/WebAuth/Token	 \
	perl/lib/WebKDC perl/t/cookies perl/t/data perl/t/data/pages	 \
	perl/t/data/pages/confirm perl/t/data/pages/error		 \
	perl/t/data/pages/login perl/t/data/pages/pwchange		 \
	perl/t/data/templates perl/t/docs perl/t/kerberos perl/t/keyring \
	perl/t/lib perl/t/misc perl/t/pages perl/t/style perl/t/token	 \
	perl/t/webkdc

ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = .gitignore HACKING LICENSE autogen conf/README		    \
	conf/debian/webauth.conf conf/debian/webauth.load		    \
	conf/debian/webauthldap.conf conf/debian/webauthldap.load	    \
	conf/debian/webkdc.conf conf/debian/webkdc.load			    \
	conf/sample-webauth.conf conf/stanford-ldap.conf		    \
	conf/stanford-webauth.conf conf/token.acl docs/design-pwchange	    \
	docs/diagrams/weblogin-flow.dia docs/diagrams/weblogin-flow.png	    \
	docs/diagrams/weblogin-flow.svg docs/install-multifactor	    \
	docs/install-spnego docs/install-stanford docs/install-webkdc	    \
	docs/mod_webauth.html.en docs/mod_webauth.xml			    \
	docs/mod_webauthldap.html.en docs/mod_webauthldap.xml		    \
	docs/mod_webkdc.html.en docs/mod_webkdc.xml docs/protocol.html	    \
	docs/protocol.txt docs/protocol.xml				    \
	docs/scripts/clean-apache-manual docs/test-plan docs/userauth	    \
	docs/weblogin-config docs/weblogin-cookies docs/weblogin-flow	    \
	docs/weblogin-testing include/mkheader include/webauth/defines.h.in \
	lib/encoding-rules lib/internal.h lib/libwebauth.map		    \
	lib/libwebauth.pc.in lib/libwebauth.sym perl/MANIFEST		    \
	perl/MANIFEST.SKIP tests/TESTS tests/config/README		    \
	tests/data/cmd-password tests/data/cmd-webkdc tests/data/creds	    \
	tests/data/generate-krb5-conf tests/data/id.acl tests/data/json	    \
	tests/data/keyring tests/data/make-krb5-cred tests/data/make-tokens \
	tests/data/perl.conf tests/data/perlcriticrc tests/data/perltidyrc  \
	tests/data/service-token tests/data/tokens tests/data/tokens.conf   \
	tests/data/valgrind.supp tests/data/xml tests/docs/pod-spelling-t   \
	tests/docs/pod-t tests/mod_webauth tests/perl/critic-t		    \
	tests/perl/minimum-version-t tests/perl/module-version-t	    \
	tests/perl/strict-t tests/tap/libtap.sh tests/tap/perl/Test/RRA.pm  \
	tests/tap/perl/Test/RRA/Automake.pm				    \
	tests/tap/perl/Test/RRA/Config.pm tests/tools/wa_keyring-t	    \
	tests/util/xmalloc-t tools/wa_keyring.pod tools/weblogin-passcheck  \
	weblogin/images/confirm.xcf weblogin/images/error.xcf		    \
	weblogin/images/help.xcf weblogin/images/login.xcf		    \
	weblogin/images/logout.xcf $(PERL_FILES)

# WebAuth library include files are in include.  Remember, when overriding
# CPPFLAGS for specific build objects, to include AM_CPPFLAGS.
AM_CPPFLAGS = -I$(srcdir)/include -I$(builddir)/include

noinst_LTLIBRARIES = portable/libportable.la
portable_libportable_la_SOURCES = portable/apache.h portable/apr.h	\
        portable/dummy.c portable/krb5-extra.c portable/krb5.h		\
        portable/macros.h portable/stdbool.h portable/system.h
portable_libportable_la_CPPFLAGS = $(AM_CPPFLAGS) $(KRB5_CPPFLAGS)
portable_libportable_la_LIBADD = $(LTLIBOBJS)
noinst_LIBRARIES = util/libutil.a
util_libutil_a_SOURCES = util/macros.h util/messages.c util/messages.h	\
        util/xmalloc.c util/xmalloc.h

if HAVE_LD_VERSION_SCRIPT
    VERSION_LDFLAGS = -Wl,--version-script=${srcdir}/lib/libwebauth.map
else
    VERSION_LDFLAGS = -export-symbols ${srcdir}/lib/libwebauth.sym
endif

lib_LTLIBRARIES = lib/libwebauth.la
webauthincludedir = $(includedir)/webauth
webauthinclude_HEADERS = include/webauth/basic.h include/webauth/factors.h \
	include/webauth/keys.h include/webauth/krb5.h			   \
	include/webauth/tokens.h include/webauth/util.h			   \
	include/webauth/was.h include/webauth/webkdc.h
nodist_webauthinclude_HEADERS = include/webauth/defines.h
lib_libwebauth_la_SOURCES = lib/apr-buffer.c lib/attr-decode.c		    \
	lib/attr-encode.c lib/context.c lib/errors.c lib/factors.c	    \
	lib/file-io.c lib/hex.c lib/internal.h lib/keyring.c lib/keys.c	    \
	lib/krb5.c lib/rules-cache.c lib/rules-keyring.c lib/rules-krb5.c   \
	lib/rules-tokens.c lib/token-crypto.c lib/token-encode.c	    \
	lib/token-merge.c lib/userinfo.c lib/userinfo-json.c		    \
	lib/userinfo-remctl.c lib/userinfo-xml.c lib/util.c lib/was-cache.c \
	lib/webkdc-config.c lib/webkdc-logging.c lib/webkdc-login.c	    \
	lib/xml.c
EXTRA_lib_libwebauth_la_SOURCES = lib/krb5-heimdal.c lib/krb5-mit.c
lib_libwebauth_la_CPPFLAGS = $(AM_CPPFLAGS) $(APR_CPPFLAGS)		\
	$(APRUTIL_CPPFLAGS) $(JANSSON_CPPFLAGS) $(REMCTL_CPPFLAGS)	\
	$(KRB5_CPPFLAGS) $(CRYPTO_CPPFLAGS)
lib_libwebauth_la_LDFLAGS = -version-info 12:0:0 $(VERSION_LDFLAGS)	\
	$(APR_LDFLAGS) $(APRUTIL_LDFLAGS) $(JANSSON_LDFLAGS)		\
	$(REMCTL_LDFLAGS) $(KRB5_LDFLAGS) $(CRYPTO_LDFLAGS)
lib_libwebauth_la_LIBADD = portable/libportable.la $(APR_LIBS)		\
	$(APRUTIL_LIBS) $(JANSSON_LIBS) $(REMCTL_LIBS) $(KRB5_LIBS)	\
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

modules_ldap_mod_webauthldap_la_SOURCES = modules/ldap/config.c		\
	modules/ldap/mod_webauthldap.c modules/ldap/mod_webauthldap.h
modules_ldap_mod_webauthldap_la_CPPFLAGS = $(AM_CPPFLAGS) $(APACHE_CPPFLAGS) \
	$(KRB5_CPPFLAGS) $(LDAP_CPPFLAGS)
modules_ldap_mod_webauthldap_la_LDFLAGS = -module -shared -avoid-version \
	$(APACHE_LDFLAGS) $(KRB5_LDFLAGS) $(LDAP_LDFLAGS)
modules_ldap_mod_webauthldap_la_LIBADD = portable/libportable.la \
	$(APACHE_LIBS) $(KRB5_LIBS) $(LDAP_LIBS)
modules_webauth_mod_webauth_la_SOURCES = modules/webauth/config.c	\
	modules/webauth/krb5.c modules/webauth/mod_webauth.c		\
	modules/webauth/mod_webauth.h modules/webauth/util.c		\
	modules/webauth/webkdc.c
modules_webauth_mod_webauth_la_CPPFLAGS = $(AM_CPPFLAGS) $(APACHE_CPPFLAGS) \
	$(CURL_CPPFLAGS)
modules_webauth_mod_webauth_la_LDFLAGS = -module -shared -avoid-version \
	$(APACHE_LDFLAGS) $(CURL_LDFLAGS)
modules_webauth_mod_webauth_la_LIBADD = lib/libwebauth.la $(APACHE_LIBS) \
	$(CURL_LIBS) $(KEYUTILS_LIBS)
modules_webkdc_mod_webkdc_la_SOURCES = modules/webkdc/acl.c	\
	modules/webkdc/config.c modules/webkdc/logging.c	\
	modules/webkdc/mod_webkdc.c modules/webkdc/mod_webkdc.h	\
	modules/webkdc/util.c
modules_webkdc_mod_webkdc_la_CPPFLAGS = $(AM_CPPFLAGS) $(APACHE_CPPFLAGS)
modules_webkdc_mod_webkdc_la_LDFLAGS = -module -shared -avoid-version \
	$(APACHE_LDFLAGS)
modules_webkdc_mod_webkdc_la_LIBADD = lib/libwebauth.la $(APACHE_LIBS)

bin_PROGRAMS = tools/wa_keyring
tools_wa_keyring_CPPFLAGS = $(AM_CPPFLAGS) $(APR_CPPFLAGS) $(CRYPTO_CPPFLAGS)
tools_wa_keyring_LDFLAGS = $(CRYPTO_LDFLAGS)
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
    dist_weblogin_SCRIPTS = weblogin/login.fcgi weblogin/logout.fcgi	\
	weblogin/pwchange.fcgi
    dist_image_DATA = weblogin/images/confirm.png weblogin/images/error.png \
	weblogin/images/help.png weblogin/images/login.png		    \
	weblogin/images/logout.png
    dist_template_DATA = weblogin/templates/confirm.tmpl		\
	weblogin/templates/error.tmpl weblogin/templates/help.html	\
	weblogin/templates/login.tmpl weblogin/templates/logout.tmpl	\
	weblogin/templates/multifactor.tmpl				\
	weblogin/templates/pwchange.tmpl
endif

# Build and install the Perl bindings if desired.
BINDINGS         =
BINDINGS_CHECK   =
BINDINGS_INSTALL =
if BUILD_PERL
    BINDINGS         += perl/lib/WebAuth.o
    BINDINGS_CHECK   += perl/t/data/keyring perl/t/data/tokens.conf
    BINDINGS_INSTALL += install-data-local-perl
endif

# CFLAGS and LDFLAGS to pass to the Perl build.
PERL_CFLAGS = -I$(abs_top_builddir) -I$(abs_top_srcdir) \
	-I$(abs_top_srcdir)/include $(CPPFLAGS) $(APR_CPPFLAGS)
PERL_LDFLAGS_FULL = -L$(abs_top_builddir)/lib/.libs $(PERL_LDFLAGS) $(LDFLAGS)

# The following section sets up the Perl module build properly.  Most of the
# complexity is here to handle building outside of the source directory, in
# which case we need to copy various files from the source directory and make
# sure they're up to date since Perl can't handle VPATH builds.
perl/lib/WebAuth.o: $(srcdir)/perl/Build.PL $(srcdir)/perl/lib/WebAuth.pm \
		$(srcdir)/perl/lib/WebAuth.xs $(srcdir)/perl/typemap	  \
		lib/libwebauth.la $(BINDINGS_CHECK)
	set -e; if [ x"$(builddir)" != x"$(srcdir)" ] ; then		\
	    for d in $(PERL_DIRECTORIES) ; do				\
		[ -d "$(builddir)/$$d" ] || mkdir "$(builddir)/$$d" ;	\
	    done ;							\
	    for f in $(PERL_FILES) ; do					\
		cp "$(srcdir)/$$f" "$(builddir)/$$f" ;			\
	    done							\
	fi
	cp -R $(srcdir)/tests/tap/perl/* perl/t/lib/
	rm -f perl/lib/WebAuth.o
	cd perl && perl Build.PL					\
	    --config lddlflags='$(PERL_LDFLAGS_FULL)'			\
	    --config optimize='$(CFLAGS) $(PERL_CFLAGS_EXTRA)'		\
	    --extra-compiler-flags '$(PERL_CFLAGS)'			\
	    --extra-linker-flags '-lwebauth $(DEPEND_LIBS) $(LIBS)'	\
	    $(WEBAUTH_PERL_FLAGS)
	cd perl && ./Build

install-data-local-perl: perl/lib/WebAuth.o
	cd perl && ./Build install --destdir '$(DESTDIR)'

# Run the hooks for bindings and Apache modules.
all-local: $(BINDINGS) $(MODULES)
install-exec-local: $(BINDINGS_INSTALL)

CLEANFILES = lib/libwebauth.pc perl/t/data/keyring perl/t/data/tokens.conf \
	perl/t/lib/Test/RRA.pm perl/t/lib/Test/RRA/Automake.pm		   \
	perl/t/lib/Test/RRA/Config.pm
DISTCLEANFILES = config.h.in~ include/webauth/defines.h
MAINTAINERCLEANFILES = Makefile.in aclocal.m4 config.h.in configure	\
	docs/protocol.html docs/protocol.txt lib/rules-cache.c		\
	lib/rules-keyring.c lib/rules-krb5.c lib/rules-tokens.c		\
	m4/libtool.m4 m4/ltoptions.m4 m4/ltsugar.m4 m4/ltversion.m4	\
	m4/lt~obsolete.m4 tools/wa_keyring.1

# Clean up the results of running the test suite under gcov.  Also run make
# clean in the perl directory if needed.
clean-local:
	rm -f */*.gcda */*.gcno */*/*.gcda */*/*.gcno
	set -e; if [ -f "perl/Build" ] ; then	\
	    cd perl && ./Build realclean ;	\
	    rm -rf t/data/tokens ;		\
	fi

# Remove the Perl files we copied over if srcdir != builddir.
distclean-local:
	rm -rf autom4te.cache
	set -e; if [ x"$(builddir)" != x"$(srcdir)" ] ; then	\
	    for f in $(PERL_FILES) ; do				\
		rm -f "$(builddir)/$$f" ;			\
	    done ;						\
	fi

# A set of flags for warnings.  Add -O because gcc won't find some warnings
# without optimization turned on.  Desirable warnings that can't be turned
# on due to other problems:
#
#     -Wconversion      http://bugs.debian.org/488884 (htons warnings)
#
# Last checked against gcc 4.8.2 (2014-04-12).  -D_FORTIFY_SOURCE=2 enables
# warn_unused_result attribute markings on glibc functions on Linux, which
# catches a few more issues.
WARNINGS = -g -O -fstrict-overflow -fstrict-aliasing -D_FORTIFY_SOURCE=2    \
	-Wall -Wextra -Wendif-labels -Wformat=2 -Winit-self -Wswitch-enum   \
	-Wstrict-overflow=5 -Wfloat-equal -Wdeclaration-after-statement	    \
	-Wshadow -Wpointer-arith -Wbad-function-cast -Wcast-align	    \
	-Wwrite-strings -Wjump-misses-init -Wlogical-op -Wstrict-prototypes \
	-Wold-style-definition -Wmissing-prototypes -Wnormalized=nfc	    \
	-Wpacked -Wredundant-decls -Wnested-externs -Winline -Wvla -Werror

# Suppress some warnings for Perl code because the auto-generated code
# doesn't pass them.  -Wno-strict-prototypes and -Wno-missing-prototypes are
# required for the ExtUtils::CBuilder probe.
PERL_WARNINGS = -Wno-nested-externs -Wno-redundant-decls		\
    -Wno-unused-variable -Wno-strict-prototypes -Wno-missing-prototypes	\
    -Wno-old-style-definition

warnings:
	$(MAKE) V=0 CFLAGS='$(WARNINGS)'		\
	    KRB5_CPPFLAGS='$(KRB5_CPPFLAGS_GCC)'	\
	    PERL_CFLAGS_EXTRA='$(PERL_WARNINGS)'
	$(MAKE) V=0 CFLAGS='$(WARNINGS)' \
	    KRB5_CPPFLAGS='$(KRB5_CPPFLAGS_GCC)' $(check_PROGRAMS)

# The bits below are for the test suite, not for the main package.
check_PROGRAMS = tests/runtests tests/lib/apr-buffer-t tests/lib/errors-t  \
	tests/lib/factors-t tests/lib/hex-t tests/lib/interval-t	   \
	tests/lib/keyring-t tests/lib/keys-t tests/lib/krb5-t		   \
	tests/lib/krb5-cred-t tests/lib/krb5-remctl-t tests/lib/krb5-tgt-t \
	tests/lib/userinfo-t tests/lib/token-crypto-t			   \
	tests/lib/token-decode-t tests/lib/token-encode-t		   \
	tests/lib/token-merge-t tests/lib/was-cache-t			   \
	tests/lib/webkdc-krb-t tests/lib/webkdc-login-t			   \
	tests/lib/webkdc-mf-t tests/portable/asprintf-t			   \
	tests/portable/mkstemp-t tests/portable/setenv-t		   \
	tests/portable/snprintf-t tests/portable/strlcat-t		   \
	tests/portable/strlcpy-t tests/portable/strndup-t		   \
	tests/util/messages-t tests/util/xmalloc
tests_runtests_CPPFLAGS = -DSOURCE='"$(abs_top_srcdir)/tests"' \
	-DBUILD='"$(abs_top_builddir)/tests"'
check_LIBRARIES = tests/tap/libtap.a
tests_tap_libtap_a_CPPFLAGS = -DPATH_REMCTLD='"$(PATH_REMCTLD)"' \
	$(KRB5_CPPFLAGS) $(APR_CPPFLAGS) $(AM_CPPFLAGS)
tests_tap_libtap_a_SOURCES = tests/tap/basic.c tests/tap/basic.h	\
	tests/tap/kerberos.c tests/tap/kerberos.h tests/tap/messages.c	\
	tests/tap/macros.h tests/tap/messages.h tests/tap/process.c	\
	tests/tap/process.h tests/tap/remctl.c tests/tap/remctl.h	\
	tests/tap/string.c tests/tap/string.h tests/tap/webauth.c	\
	tests/tap/webauth.h

# All of the test programs.
tests_lib_apr_buffer_t_SOURCES = lib/apr-buffer.c tests/lib/apr-buffer-t.c
tests_lib_apr_buffer_t_CPPFLAGS = $(APR_CPPFLAGS) $(AM_CPPFLAGS)
tests_lib_apr_buffer_t_LDADD = tests/tap/libtap.a portable/libportable.la \
	$(APR_LIBS)
tests_lib_errors_t_SOURCES = lib/context.c lib/errors.c tests/lib/errors-t.c
tests_lib_errors_t_CPPFLAGS = $(APR_CPPFLAGS) $(AM_CPPFLAGS)
tests_lib_errors_t_LDADD = tests/tap/libtap.a portable/libportable.la \
	$(APR_LIBS)
tests_lib_factors_t_CPPFLAGS = $(APR_CPPFLAGS) $(AM_CPPFLAGS)
tests_lib_factors_t_LDADD = tests/tap/libtap.a lib/libwebauth.la \
	portable/libportable.la $(APR_LIBS)
tests_lib_hex_t_SOURCES = lib/hex.c tests/lib/hex-t.c
tests_lib_hex_t_CPPFLAGS = $(APR_CPPFLAGS) $(AM_CPPFLAGS)
tests_lib_hex_t_LDADD = tests/tap/libtap.a portable/libportable.la
tests_lib_interval_t_LDADD = tests/tap/libtap.a lib/libwebauth.la \
	portable/libportable.la
tests_lib_keyring_t_CPPFLAGS = $(APR_CPPFLAGS) $(AM_CPPFLAGS)
tests_lib_keyring_t_LDADD = tests/tap/libtap.a lib/libwebauth.la \
	portable/libportable.la
tests_lib_keys_t_LDADD = tests/tap/libtap.a lib/libwebauth.la \
	portable/libportable.la
tests_lib_krb5_t_CPPFLAGS = $(KRB5_CPPFLAGS) $(AM_CPPFLAGS)
tests_lib_krb5_t_LDFLAGS = $(KRB5_LDFLAGS)
tests_lib_krb5_t_LDADD = tests/tap/libtap.a lib/libwebauth.la \
	portable/libportable.la $(KRB5_LIBS)
tests_lib_krb5_cred_t_CPPFLAGS = $(KRB5_CPPFLAGS) $(AM_CPPFLAGS)
tests_lib_krb5_cred_t_LDFLAGS = $(KRB5_LDFLAGS)
tests_lib_krb5_cred_t_LDADD = tests/tap/libtap.a lib/libwebauth.la \
	util/libutil.a portable/libportable.la $(KRB5_LIBS)
tests_lib_krb5_remctl_t_CPPFLAGS = $(KRB5_CPPFLAGS) $(AM_CPPFLAGS)
tests_lib_krb5_remctl_t_LDFLAGS = $(KRB5_LDFLAGS)
tests_lib_krb5_remctl_t_LDADD = tests/tap/libtap.a lib/libwebauth.la \
	portable/libportable.la $(KRB5_LIBS)
tests_lib_krb5_tgt_t_CPPFLAGS = $(APRUTIL_CPPFLAGS) $(AM_CPPFLAGS)
tests_lib_krb5_tgt_t_LDFLAGS = $(APRUTIL_LDFLAGS) $(KRB5_LDFLAGS)
tests_lib_krb5_tgt_t_LDADD = tests/tap/libtap.a lib/libwebauth.la \
	util/libutil.a portable/libportable.la $(APRUTIL_LIBS) $(KRB5_LIBS)
tests_lib_userinfo_t_CPPFLAGS = $(APR_CPPFLAGS) $(AM_CPPFLAGS)
tests_lib_userinfo_t_LDFLAGS = $(APR_LDFLAGS) $(KRB5_LDFLAGS)
tests_lib_userinfo_t_LDADD = tests/tap/libtap.a lib/libwebauth.la \
	util/libutil.a portable/libportable.la $(APR_LIBS) $(KRB5_LIBS)
tests_lib_token_crypto_t_LDADD = tests/tap/libtap.a lib/libwebauth.la \
	util/libutil.a portable/libportable.la
tests_lib_token_decode_t_LDADD = tests/tap/libtap.a lib/libwebauth.la \
	util/libutil.a portable/libportable.la
tests_lib_token_encode_t_LDADD = tests/tap/libtap.a lib/libwebauth.la \
	util/libutil.a portable/libportable.la
tests_lib_token_merge_t_SOURCES = lib/errors.c lib/token-merge.c \
	tests/lib/token-merge-t.c
tests_lib_token_merge_t_CPPFLAGS = $(APR_CPPFLAGS) $(AM_CPPFLAGS)
tests_lib_token_merge_t_LDADD = tests/tap/libtap.a lib/libwebauth.la \
	portable/libportable.la $(APR_LIBS)
tests_lib_was_cache_t_LDADD = tests/tap/libtap.a lib/libwebauth.la \
	util/libutil.a portable/libportable.la
tests_lib_webkdc_krb_t_CPPFLAGS = $(APR_CPPFLAGS) $(AM_CPPFLAGS)
tests_lib_webkdc_krb_t_LDFLAGS = $(APR_LDFLAGS) $(KRB5_LDFLAGS)
tests_lib_webkdc_krb_t_LDADD = tests/tap/libtap.a lib/libwebauth.la \
	util/libutil.a portable/libportable.la $(APR_LIBS) $(KRB5_LIBS)
tests_lib_webkdc_login_t_CPPFLAGS = $(APR_CPPFLAGS) $(AM_CPPFLAGS)
tests_lib_webkdc_login_t_LDFLAGS = $(APR_LDFLAGS)
tests_lib_webkdc_login_t_LDADD = tests/tap/libtap.a lib/libwebauth.la \
	util/libutil.a portable/libportable.la $(APR_LIBS)
tests_lib_webkdc_mf_t_CPPFLAGS = $(APR_CPPFLAGS) $(AM_CPPFLAGS)
tests_lib_webkdc_mf_t_LDFLAGS = $(APR_LDFLAGS) $(KRB5_LDFLAGS)
tests_lib_webkdc_mf_t_LDADD = tests/tap/libtap.a lib/libwebauth.la \
	util/libutil.a portable/libportable.la $(APR_LIBS) $(KRB5_LIBS)
tests_portable_asprintf_t_SOURCES = tests/portable/asprintf-t.c \
	tests/portable/asprintf.c
tests_portable_asprintf_t_LDADD = tests/tap/libtap.a portable/libportable.la
tests_portable_mkstemp_t_SOURCES = tests/portable/mkstemp-t.c \
	tests/portable/mkstemp.c
tests_portable_mkstemp_t_LDADD = tests/tap/libtap.a portable/libportable.la
tests_portable_setenv_t_SOURCES = tests/portable/setenv-t.c \
	tests/portable/setenv.c
tests_portable_setenv_t_LDADD = tests/tap/libtap.a portable/libportable.la
tests_portable_snprintf_t_SOURCES = tests/portable/snprintf-t.c \
	tests/portable/snprintf.c
tests_portable_snprintf_t_LDADD = tests/tap/libtap.a portable/libportable.la
tests_portable_strlcat_t_SOURCES = tests/portable/strlcat-t.c \
	tests/portable/strlcat.c
tests_portable_strlcat_t_LDADD = tests/tap/libtap.a portable/libportable.la
tests_portable_strlcpy_t_SOURCES = tests/portable/strlcpy-t.c \
	tests/portable/strlcpy.c
tests_portable_strlcpy_t_LDADD = tests/tap/libtap.a portable/libportable.la
tests_portable_strndup_t_SOURCES = tests/portable/strndup-t.c \
	tests/portable/strndup.c
tests_portable_strndup_t_LDADD = tests/tap/libtap.a portable/libportable.la
tests_util_messages_t_LDADD = tests/tap/libtap.a util/libutil.a \
	portable/libportable.la
tests_util_xmalloc_LDADD = util/libutil.a portable/libportable.la

# The Perl test suite also requires a copy of the tokens.conf file, the test
# keyring, and all the pre-generated tokens.  Handle copying those over via
# Makefile rules and remove them on make clean.
perl/t/data/keyring: $(srcdir)/tests/data/keyring
	[ -d perl/t/data] || $(MKDIR_P) perl/t/data
	cp $(srcdir)/tests/data/keyring perl/t/data/keyring
perl/t/data/tokens.conf: $(srcdir)/tests/data/tokens.conf
	cp $(srcdir)/tests/data/tokens.conf perl/t/data/tokens.conf
	[ -d perl/t/data/tokens ] || $(MKDIR_P) perl/t/data/tokens
	cp $(srcdir)/tests/data/tokens/* perl/t/data/tokens/

check-local: $(check_PROGRAMS) $(srcdir)/tests/TESTS $(BINDINGS_CHECK)
	cd tests && ./runtests -l $(abs_top_srcdir)/tests/TESTS
	@set -e; if [ -f perl/Build ] ; then				\
	    echo '' ;							\
	    cd perl && LD_LIBRARY_PATH='$(abs_top_builddir)/lib/.libs'	\
		REMCTLD='$(PATH_REMCTLD)' ./Build test ;		\
	fi

# Used by maintainers to run the main test suite under valgrind.  Suppress
# the xmalloc and pod-spelling tests because the former won't work properly
# under valgrind (due to increased memory usage) and the latter is pointless
# to run under valgrind.
check-valgrind: $(check_PROGRAMS)
	rm -rf $(abs_top_builddir)/tmp-valgrind
	mkdir $(abs_top_builddir)/tmp-valgrind
	env RRA_MAINTAINER_TESTS= valgrind --leak-check=full		   \
	    --show-reachable=yes --trace-children=yes			   \
	    --log-file=$(abs_top_builddir)/tmp-valgrind/log.%p		   \
	    --suppressions=$(abs_top_srcdir)/tests/data/valgrind.supp	   \
	    --trace-children-skip="/bin/sh,*/cat,*/cut,*/expr,*/getopt,*/kinit,*/ls,*/mkdir,*/rm,*/rmdir,*/sed,*/sleep,*/wc,*/remctld,*/data/cmd-*,*/data/generate-krb5-conf,*/docs/*-t,*/perl/*-t,*/util/xmalloc-t" \
	    tests/runtests -l $(abs_top_srcdir)/tests/TESTS
