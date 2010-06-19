dnl Process this file with autoconf to produce a configure script.
dnl
dnl Written by Russ Allbery <rra@stanford.edu>
dnl Copyright 2002, 2003, 2005, 2006, 2007, 2008, 2009, 2010
dnl    Board of Trustees, Leland Stanford Jr. University
dnl
dnl See LICENSE for licensing terms.

AC_PREREQ([2.64])
AC_INIT([WebAuth], [3.6.2], [webauth-team@lists.stanford.edu])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_LIBOBJ_DIR([portable])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.11 check-news silent-rules -Wall -Werror])
AM_MAINTAINER_MODE

dnl Store information about the time the package was configured and the person
dnl who configured it into another variable.
webauth_user=`(whoami || /usr/ucb/whoami || echo UNKNOWN) 2>/dev/null`
webauth_host=`(hostname || echo UNKNOWN) 2>/dev/null`
webauth_date=`(date -u +"%Y-%m-%d %T UTC" || echo UNKNOWN) 2>/dev/null`
AC_DEFINE_UNQUOTED([PACKAGE_BUILD_INFO],
    ["Built by $webauth_user@$webauth_host on $webauth_date"],
    [Define to information about when and by whom the package was built.])

dnl Make sure $prefix is set so that we can use it internally.
test x"$prefix" = xNONE && prefix="$ac_default_prefix"

dnl If the user requests reduced library dependencies, set a flag that is used
dnl in all of our library checks.
reduced_depends=false
AC_ARG_ENABLE([reduced-depends],
    AC_HELP_STRING([--enable-reduced-depends],
        [Try to minimize shared library dependencies]),
    [if test x"$enableval" = xyes ; then
         reduced_depends=true
     fi])

dnl By default, we don't build mod_webkdc.  Allow that to be enabled.
build_webkdc=false
AC_ARG_ENABLE([mod_webkdc],
    AC_HELP_STRING([--enable-mod_webkdc],
        [Build and install the WebKDC Apache module]),
    [if test x"$enableval" != xno ; then
        build_webkdc=true
     fi])
AM_CONDITIONAL([BUILD_WEBKDC], [test x"$build_webkdc" = xtrue])

dnl Provide a way to disable building mod_webauth for systems that don't need
dnl it, like the WebKDC, or for a pure library build.
build_webauth=true
AC_ARG_ENABLE([mod_webauth],
    AC_HELP_STRING([--disable-mod_webauth],
        [Do not build the WebAuth Apache module]),
    [if test x"$enableval" = xno ; then
        build_webauth=false
     fi])
AM_CONDITIONAL([BUILD_WEBAUTH], [test x"$build_webauth" = xtrue])

dnl Provide a way to disable building mod_webauthldap for systems that don't
dnl need the directory integration.
build_webauthldap=true
AC_ARG_ENABLE([mod_webauthldap],
    AC_HELP_STRING([--disable-mod_webauthldap],
        [Do not build the WebAuth LDAP  module]),
    [if test x"$enableval" = xno ; then
        build_webauthldap=false
     fi])
AM_CONDITIONAL([BUILD_WEBAUTHLDAP], [test x"$build_webauthldap" = xtrue])

dnl Set the default compiler flags.  --enable-debug is the default.  If CFLAGS
dnl is set in the environment, always use it; otherwise, use -g unless
dnl --disable-debug is given.  If it is, use -O2 -DNDEBUG.
AC_ARG_ENABLE([debug],
    AC_HELP_STRING([--disable-debug], [Compile without debugging]),
    [if test -z "$CFLAGS" ; then
        if test x"$enableval" != xno ; then
            CFLAGS=-g
        else
            CFLAGS="-O2 -DNDEBUG"
        fi
     fi],
    [if test -z "$CFLAGS" ; then
        CFLAGS=-g
     fi])

dnl Allow the user to indicate that the Perl modules should not be built.
AC_ARG_ENABLE([perl],
    AC_HELP_STRING([--enable-perl], [Build Perl bindings]),
    [if test x"$enableval" = xyes ; then
        build_perl=true
     else
        build_perl=false
     fi],
     [if test x"$build_webkdc" = xtrue ; then
         build_perl=true
      else
         build_perl=false
      fi])
AM_CONDITIONAL([BUILD_PERL], [test x"$build_perl" = xtrue])

dnl Checks for programs.
AC_PROG_CC
AC_USE_SYSTEM_EXTENSIONS
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_LIBTOOL

dnl Find apxs, which may be in a separate Apache 2.x installation location.
WEBAUTH_APACHE

dnl Find Perl, used to build the Perl bindings.
if test x"$build_perl" = xtrue ; then
    AC_PATH_PROG([PERL], [perl])
fi

dnl Checks for libraries.
RRA_LIB_KRB5
RRA_LIB_KRB5_SWITCH
AC_CHECK_HEADERS([et/com_err.h])
AC_CHECK_TYPES([krb5_realm], , , [#include <krb5.h>])
AC_CHECK_FUNCS([krb5_free_keytab_entry_contents \
                krb5_get_init_creds_opt_alloc \
                krb5_get_init_creds_opt_set_default_flags \
                krb5_principal_get_realm \
                krb5_unparse_name_flags])
AC_CHECK_MEMBER([krb5_creds.session],
    [AC_DEFINE([HAVE_KRB5_HEIMDAL], [1],
        [Define if your Kerberos implementation is Heimdal.])],
    [AC_DEFINE([HAVE_KRB5_MIT], [1],
        [Define if your Kerberos implementation is MIT.])],
    [#include <krb5.h>])
RRA_LIB_KRB5_RESTORE
WEBAUTH_LIB_SSL
WEBAUTH_LIB_CURL
WEBAUTH_LIB_LDAP

dnl Add in the various dependent libraries if needed.
DEPEND_LIBS=
if test x"$reduced_depends" != xtrue ; then
    DEPEND_LIBS="$CRYPTO_LIBS $KRB5_LIBS"
    CURL_LIBS="$CURL_LIBS $SSL_LIBS"
    LDAP_LIBS="$LDAP_LIBS $SSL_LIBS"
fi
AC_SUBST([DEPEND_LIBS])

AC_HEADER_STDBOOL
AC_CHECK_HEADERS([netinet/in.h sys/bittypes.h syslog.h])
AC_CHECK_DECLS([snprintf, vsnprintf])
RRA_C_C99_VAMACROS
RRA_C_GNU_VAMACROS
AC_TYPE_LONG_LONG_INT
AC_TYPE_INT32_T
AC_TYPE_UINT32_T
AC_TYPE_INTPTR_T
RRA_FUNC_SNPRINTF
AC_REPLACE_FUNCS([asprintf strlcat strlcpy])

dnl Generate special flags for apxs, which doesn't understand compiler flags.
dnl We have to do this with KRB5_LIBS and DEPEND_LIBS as well, since Heimdal
dnl likes to put -pthread into the compiler flags and apxs doesn't understand
dnl it.  Handle -R (runtime search path link option) similarly.
APXS_CFLAGS=-Wc,`echo "$CFLAGS" | sed 's/ / -Wc,/g'`
APXS_DEPEND_LIBS=`echo " $DEPEND_LIBS" \
    | sed 's/-pthread/-Wc,-pthread -Wl,-lpthread/' \
    | sed 's/-pthreads/-Wc,-pthreads -Wl,-lpthreads/' \
    | sed 's/ -R/ -Wl,-R/' \
    | sed 's/ -dynamic/ -Wl,-dynamic/'`
APXS_KRB5_LIBS=`echo " $KRB5_LIBS" \
    | sed 's/-pthread/-Wc,-pthread -Wl,-lpthread/' \
    | sed 's/-pthreads/-Wc,-pthreads -Wl,-lpthreads/' \
    | sed 's/ -R/ -Wl,-R/' \
    | sed 's/ -dynamic/ -Wl,-dynamic/'`
AC_SUBST([APXS_CFLAGS])
AC_SUBST([APXS_DEPEND_LIBS])
AC_SUBST([APXS_KRB5_LIBS])

dnl If and only if we're on Linux, use a mapfile to do symbol versioning and
dnl make sure that all symbols in the library are resolved.  We'd like to do
dnl this on all platforms, but the syntax is different everywhere and I don't
dnl feel like dealing with the differences.
case "$host" in
*-gnu*)
    VERSION_LDFLAGS='-Wl,--version-script=${srcdir}/lib/mapfile -Wl,-z,defs'
    ;;
*)
    VERSION_LDFLAGS=""
    ;;
esac
AC_SUBST([VERSION_LDFLAGS])

dnl Output files.
AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADERS([config.h mod-config.h])
if test x"$build_perl" = xtrue ; then
    AC_CONFIG_FILES([perl/Makefile.PL])
fi

dnl Generate webauth.h from webauth.h.in.
AC_CONFIG_COMMANDS([lib/webauth.h],
    [${srcdir}/lib/mkheader ${srcdir}/${filename}.in ${filename}],
    [filename=lib/webauth.h])

dnl Generate config.h.
AC_OUTPUT
