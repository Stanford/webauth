dnl Process this file with autoconf to produce a configure script.
dnl
dnl Written by Russ Allbery <rra@stanford.edu>
dnl Copyright 2002, 2003, 2005, 2006, 2007, 2008, 2009, 2010, 2011
dnl    The Board of Trustees of the Leland Stanford Junior University
dnl
dnl See LICENSE for licensing terms.

AC_PREREQ([2.64])
AC_INIT([WebAuth], [3.7.4], [webauth-team@lists.stanford.edu])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_LIBOBJ_DIR([portable])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.11 check-news silent-rules -Wall -Werror])
AM_MAINTAINER_MODE

AC_PROG_CC
AC_USE_SYSTEM_EXTENSIONS
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_LIBTOOL
RRA_LD_VERSION_SCRIPT

dnl Store information about the time the package was configured and the person
dnl who configured it into another variable.
webauth_user=`(whoami || /usr/ucb/whoami || echo UNKNOWN) 2>/dev/null`
webauth_host=`(hostname || echo UNKNOWN) 2>/dev/null`
webauth_date=`(date -u +"%Y-%m-%d %T UTC" || echo UNKNOWN) 2>/dev/null`
AC_DEFINE_UNQUOTED([PACKAGE_BUILD_INFO],
    ["Built by $webauth_user@$webauth_host on $webauth_date"],
    [Define to information about when and by whom the package was built.])

dnl By default, we don't build mod_webkdc or the WebLogin Perl module or code.
dnl Allow that to be enabled.
build_webkdc=false
AC_ARG_ENABLE([webkdc],
    [AC_HELP_STRING([--enable-webkdc],
        [Build and install WebLogin and the WebKDC Apache module])],
    [AS_IF([test x"$enableval" != xno], [build_webkdc=true])])
AM_CONDITIONAL([BUILD_WEBKDC], [test x"$build_webkdc" = xtrue])

dnl Provide a way to disable building mod_webauth for systems that don't need
dnl it, like the WebKDC, or for a pure library build.
build_webauth=true
AC_ARG_ENABLE([mod_webauth],
    [AC_HELP_STRING([--disable-mod_webauth],
        [Do not build the WebAuth Apache module])],
    [AS_IF([test x"$enableval" = xno], [build_webauth=false])])
AM_CONDITIONAL([BUILD_WEBAUTH], [test x"$build_webauth" = xtrue])

dnl Provide a way to disable building mod_webauthldap for systems that don't
dnl need the directory integration.
build_webauthldap=true
AC_ARG_ENABLE([mod_webauthldap],
    [AC_HELP_STRING([--disable-mod_webauthldap],
        [Do not build the WebAuth LDAP Apache module])],
    [AS_IF([test x"$enableval" = xno], [build_webauthldap=false])])
AM_CONDITIONAL([BUILD_WEBAUTHLDAP], [test x"$build_webauthldap" = xtrue])

dnl Allow the user to indicate that the Perl modules should not be built.
AC_ARG_ENABLE([perl],
    [AC_HELP_STRING([--enable-perl], [Build Perl bindings])],
    [AS_IF([test x"$enableval" = xyes], [build_perl=true],
        [build_perl=false])],
    [build_perl="$build_webkdc"])
AM_CONDITIONAL([BUILD_PERL], [test x"$build_perl" = xtrue])
AS_IF([test x"$build_perl" = xtrue], [AC_PATH_PROG([PERL], [perl])])

RRA_LIB_APACHE
RRA_LIB_KRB5
RRA_LIB_KRB5_SWITCH
AC_CHECK_HEADERS([et/com_err.h])
AC_CHECK_FUNCS([krb5_data_free \
    krb5_get_init_creds_opt_alloc \
    krb5_get_init_creds_opt_set_default_flags \
    krb5_principal_get_realm \
    krb5_principal_set_realm \
    krb5_unparse_name_flags \
    krb5_xfree])
AC_CHECK_FUNCS([krb5_get_init_creds_opt_free],
    [RRA_FUNC_KRB5_GET_INIT_CREDS_OPT_FREE_ARGS])
AC_CHECK_DECLS([krb5_kt_free_entry], [], [], [#include <krb5.h>])
AC_CHECK_MEMBER([krb5_creds.session],
    [AC_DEFINE([HAVE_KRB5_HEIMDAL], [1],
        [Define if your Kerberos implementation is Heimdal.])],
    [AC_DEFINE([HAVE_KRB5_MIT], [1],
        [Define if your Kerberos implementation is MIT.])],
    [#include <krb5.h>])
RRA_LIB_KRB5_RESTORE
RRA_LIB_SSL
RRA_LIB_CURL
AS_IF([test x"$build_webauthldap" = x"true"], [RRA_LIB_LDAP])

AC_HEADER_STDBOOL
AC_CHECK_HEADERS([sys/bittypes.h syslog.h])
AC_CHECK_DECLS([snprintf, vsnprintf])
AC_CHECK_FUNCS([setrlimit])
RRA_C_C99_VAMACROS
RRA_C_GNU_VAMACROS
AC_TYPE_LONG_LONG_INT
AC_TYPE_INT32_T
AC_TYPE_UINT32_T
AC_TYPE_INTPTR_T
RRA_FUNC_SNPRINTF
AC_REPLACE_FUNCS([asprintf mkstemp strlcat strlcpy])

dnl Used to determine whether to add our GCC-specific warning suppression
dnl flags to the language binding builds.
AM_CONDITIONAL([GCC], [test x"$GCC" = xyes])

dnl Used when linking the Perl module.  Normally link against all the
dnl dependencies that libwebauth may need, but don't do so if
dnl --enable-reduced-depends was specified.
AS_IF([test x"$rra_reduced_depends" = xtrue],
    [DEPEND_LIBS=],
    [DEPEND_LIBS="$KRB5_LDFLAGS $KRB5_LIBS -lcom_err"
     DEPEND_LIBS="$DEPEND_LIBS $CRYPTO_LDFLAGS $CRYPTO_LIBS"])
AC_SUBST([DEPEND_LIBS])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADERS([config.h modules/mod-config.h])
AS_IF([test x"$build_perl" = xtrue], [AC_CONFIG_FILES([perl/Makefile.PL])])
AC_CONFIG_COMMANDS([include/webauth.h],
    [${srcdir}/include/mkheader ${srcdir}/${filename}.in ${filename}],
    [filename=include/webauth.h])
AC_OUTPUT
