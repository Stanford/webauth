dnl Process this file with autoconf to produce a configure script.
dnl $Id$

dnl Put more complex macros into separate files to make them easier to
dnl maintain.  (Also good for macros that should be used in other projects as
dnl well.)
m4_include([m4/apache.m4])
m4_include([m4/curl.m4])
m4_include([m4/int32.m4])
m4_include([m4/krb5.m4])
m4_include([m4/libtool.m4])
m4_include([m4/ssl.m4])

AC_REVISION($Revision$)
AC_PREREQ(2.53)
AC_INIT([Webauth], [2.90.0], [webauth-team@lists.stanford.edu])
AC_CONFIG_AUX_DIR([tools])

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

dnl Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB

dnl Find apxs, which may be in a separate Apache 2.x installation location.
WEBAUTH_APACHE

dnl Checks for libraries

dnl The rat's nest of networking libraries.  The common cases are not to
dnl need any extra libraries, or to need -lsocket -lnsl.  We need to avoid
dnl linking with libnsl unless we need it, though, since on some OSes where
dnl it isn't necessary it will totally break networking.  Unisys also
dnl includes gethostbyname in libsocket but needs libnsl for socket().
AC_SEARCH_LIBS(gethostbyname, nsl)
AC_SEARCH_LIBS(socket, socket, ,
    [AC_CHECK_LIB(nsl, socket, LIBS="$LIBS -lsocket -lnsl", , -lsocket)])

WEBAUTH_LIB_KRB5
WEBAUTH_LIB_SSL
WEBAUTH_LIB_CURL

dnl Check for an implementation of AES, and if not found in the OpenSSL
dnl libraries, set WEBAUTH_AES_OBJS to the *.o files required for it.
aes="aes_cbc.o aes_cfb.o aes_core.o aes_ctr.o aes_ecb.o aes_misc.o aes_ofb.o"
AC_CHECK_LIB(crypto, AES_cbc_encrypt, 
    [AC_MSG_NOTICE([using AES support in -lcrypto])],
    [AC_MSG_NOTICE([building AES support in -lwebauth])
     WEBAUTH_AES_OBJS=$aes
     AC_SUBST(WEBAUTH_AES_OBJS)])

dnl Checks for header files.
AC_HEADER_STDC

dnl Checks for types.
WEBAUTH_TYPE_INT32_T

dnl Checks for structures.
dnl Checks for compiler characteristics.

dnl Crank up warnings if using GCC
if test "$GCC" = "yes" ; then
    CFLAGS="-Wall $CFLAGS"
fi

dnl Generate special flags for apxs, which doesn't understand compiler flags.
APXS_CFLAGS=-Wc,`echo "$CFLAGS" | sed 's/ / -Wc,/g'`
AC_SUBST([APXS_CFLAGS])

dnl Checks for library functions.
dnl Checks for system services.

dnl Output files.
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
    Makefile
    src/Makefile
    src/bindings/perl/WebAuth/Makefile.PL
    src/libwebauth/Makefile
    src/libwebauth/webauth.h
    src/modules/Makefile
    src/modules/webauth/Makefile
    src/modules/webkdc/Makefile
    src/utils/Makefile
    tests/Makefile
    tests/libwebauth/Makefile
])
AC_OUTPUT
