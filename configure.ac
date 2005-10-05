dnl Process this file with autoconf to produce a configure script.
dnl $Id$

dnl Put more complex macros into separate files to make them easier to
dnl maintain.  (Also good for macros that should be used in other projects as
dnl well.)
m4_include([m4/apache.m4])
m4_include([m4/curl.m4])
m4_include([m4/int32.m4])
m4_include([m4/krb5.m4])
m4_include([m4/libgcc.m4])
m4_include([m4/libtool.m4])
m4_include([m4/ssl.m4])
m4_include([m4/ldap.m4])

AC_REVISION($Revision$)
AC_PREREQ(2.57)
AC_INIT([Webauth], [3.3.0], [webauth-team@lists.stanford.edu])
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

dnl By default, we don't build mod_webkdc.  Allow that to be enabled.
MODULES=
AC_ARG_ENABLE([mod_webkdc],
    AC_HELP_STRING([--enable-mod_webkdc],
        [Build and install the WebKDC Apache module]),
    [if test x"$enableval" != xno ; then
        MODULES=webkdc
     fi])
AC_SUBST(MODULES)

dnl Provide a way to disable building mod_webauth for systems that don't need
dnl it, like the WebKDC, or for a pure library build.
AC_ARG_ENABLE([mod_webauth],
    AC_HELP_STRING([--disable-mod_webauth],
        [Do not build the WebAuth Apache module]),
    [if test x"$enableval" = xyes ; then
        MODULES="webauth $MODULES"
     fi],
    [MODULES="webauth $MODULES"])

AC_ARG_ENABLE([mod_webauthldap],
    AC_HELP_STRING([--disable-mod_webauthldap],
        [Do not build the WebAuth LDAP  module]),
    [if test x"$enableval" = xyes ; then
        MODULES="webauthldap $MODULES"
     fi],
    [MODULES="webauthldap $MODULES"])

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
        build_perl=yes
        BINDINGS=perl
     else
        build_perl=no
        BINDINGS=
     fi],
     [case "$MODULES" in
      *webkdc*)
         BINDINGS=perl
         build_perl=yes
         ;;
      *)
         BINDINGS=
         build_perl=no
         ;;
      esac])
AC_SUBST(BINDINGS)

dnl Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB

dnl Find apxs, which may be in a separate Apache 2.x installation location.
WEBAUTH_APACHE

dnl Find Perl, used to build the Perl bindings.
if test x"$build_perl" = xyes ; then
    AC_PATH_PROG([PERL], [perl])
fi

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
WEBAUTH_LIB_LDAP
WEBAUTH_LIB_LIBGCC

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([netinet/in.h])

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
AC_CONFIG_HEADERS([config.h mod-config.h])
AC_CONFIG_FILES([
    Makefile
    src/Makefile
    src/bindings/Makefile
    src/libwebauth/Makefile
    src/modules/Makefile
    src/modules/webauth/Makefile
    src/modules/webauthldap/Makefile
    src/utils/Makefile
    src/webkdc/Makefile
    tests/Makefile
    tests/libwebauth/Makefile
])
if test x"$build_perl" = xyes ; then
    AC_CONFIG_FILES([
        src/bindings/perl/Makefile
        src/bindings/perl/WebAuth/Makefile.PL
    ])
fi

dnl Only create the WebKDC makefile if we're building the WebKDC.
case "$MODULES" in
*webkdc*)
    AC_CONFIG_FILES([src/modules/webkdc/Makefile])
    ;;
esac

dnl Generate webauth.h from webauth.h.in.
AC_CONFIG_COMMANDS([src/libwebauth/webauth.h],
    [$srcdir/tools/mkheader $srcdir/$filename.in $filename],
    [filename=src/libwebauth/webauth.h])

dnl Link all of the Perl binding files into the build tree, since Perl doesn't
dnl support the VPATH thing.
if test x"$build_perl" = xyes ; then
    AC_CONFIG_COMMANDS([src/bindings/perl/WebAuth/WebAuth.xs],
    [if test x"$ac_srcdir" != x. && test x"$ac_srcdir" != x ; then
        for f in WebAuth.pm WebAuth.xs test.pl typemap ; do
            $LN_S "$ac_srcdir/$f" "src/bindings/perl/WebAuth/$f"
        done
    fi], [LN_S="$LN_S"])
fi

dnl Generate config.h.
AC_OUTPUT
