dnl Find the compiler and linker flags for cURL.
dnl
dnl Finds the compiler and linker flags for linking with the cURL library.
dnl Provides the --with-curl, --with-curl-lib, and --with-curl-include
dnl configure options to specify non-standard paths to the cURL libraries.
dnl Uses curl-config where available.
dnl
dnl Provides the macro RRA_LIB_CURL and sets the substitution variables
dnl CURL_CPPFLAGS, CURL_LDFLAGS, and CURL_LIBS.  Also provides
dnl RRA_LIB_CURL_SWITCH to set CPPFLAGS, LDFLAGS, and LIBS to include the cURL
dnl libraries, saving the current values first, and RRA_LIB_CURL_RESTORE to
dnl restore those settings to before the last RRA_LIB_CURL_SWITCH.
dnl
dnl Depends on RRA_SET_LDFLAGS and RRA_ENABLE_REDUCED_DEPENDS and may depend
dnl on RRA_LIB_OPENSSL.
dnl
dnl The canonical version of this file is maintained in the rra-c-util
dnl package, available at <http://www.eyrie.org/~eagle/software/rra-c-util/>.
dnl
dnl Written by Russ Allbery <eagle@eyrie.org>
dnl Copyright 2010, 2013
dnl     The Board of Trustees of the Leland Stanford Junior University
dnl
dnl This file is free software; the authors give unlimited permission to copy
dnl and/or distribute it, with or without modifications, as long as this
dnl notice is preserved.

dnl Save the current CPPFLAGS, LDFLAGS, and LIBS settings and switch to
dnl versions that include the cURL flags.  Used as a wrapper, with
dnl RRA_LIB_CURL_RESTORE, around tests.
AC_DEFUN([RRA_LIB_CURL_SWITCH],
[rra_curl_save_CPPFLAGS="$CPPFLAGS"
 rra_curl_save_LDFLAGS="$LDFLAGS"
 rra_curl_save_LIBS="$LIBS"
 CPPFLAGS="$CURL_CPPFLAGS $CPPFLAGS"
 LDFLAGS="$CURL_LDFLAGS $LDFLAGS"
 LIBS="$CURL_LIBS $LIBS"])

dnl Restore CPPFLAGS, LDFLAGS, and LIBS to their previous values (before
dnl RRA_LIB_CURL_SWITCH was called).
AC_DEFUN([RRA_LIB_CURL_RESTORE],
[CPPFLAGS="$rra_curl_save_CPPFLAGS"
 LDFLAGS="$rra_curl_save_LDFLAGS"
 LIBS="$rra_curl_save_LIBS"])

dnl Set CURL_CPPFLAGS and CURL_LDFLAGS based on rra_curl_root,
dnl rra_curl_libdir, and rra_curl_includedir.
AC_DEFUN([_RRA_LIB_CURL_PATHS],
[AS_IF([test x"$rra_curl_libdir" != x],
    [CURL_LDFLAGS="-L$rra_curl_libdir"],
    [AS_IF([test x"$rra_curl_root" != x],
        [RRA_SET_LDFLAGS([CURL_LDFLAGS], [$rra_curl_root])])])
 AS_IF([test x"$rra_curl_includedir" != x],
    [CURL_CPPFLAGS="-I$rra_curl_includedir"],
    [AS_IF([test x"$rra_curl_root" != x],
        [AS_IF([test x"$rra_curl_root" != x/usr],
            [CURL_CPPFLAGS="-I${rra_curl_root}/include"])])])])

dnl Does the appropriate library checks for reduced-dependency cURL linkage.
AC_DEFUN([_RRA_LIB_CURL_REDUCED],
[RRA_LIB_CURL_SWITCH
 AC_CHECK_LIB([curl], [curl_easy_init], [CURL_LIBS="-lcurl"],
    [AC_MSG_ERROR([cannot find usable cURL library])])
 RRA_LIB_CURL_RESTORE])

dnl Does the appropriate library checks for cURL linkage without curl-config
dnl or reduced dependencies.
AC_DEFUN([_RRA_LIB_CURL_MANUAL],
[AC_REQUIRE([RRA_LIB_OPENSSL])
 RRA_LIB_CURL_SWITCH
 AC_CHECK_LIB([z], [inflate], [CURL_LIBS=-lz])
 AC_CHECK_LIB([curl], [curl_easy_init],
    [CURL_LDFLAGS="$CURL_LDFLAGS OPENSSL_LDFLAGS"
     CURL_LIBS="-lcurl $CURL_LIBS $OPENSSL_LIBS"],
    [AC_MSG_ERROR([cannot find usable cURL library])],
    [$CURL_LIBS $OPENSSL_LDFLAGS $OPENSSL_LIBS])
 RRA_LIB_CURL_RESTORE])

dnl Sanity-check the results of curl-config and be sure we can really link a
dnl cURL program.  If that fails, clear CURL_CPPFLAGS and CURL_LIBS so that we
dnl know we don't have usable flags and fall back on the manual check.
AC_DEFUN([_RRA_LIB_CURL_CHECK],
[RRA_LIB_CURL_SWITCH
 AC_CHECK_FUNC([curl_easy_init],
    [RRA_LIB_CURL_RESTORE],
    [RRA_LIB_CURL_RESTORE
     CURL_CPPFLAGS=
     CURL_LIBS=
     _RRA_LIB_CURL_PATHS
     AS_IF([test x"$rra_reduced_depends" = xtrue],
         [_RRA_LIB_CURL_REDUCED],
         [_RRA_LIB_CURL_MANUAL])])])

dnl The main macro.
AC_DEFUN([RRA_LIB_CURL],
[AC_REQUIRE([AC_CANONICAL_HOST])
 AC_REQUIRE([RRA_ENABLE_REDUCED_DEPENDS])
 rra_curl_root=
 rra_curl_libdir=
 rra_curl_includedir=
 CURL_CPPFLAGS=
 CURL_LDFLAGS=
 CURL_LIBS=
 AC_SUBST([CURL_CPPFLAGS])
 AC_SUBST([CURL_LDFLAGS])
 AC_SUBST([CURL_LIBS])

 AC_ARG_WITH([curl],
    [AS_HELP_STRING([--with-curl=DIR],
        [Location of cURL headers and libraries])],
    [AS_IF([test x"$withval" != xyes && test x"$withval" != xno],
        [rra_curl_root="$withval"])])
 AC_ARG_WITH([curl-include],
    [AS_HELP_STRING([--with-curl-include=DIR],
        [Location of cURL headers])],
    [AS_IF([test x"$withval" != xyes && test x"$withval" != xno],
        [rra_curl_includedir="$withval"])])
 AC_ARG_WITH([curl-lib],
    [AS_HELP_STRING([--with-curl-lib=DIR],
        [Location of cURL libraries])],
    [AS_IF([test x"$withval" != xyes && test x"$withval" != xno],
        [rra_curl_libdir="$withval"])])

 AC_ARG_VAR([CURL_CONFIG], [Path to curl-config])
 AS_IF([test x"$rra_curl_root" != x && test -z "$CURL_CONFIG"],
    [AS_IF([test -x "${rra_curl_root}/bin/curl-config"],
        [CURL_CONFIG="${rra_curl_root}/bin/curl-config"])],
    [AC_PATH_PROG([CURL_CONFIG], [curl-config])])
 AS_IF([test x"$CURL_CONFIG" != x && test -x "$CURL_CONFIG"],
    [CURL_CPPFLAGS=`"$CURL_CONFIG" --cflags 2>/dev/null`
     CURL_LIBS=`"$CURL_CONFIG" --libs 2>/dev/null`
     CURL_CPPFLAGS=`echo "$CURL_CPPFLAGS" | sed 's%-I/usr/include ?%%'`
     # Work around a bug in the Mac OS X curl-config script fixed in Tiger.
     AS_CASE([$host],
         [powerpc-apple-darwin7*],
         [CURL_LIBS=`echo "$CURL_LIBS" | sed 's/-arch i386//g'`])
     _RRA_LIB_CURL_CHECK],
    [_RRA_LIB_CURL_PATHS
     AS_IF([test x"$rra_reduced_depends" = xtrue],
        [_RRA_LIB_CURL_REDUCED],
        [_RRA_LIB_CURL_MANUAL])])])
