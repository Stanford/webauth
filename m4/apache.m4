dnl Find the compiler and linker flags for Apache modules.
dnl
dnl Finds the compiler and linker flags for building an Apache module.
dnl Provides the --with-apxs configure option to specify the path of the apxs
dnl utility, or searches for it on the user's PATH.
dnl
dnl Provides the macro RRA_LIB_APACHE and sets the substitution variables
dnl APACHE_CPPFLAGS, APACHE_LDFLAGS, and APACHE_LIBS.  Also provides
dnl RRA_LIB_APACHE_SWITCH to set CPPFLAGS, LDFLAGS, and LIBS to include the
dnl Apache libraries, saving the current values first, and
dnl RRA_LIB_APACHE_RESTORE to restore those settings to before the last
dnl RRA_LIB_APACHE_SWITCH.  The configure script will exit with an error if
dnl apxs could not be found or does not support the desired options.
dnl
dnl The canonical version of this file is maintained in the rra-c-util
dnl package, available at <http://www.eyrie.org/~eagle/software/rra-c-util/>.
dnl
dnl Written by Russ Allbery <eagle@eyrie.org>
dnl Copyright 2010
dnl     The Board of Trustees of the Leland Stanford Junior University
dnl
dnl This file is free software; the authors give unlimited permission to copy
dnl and/or distribute it, with or without modifications, as long as this
dnl notice is preserved.

dnl Headers to include when probing for Apache properties.
AC_DEFUN([RRA_INCLUDES_APACHE], [[
#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <http_request.h>
#include <unixd.h>
]])

dnl Save the current CPPFLAGS, LDFLAGS, and LIBS settings and switch to
dnl versions that include the Apache flags.  Used as a wrapper, with
dnl RRA_LIB_APACHE_RESTORE, around tests.
AC_DEFUN([RRA_LIB_APACHE_SWITCH],
[rra_apache_save_CPPFLAGS="$CPPFLAGS"
 rra_apache_save_LDFLAGS="$LDFLAGS"
 rra_apache_save_LIBS="$LIBS"
 CPPFLAGS="$APACHE_CPPFLAGS $CPPFLAGS"
 LDFLAGS="$APACHE_LDFLAGS $LDFLAGS"
 LIBS="$APACHE_LIBS $LIBS"])

dnl Restore CPPFLAGS, LDFLAGS, and LIBS to their previous values (before
dnl RRA_LIB_APACHE_SWITCH was called).
AC_DEFUN([RRA_LIB_APACHE_RESTORE],
[CPPFLAGS="$rra_apache_save_CPPFLAGS"
 LDFLAGS="$rra_apache_save_LDFLAGS"
 LIBS="$rra_apache_save_LIBS"])

dnl The main macro for determining the flags for Apache modules.
AC_DEFUN([RRA_LIB_APACHE],
[rra_apache_apxs=
 APACHE_CPPFLAGS=
 APACHE_LDFLAGS=
 APACHE_LIBS=
 AC_SUBST([APACHE_CPPFLAGS])
 AC_SUBST([APACHE_LDFLAGS])
 AC_SUBST([APACHE_LIBS])

 AC_ARG_WITH([apxs],
    [AS_HELP_STRING([--with-apxs=PATH],
        [Path to Apache 2.x apxs program])],
    [AS_IF([test x"$withval" != xno && test x"$withval" != xyes],
        [rra_apache_apxs="$withval"])])
 AS_IF([test -z "$rra_apache_apxs"],
    [AC_PATH_PROGS([rra_apache_apxs], [apxs2 apxs], [false])
     AS_IF([test x"$rra_apache_apxs" = xfalse],
        [AC_MSG_ERROR([cannot find usable apxs program])])])
 APACHE_CPPFLAGS=`"$rra_apache_apxs" -q CFLAGS 2>/dev/null`
 APACHE_CPPFLAGS=`echo "$APACHE_CPPFLAGS" | sed -e 's/ -g//' -e 's/ -O[0-9]//'`
 rra_apache_includedir=`"$rra_apache_apxs" -q INCLUDEDIR 2>/dev/null`
 AS_IF([test -z "$rra_apache_includedir"],
    [AC_MSG_ERROR([apxs -q INCLUDEDIR failed or returned no value])])
 APACHE_CPPFLAGS="$APACHE_CPPFLAGS -I$rra_apache_includedir"
 AC_ARG_VAR([APR_CONFIG], [Path to apr-1-config or apr-config])
 AC_PATH_PROGS([APR_CONFIG], [apr-1-config apr-config], [false])
 AS_IF([test x"$APR_CONFIG" != xfalse],
     [APACHE_CPPFLAGS="$APACHE_CPPFLAGS "`"$APR_CONFIG" --includes`])
 APACHE_LDFLAGS=`"$rra_apache_apxs" -q LDFLAGS_SHLIB 2>/dev/null`])
