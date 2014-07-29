dnl Find the compiler and linker flags for Jansson.
dnl 
dnl Finds the compiler and linker flags for linking with the Jansson JSON
dnl parsing library.  Provides the --with-jansson, --with-jansson-lib, and
dnl --with-jansson-include configure options to specify non-standard paths to
dnl the Jansson libraries or header files.
dnl 
dnl Provides the macros RRA_LIB_JANSSON and RRA_LIB_JANSSON_OPTIONAL and sets
dnl the substitution variables JANSSON_CPPFLAGS, JANSSON_LDFLAGS, and
dnl JANSSON_LIBS.  Also provides RRA_LIB_JANSSON_SWITCH to set CPPFLAGS,
dnl LDFLAGS, and LIBS to include the Jansson library, saving the current
dnl values first, and RRA_LIB_JANSSON_RESTORE to restore those settings to
dnl before the last RRA_LIB_JANSSON_SWITCH.  Defines HAVE_JANSSON and sets
dnl rra_use_JANSSON to true if libevent is found.  If it isn't found, the
dnl substitution variables will be empty.
dnl 
dnl Depends on the lib-helper.m4 framework.
dnl
dnl The canonical version of this file is maintained in the rra-c-util
dnl package, available at <http://www.eyrie.org/~eagle/software/rra-c-util/>.
dnl
dnl Written by Russ Allbery <eagle@eyrie.org>
dnl Copyright 2014
dnl     The Board of Trustees of the Leland Stanford Junior University
dnl
dnl This file is free software; the authors give unlimited permission to copy
dnl and/or distribute it, with or without modifications, as long as this
dnl notice is preserved.

dnl Save the current CPPFLAGS, LDFLAGS, and LIBS settings and switch to
dnl versions that include the Jansson flags.  Used as a wrapper, with
dnl RRA_LIB_JANSSON_RESTORE, around tests.
AC_DEFUN([RRA_LIB_JANSSON_SWITCH], [RRA_LIB_HELPER_SWITCH([JANSSON])])

dnl Restore CPPFLAGS, LDFLAGS, and LIBS to their previous values before
dnl RRA_LIB_JANSSON_SWITCH was called.
AC_DEFUN([RRA_LIB_JANSSON_RESTORE], [RRA_LIB_HELPER_RESTORE([JANSSON])])

dnl Checks if Jansson is present.  The single argument, if "true", says to
dnl fail if the Jansson library could not be found.  Prefer probing with
dnl pkg-config if available and the --with flags were not given.
AC_DEFUN([_RRA_LIB_JANSSON_INTERNAL],
[RRA_LIB_HELPER_PATHS([JANSSON])
 AS_IF([test x"$JANSSON_CPPFLAGS" = x && test x"$JANSSON_LDFLAGS" = x],
    [PKG_CHECK_EXISTS([jansson],
        [PKG_CHECK_MODULES([JANSSON], [jansson])
         JANSSON_CPPFLAGS="$JANSSON_CFLAGS"])])
 AS_IF([test x"$JANSSON_LIBS" = x],
    [RRA_LIB_JANSSON_SWITCH
     LIBS=
     AC_SEARCH_LIBS([json_loads], [jansson],
        [JANSSON_LIBS="$LIBS"],
        [AS_IF([test x"$1" = xtrue],
            [AC_MSG_ERROR([cannot find usable Jansson library])])])
     RRA_LIB_JANSSON_RESTORE])])

dnl The main macro for packages with mandatory libevent support.
AC_DEFUN([RRA_LIB_JANSSON],
[RRA_LIB_HELPER_VAR_INIT([JANSSON])
 RRA_LIB_HELPER_WITH([jansson], [Jansson], [JANSSON])
 _RRA_LIB_JANSSON_INTERNAL([true])
 rra_use_JANSSON=true
 AC_DEFINE([HAVE_JANSSON], 1, [Define if Jansson is available.])])

dnl The main macro for packages with optional Jansson support.
AC_DEFUN([RRA_LIB_JANSSON_OPTIONAL],
[RRA_LIB_HELPER_VAR_INIT([JANSSON])
 RRA_LIB_HELPER_WITH_OPTIONAL([jansson], [Jansson], [JANSSON])
 AS_IF([test x"$rra_use_JANSSON" != xfalse],
    [AS_IF([test x"$rra_use_JANSSON" = xtrue],
        [_RRA_LIB_JANSSON_INTERNAL([true])],
        [_RRA_LIB_JANSSON_INTERNAL([false])])])
 AS_IF([test x"$JANSSON_LIBS" != x],
    [rra_use_JANSSON=true
     AC_DEFINE([HAVE_JANSSON], 1, [Define if Jansson is available.])])])
