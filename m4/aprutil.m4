dnl Find the compiler and linker flags for APR-Util.
dnl
dnl Finds the compiler and linker flags for building with APR-Util.  Provides
dnl the --with-aprutil, --with-aprutil-lib, and --with-aprutil-include
dnl configure option to specify non-standard paths to the APR-Util libraries.
dnl
dnl Provides the macro RRA_LIB_APRUTIL and sets the substitution variables
dnl APRUTIL_CPPFLAGS, APRUTIL_LDFLAGS, and APRUTIL_LIBS.  Also provides
dnl RRA_LIB_APRUTIL_SWITCH to set CPPFLAGS, LDFLAGS, and LIBS to include the
dnl Apache libraries, saving the current values first, and
dnl RRA_LIB_APRUTIL_RESTORE to restore those settings to before the last
dnl RRA_LIB_APRUTIL_SWITCH.
dnl
dnl Depends on RRA_SET_LDFLAGS and RRA_ENABLE_REDUCED_DEPENDS.
dnl
dnl The canonical version of this file is maintained in the rra-c-util
dnl package, available at <http://www.eyrie.org/~eagle/software/rra-c-util/>.
dnl
dnl Written by Russ Allbery <eagle@eyrie.org>
dnl Copyright 2010, 2011
dnl     The Board of Trustees of the Leland Stanford Junior University
dnl
dnl This file is free software; the authors give unlimited permission to copy
dnl and/or distribute it, with or without modifications, as long as this
dnl notice is preserved.

dnl Save the current CPPFLAGS, LDFLAGS, and LIBS settings and switch to
dnl versions that include the Apache flags.  Used as a wrapper, with
dnl RRA_LIB_APRUTIL_RESTORE, around tests.
AC_DEFUN([RRA_LIB_APRUTIL_SWITCH],
[rra_aprutil_save_CPPFLAGS="$CPPFLAGS"
 rra_aprutil_save_LDFLAGS="$LDFLAGS"
 rra_aprutil_save_LIBS="$LIBS"
 CPPFLAGS="$APRUTIL_CPPFLAGS $CPPFLAGS"
 LDFLAGS="$APRUTIL_LDFLAGS $LDFLAGS"
 LIBS="$APRUTIL_LIBS $LIBS"])

dnl Restore CPPFLAGS, LDFLAGS, and LIBS to their previous values (before
dnl RRA_LIB_APRUTIL_SWITCH was called).
AC_DEFUN([RRA_LIB_APRUTIL_RESTORE],
[CPPFLAGS="$rra_aprutil_save_CPPFLAGS"
 LDFLAGS="$rra_aprutil_save_LDFLAGS"
 LIBS="$rra_aprutil_save_LIBS"])

dnl Set APRUTIL_CPPFLAGS and APRUTIL_LDFLAGS based on rra_aprutil_root,
dnl rra_aprutil_libdir, and rra_aprutil_includedir.
AC_DEFUN([_RRA_LIB_APRUTIL_PATHS],
[AS_IF([test x"$rra_aprutil_libdir" != x],
    [APRUTIL_LDFLAGS="-L$rra_aprutil_libdir"],
    [AS_IF([test x"$rra_aprutil_root" != x],
        [RRA_SET_LDFLAGS([APRUTIL_LDFLAGS], [$rra_aprutil_root])])])
 AS_IF([test x"$rra_aprutil_includedir" != x],
    [APRUTIL_CPPFLAGS="-I$rra_aprutil_includedir"],
    [AS_IF([test x"$rra_aprutil_root" != x],
        [AS_IF([test x"$rra_aprutil_root" != x/usr],
            [APRUTIL_CPPFLAGS="-I${rra_aprutil_root}/include"])])])])

dnl The main macro for determining the flags for Apache modules.
AC_DEFUN([RRA_LIB_APRUTIL],
[AC_REQUIRE([RRA_ENABLE_REDUCED_DEPENDS])
 rra_aprutil_root=
 rra_aprutil_libdir=
 rra_aprutil_includedir=
 APRUTIL_CPPFLAGS=
 APRUTIL_LDFLAGS=
 APRUTIL_LIBS=
 AC_SUBST([APRUTIL_CPPFLAGS])
 AC_SUBST([APRUTIL_LDFLAGS])
 AC_SUBST([APRUTIL_LIBS])

 AC_ARG_WITH([aprutil],
    [AS_HELP_STRING([--with-aprutil=DIR],
        [Location of APR-Util headers and libraries])],
    [AS_IF([test x"$withval" != xyes && test x"$withval" != xno],
        [rra_aprutil_root="$withval"])])
 AC_ARG_WITH([aprutil-include],
    [AS_HELP_STRING([--with-aprutil-include=DIR],
        [Location of APR-Util headers])],
    [AS_IF([test x"$withval" != xyes && test x"$withval" != xno],
        [rra_aprutil_includedir="$withval"])])
 AC_ARG_WITH([aprutil-lib],
    [AS_HELP_STRING([--with-aprutil-lib=DIR],
        [Location of APR-Util libraries])],
    [AS_IF([test x"$withval" != xyes && test x"$withval" != xno],
        [rra_aprutil_libdir="$withval"])])

 AC_ARG_VAR([APU_CONFIG], [Path to apu-1-config or apu-config])
 AC_PATH_PROGS([APU_CONFIG], [apu-1-config apu-config], [false])
 AS_IF([test x"$APU_CONFIG" != xfalse],
    [APRUTIL_CPPFLAGS="$APRUTIL_CPPFLAGS "`"$APU_CONFIG" --includes`
     AS_IF([test x"$rra_reduced_depends" = xtrue],
        [APRUTIL_LIBS=`"$APU_CONFIG" --link-ld --avoid-ldap --avoid-dbm`],
        [APRUTIL_LIBS=`"$APU_CONFIG" --link-ld --libs`])],
    [_RRA_LIB_APRUTIL_PATHS
     RRA_LIB_APRUTIL_SWITCH
     AC_CHECK_LIB([apr-1], [apr_base64_decode], [APRUTIL_LIBS="-lapr-1"],
        [AC_MSG_ERROR([cannot find usable APR library])])
     RRA_LIB_APRUTIL_RESTORE])])
