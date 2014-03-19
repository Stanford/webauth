dnl Find the compiler and linker flags for APR.
dnl
dnl Finds the compiler and linker flags for building with APR.  Provides the
dnl --with-apr, --with-apr-lib, and --with-apr-include configure option to
dnl specify non-standard paths to the APR libraries.
dnl
dnl Provides the macro RRA_LIB_APR and sets the substitution variables
dnl APR_CPPFLAGS, APR_LDFLAGS, and APR_LIBS.  Also provides RRA_LIB_APR_SWITCH
dnl to set CPPFLAGS, LDFLAGS, and LIBS to include the Apache libraries, saving
dnl the current values first, and RRA_LIB_APR_RESTORE to restore those
dnl settings to before the last RRA_LIB_APR_SWITCH.
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
dnl RRA_LIB_APR_RESTORE, around tests.
AC_DEFUN([RRA_LIB_APR_SWITCH],
[rra_apr_save_CPPFLAGS="$CPPFLAGS"
 rra_apr_save_LDFLAGS="$LDFLAGS"
 rra_apr_save_LIBS="$LIBS"
 CPPFLAGS="$APR_CPPFLAGS $CPPFLAGS"
 LDFLAGS="$APR_LDFLAGS $LDFLAGS"
 LIBS="$APR_LIBS $LIBS"])

dnl Restore CPPFLAGS, LDFLAGS, and LIBS to their previous values (before
dnl RRA_LIB_APR_SWITCH was called).
AC_DEFUN([RRA_LIB_APR_RESTORE],
[CPPFLAGS="$rra_apr_save_CPPFLAGS"
 LDFLAGS="$rra_apr_save_LDFLAGS"
 LIBS="$rra_apr_save_LIBS"])

dnl Set APR_CPPFLAGS and APR_LDFLAGS based on rra_apr_root, rra_apr_libdir,
dnl and rra_apr_includedir.
AC_DEFUN([_RRA_LIB_APR_PATHS],
[AS_IF([test x"$rra_apr_libdir" != x],
    [APR_LDFLAGS="-L$rra_apr_libdir"],
    [AS_IF([test x"$rra_apr_root" != x],
        [RRA_SET_LDFLAGS([APR_LDFLAGS], [$rra_apr_root])])])
 AS_IF([test x"$rra_apr_includedir" != x],
    [APR_CPPFLAGS="-I$rra_apr_includedir"],
    [AS_IF([test x"$rra_apr_root" != x],
        [AS_IF([test x"$rra_apr_root" != x/usr],
            [APR_CPPFLAGS="-I${rra_apr_root}/include"])])])])

dnl The main macro for determining the flags for Apache modules.
AC_DEFUN([RRA_LIB_APR],
[AC_REQUIRE([RRA_ENABLE_REDUCED_DEPENDS])
 rra_apr_root=
 rra_apr_libdir=
 rra_apr_includedir=
 APR_CPPFLAGS=
 APR_LDFLAGS=
 APR_LIBS=
 AC_SUBST([APR_CPPFLAGS])
 AC_SUBST([APR_LDFLAGS])
 AC_SUBST([APR_LIBS])

 AC_ARG_WITH([apr],
    [AS_HELP_STRING([--with-apr=DIR],
        [Location of APR headers and libraries])],
    [AS_IF([test x"$withval" != xyes && test x"$withval" != xno],
        [rra_apr_root="$withval"])])
 AC_ARG_WITH([apr-include],
    [AS_HELP_STRING([--with-apr-include=DIR],
        [Location of APR headers])],
    [AS_IF([test x"$withval" != xyes && test x"$withval" != xno],
        [rra_apr_includedir="$withval"])])
 AC_ARG_WITH([apr-lib],
    [AS_HELP_STRING([--with-apr-lib=DIR],
        [Location of APR libraries])],
    [AS_IF([test x"$withval" != xyes && test x"$withval" != xno],
        [rra_apr_libdir="$withval"])])

 AC_ARG_VAR([APR_CONFIG], [Path to apr-1-config or apr-config])
 AC_PATH_PROGS([APR_CONFIG], [apr-1-config apr-config], [false])
 AS_IF([test x"$APR_CONFIG" != xfalse],
    [APR_CPPFLAGS="$APR_CPPFLAGS "`"$APR_CONFIG" --includes`
     AS_IF([test x"$rra_reduced_depends" = xtrue],
        [APR_LIBS=`"$APR_CONFIG" --link-ld`],
        [APR_LIBS=`"$APR_CONFIG" --link-ld --libs`])],
    [_RRA_LIB_APR_PATHS
     RRA_LIB_APR_SWITCH
     AC_CHECK_LIB([apr-1], [apr_initialize], [APR_LIBS="-lapr-1"],
        [AC_MSG_ERROR([cannot find usable APR library])])
     RRA_LIB_APR_RESTORE])])
