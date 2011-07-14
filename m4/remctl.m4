dnl Find the compiler and linker flags for remctl.
dnl
dnl Finds the compiler and linker flags for linking with remctl libraries.
dnl Provides the --with-remctl, --with-remctl-include, and --with-remctl-lib
dnl configure options to specify non-standard paths to the remctl headers and
dnl libraries.
dnl
dnl Provides the macro RRA_LIB_REMCTL and sets the substitution variables
dnl REMCTL_CPPFLAGS, REMCTL_LDFLAGS, and REMCTL_LIBS.  Also provides
dnl RRA_LIB_REMCTL_SWITCH to set CPPFLAGS, LDFLAGS, and LIBS to include the
dnl remctl libraries, saving the current values first, and
dnl RRA_LIB_REMCTL_RESTORE to restore those settings to before the last
dnl RRA_LIB_REMCTL_SWITCH.
dnl
dnl Depends on RRA_ENABLE_REDUCED_DEPENDS, RRA_SET_LDFLAGS, and
dnl RRA_LIB_GSSAPI.
dnl
dnl Written by Russ Allbery <rra@stanford.edu>
dnl Copyright 2008, 2009
dnl     The Board of Trustees of the Leland Stanford Junior University
dnl
dnl This file is free software; the authors give unlimited permission to copy
dnl and/or distribute it, with or without modifications, as long as this
dnl notice is preserved.

dnl Save the current CPPFLAGS, LDFLAGS, and LIBS settings and switch to
dnl versions that include the remctl flags.  Used as a wrapper, with
dnl RRA_LIB_REMCTL_RESTORE, around tests.
AC_DEFUN([RRA_LIB_REMCTL_SWITCH],
[rra_remctl_save_CPPFLAGS="$CPPFLAGS"
 rra_remctl_save_LDFLAGS="$LDFLAGS"
 rra_remctl_save_LIBS="$LIBS"
 CPPFLAGS="$REMCTL_CPPFLAGS $CPPFLAGS"
 LDFLAGS="$REMCTL_LDFLAGS $LDFLAGS"
 LIBS="$REMCTL_LIBS $LIBS"])

dnl Restore CPPFLAGS, LDFLAGS, and LIBS to their previous values (before
dnl RRA_LIB_REMCTL_SWITCH was called).
AC_DEFUN([RRA_LIB_REMCTL_RESTORE],
[CPPFLAGS="$rra_remctl_save_CPPFLAGS"
 LDFLAGS="$rra_remctl_save_LDFLAGS"
 LIBS="$rra_remctl_save_LIBS"])

dnl Set REMCTL_CPPFLAGS and REMCTL_LDFLAGS based on rra_remctl_root,
dnl rra_remctl_libdir, and rra_remctl_includedir.
AC_DEFUN([_RRA_LIB_REMCTL_PATHS],
[AS_IF([test x"$rra_remctl_libdir" != x],
    [REMCTL_LDFLAGS="-L$rra_remctl_libdir"],
    [AS_IF([test x"$rra_remctl_root" != x],
        [RRA_SET_LDFLAGS([REMCTL_LDFLAGS], [$rra_remctl_root])])])
 AS_IF([test x"$rra_remctl_includedir" != x],
    [REMCTL_CPPFLAGS="-I$rra_remctl_includedir"],
    [AS_IF([test x"$rra_remctl_root" != x],
        [AS_IF([test x"$rra_remctl_root" != x/usr],
            [REMCTL_CPPFLAGS="-I${rra_remctl_root}/include"])])])])

dnl Sanity-check the results of the remctl library search to be sure we can
dnl really link a remctl program.
AC_DEFUN([_RRA_LIB_REMCTL_CHECK],
[RRA_LIB_REMCTL_SWITCH
 AC_CHECK_FUNC([remctl_open], [],
    [AC_MSG_FAILURE([unable to link with remctl library])])
 RRA_LIB_REMCTL_RESTORE])

dnl The main macro.
AC_DEFUN([RRA_LIB_REMCTL],
[AC_REQUIRE([RRA_ENABLE_REDUCED_DEPENDS])
 rra_remctl_root=
 rra_remctl_libdir=
 rra_remctl_includedir=
 REMCTL_CPPFLAGS=
 REMCTL_LDFLAGS=
 REMCTL_LIBS=
 AC_SUBST([REMCTL_CPPFLAGS])
 AC_SUBST([REMCTL_LDFLAGS])
 AC_SUBST([REMCTL_LIBS])

 AC_ARG_WITH([remctl],
    [AS_HELP_STRING([--with-remctl=DIR],
        [Location of remctl headers and libraries])],
    [AS_IF([test x"$withval" != xyes && test x"$withval" != xno],
        [rra_remctl_root="$withval"])])
 AC_ARG_WITH([remctl-include],
    [AS_HELP_STRING([--with-remctl-include=DIR],
        [Location of remctl headers])],
    [AS_IF([test x"$withval" != xyes && test x"$withval" != xno],
        [rra_remctl_includedir="$withval"])])
 AC_ARG_WITH([remctl-lib],
    [AS_HELP_STRING([--with-remctl-lib=DIR],
        [Location of remctl libraries])],
    [AS_IF([test x"$withval" != xyes && test x"$withval" != xno],
        [rra_remctl_libdir="$withval"])])

 _RRA_LIB_REMCTL_PATHS
 AS_IF([test x"$rra_reduced_depends" = xtrue],
    [REMCTL_LIBS="-lremctl"],
    [RRA_LIB_GSSAPI
     REMCTL_CPPFLAGS="$REMCTL_CPPFLAGS $GSSAPI_CPPFLAGS"
     REMCTL_LDFLAGS="$REMCTL_LDFLAGS $GSSAPI_LDFLAGS"
     REMCTL_LIBS="-lremctl $GSSAPI_LIBS"])
 _RRA_LIB_REMCTL_CHECK])
