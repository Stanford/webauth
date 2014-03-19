dnl Find the compiler and linker flags for OpenLDAP.
dnl
dnl Finds the compiler and linker flags for linking with the LDAP library.
dnl Provides the --with-ldap, --with-ldap-lib, and --with-ldap-include
dnl configure options to specify non-standard paths to the LDAP libraries.
dnl
dnl Provides the macro RRA_LIB_LDAP and sets the substitution variables
dnl LDAP_CPPFLAGS, LDAP_LDFLAGS, and LDAP_LIBS.  Also provides
dnl RRA_LIB_LDAP_SWITCH to set CPPFLAGS, LDFLAGS, and LIBS to include the LDAP
dnl libraries, saving the current values first, and RRA_LIB_LDAP_RESTORE to
dnl restore those settings to before the last RRA_LIB_LDAP_SWITCH.
dnl
dnl Depends on RRA_SET_LDFLAGS and RRA_ENABLE_REDUCED_DEPENDS.
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

dnl Save the current CPPFLAGS, LDFLAGS, and LIBS settings and switch to
dnl versions that include the LDAP flags.  Used as a wrapper, with
dnl RRA_LIB_LDAP_RESTORE, around tests.
AC_DEFUN([RRA_LIB_LDAP_SWITCH],
[rra_ldap_save_CPPFLAGS="$CPPFLAGS"
 rra_ldap_save_LDFLAGS="$LDFLAGS"
 rra_ldap_save_LIBS="$LIBS"
 CPPFLAGS="$LDAP_CPPFLAGS $CPPFLAGS"
 LDFLAGS="$LDAP_LDFLAGS $LDFLAGS"
 LIBS="$LDAP_LIBS $LIBS"])

dnl Restore CPPFLAGS, LDFLAGS, and LIBS to their previous values (before
dnl RRA_LIB_LDAP_SWITCH was called).
AC_DEFUN([RRA_LIB_LDAP_RESTORE],
[CPPFLAGS="$rra_ldap_save_CPPFLAGS"
 LDFLAGS="$rra_ldap_save_LDFLAGS"
 LIBS="$rra_ldap_save_LIBS"])

dnl Set LDAP_CPPFLAGS and LDAP_LDFLAGS based on rra_ldap_root,
dnl rra_ldap_libdir, and rra_ldap_includedir.
AC_DEFUN([_RRA_LIB_LDAP_PATHS],
[AS_IF([test x"$rra_ldap_libdir" != x],
    [LDAP_LDFLAGS="-L$rra_ldap_libdir"],
    [AS_IF([test x"$rra_ldap_root" != x],
        [RRA_SET_LDFLAGS([LDAP_LDFLAGS], [$rra_ldap_root])])])
 AS_IF([test x"$rra_ldap_includedir" != x],
    [LDAP_CPPFLAGS="-I$rra_ldap_includedir"],
    [AS_IF([test x"$rra_ldap_root" != x],
        [AS_IF([test x"$rra_ldap_root" != x/usr],
            [LDAP_CPPFLAGS="-I${rra_ldap_root}/include"])])])])

dnl The main macro.
AC_DEFUN([RRA_LIB_LDAP],
[AC_REQUIRE([RRA_ENABLE_REDUCED_DEPENDS])
 rra_ldap_root=
 rra_ldap_libdir=
 rra_ldap_includedir=
 LDAP_CPPFLAGS=
 LDAP_LDFLAGS=
 LDAP_LIBS=
 AC_SUBST([LDAP_CPPFLAGS])
 AC_SUBST([LDAP_LDFLAGS])
 AC_SUBST([LDAP_LIBS])

 AC_ARG_WITH([ldap],
    [AS_HELP_STRING([--with-ldap=DIR],
        [Location of LDAP headers and libraries])],
    [AS_IF([test x"$withval" != xyes && test x"$withval" != xno],
        [rra_ldap_root="$withval"])])
 AC_ARG_WITH([ldap-include],
    [AS_HELP_STRING([--with-ldap-include=DIR],
        [Location of LDAP headers])],
    [AS_IF([test x"$withval" != xyes && test x"$withval" != xno],
        [rra_ldap_includedir="$withval"])])
 AC_ARG_WITH([ldap-lib],
    [AS_HELP_STRING([--with-ldap-lib=DIR],
        [Location of LDAP libraries])],
    [AS_IF([test x"$withval" != xyes && test x"$withval" != xno],
        [rra_ldap_libdir="$withval"])])

 _RRA_LIB_LDAP_PATHS
 RRA_LIB_LDAP_SWITCH
 AS_IF([test x"$rra_reduced_depends" != xtrue],
    [AC_CHECK_LIB([lber], [ber_dump], [LDAP_LIBS=-llber])])
 AC_CHECK_LIB([ldap], [ldap_open], [LDAP_LIBS="-lldap $LDAP_LIBS"],
    [AC_MSG_ERROR([cannot find usable LDAP library])],
    [$LDAP_LIBS])
 RRA_LIB_LDAP_RESTORE])
