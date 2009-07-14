dnl apache.m4 -- Find the root of the Apache installation.
dnl
dnl Defines the macro WEBAUTH_APACHE, which allows the user to specify the
dnl root of the Apache installation and defines the output variable APXS to
dnl point to the full path to apxs.  Also sets the APACHE_ROOT output variable
dnl to the root of the Apache installation.  If the --with-apache option isn't
dnl given, apxs2 and apxs is searched for on the user's path (unless
dnl --with-apxs is given) and /usr/local/apache2 is used as the Apache root.
dnl
dnl Written by Russ Allbery <rra@stanford.edu>
dnl Copyright 2002, 2003, 2004, 2006, 2009
dnl     Board of Trustees, Leland Stanford Jr. University
dnl
dnl See LICENSE for licensing terms.

AC_DEFUN([WEBAUTH_APACHE],
[APACHE_ROOT=/usr/local/apache2
AC_ARG_WITH([apache],
    AC_HELP_STRING([--with-apache=PATH], [Path to Apache 2.x install]),
    [if test x"$withval" != xno && test x"$withval" != xyes ; then
        APACHE_ROOT=$withval
     fi])
AC_ARG_WITH([apxs],
    AC_HELP_STRING([--with-apxs=PATH], [Path to Apache 2.x apxs script]),
    [if test x"$withval" != xno && test x"$withval" != xyes ; then
        APXS=$withval
        AC_SUBST(APXS)
     else
        AC_PATH_PROGS([APXS], [apxs2 apxs], [apxs], [$APACHE_ROOT/bin:$PATH])
     fi],
    [AC_PATH_PROGS([APXS], [apxs2 apxs], [apxs], [$APACHE_ROOT/bin:$PATH])])
AC_SUBST(APACHE_ROOT)])
