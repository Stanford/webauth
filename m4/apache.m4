dnl apache.m4 -- Find the root of the Apache installation.
dnl $Id$
dnl
dnl Defines the macro WEBAUTH_APACHE, which allows the user to specify the
dnl root of the Apache installation and defines the output variable APXS to
dnl point to the full path to apxs.  Right now, nothing else is probed for
dnl except for apxs.  If the --with-apache option isn't given, apxs is
dnl searched for on the user's path.

AC_DEFUN([WEBAUTH_APACHE],
[APACHE_PATH=
AC_ARG_WITH([apache],
    AC_HELP_STRING([--with-apache=PATH], [Path to Apache 2.x install]),
    [if test x"$withval" != xno ; then
        APACHE_PATH=$withval
     fi])
AC_PATH_PROG([APXS], [apxs], [apxs], [$APACHE_PATH:$PATH])])
