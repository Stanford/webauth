dnl apache.m4 -- Find the root of the Apache installation.
dnl $Id$
dnl
dnl Defines the macro WEBAUTH_APACHE, which allows the user to specify the
dnl root of the Apache installation and defines the output variable APXS to
dnl point to the full path to apxs.  Also sets the APACHE_ROOT output variable
dnl to the root of the Apache installation.  If the --with-apache option isn't
dnl given, apxs is searched for on the user's path (unless --with-apxs is
dnl given) and /usr/local/apache2 is used as the Apache root.

AC_DEFUN([WEBAUTH_APACHE],
[APACHE_ROOT=/usr/local/apache2
AC_ARG_WITH([apache],
    AC_HELP_STRING([--with-apache=PATH], [Path to Apache 2.x install]),
    [if test x"$withval" != xno ; then
        APACHE_ROOT=$withval
     fi])
AC_ARG_WITH([apxs],
    AC_HELP_STRING([--with-apxs=PATH], [Path to Apache 2.x apxs script]),
    [if test x"$withval" != xno ; then
        APXS=$withval
        AC_SUBST(APXS)
     else
        AC_PATH_PROG([APXS], [apxs], [apxs], [$APACHE_ROOT/bin:$PATH])
     fi])
AC_SUBST(APACHE_ROOT)])
