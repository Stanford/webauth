dnl sident.m4 -- Find the sident libraries.
dnl $Id$
dnl
dnl Defines the macro WEBAUTH_LIB_SIDENT, which probes for the sident libraries
dnl and defines the output variables SIDENT_CPPFLAGS and SIDENT_LIBS to the
dnl appropriate preprocessor and linker flags.

AC_DEFUN([WEBAUTH_LIB_SIDENT],
[AC_ARG_WITH([sident],
             AC_HELP_STRING([--with-sident=PATH], [Path to sident install]),
             [if test x"$withval" != xno ; then
                 SIDENT_LDFLAGS=-L$withval/lib
                 SIDENT_CPPFLAGS=-I$withval/include
              fi])
WEBAUTH_LDFLAGS_save=$LDFLAGS
LDFLAGS="$LDFLAGS $SIDENT_LDFLAGS"
SIDENT_LIBS=
AC_CHECK_LIB([sident], [ident_set_authtype], [SIDENT_LIBS=-lsident], , [$KRB5_LIBS])
LDFLAGS=$WEBAUTH_LDFLAGS_save
SIDENT_LIBS=`echo "$SIDENT_LDFLAGS $SIDENT_LIBS" | sed 's/^  *//'`
AC_SUBST(SIDENT_LIBS)
AC_SUBST(SIDENT_CPPFLAGS)])
