dnl ldap.m4 -- Find the OpenLDAP libraries
dnl $Id$
dnl
dnl Defines the macro WEBAUTH_LIB_LDAP, which probes for the OpenLDAP
dnl libraries and defines the output variables LDAP_LIBS and LDAP_CPPFLAGS to
dnl the appropriate preprocessor and linker flags.

AC_DEFUN([WEBAUTH_LIB_LDAP],
[AC_ARG_WITH([ldap],
    AC_HELP_STRING([--with-ldap=PATH], [Path to LDAP install]),
    [if test x"$withval" != xno && test x"$withval" != xyes ; then
        LDAP_LDFLAGS=-L$withval/lib
        LDAP_CPPFLAGS=-I$withval/include
     fi])
WEBAUTH_LDFLAGS_save=$LDFLAGS
LDFLAGS="$LDFLAGS $LDAP_LDFLAGS"
LDAP_LIBS=
if text x"$reduced_depends" != xtrue ; then
    AC_CHECK_LIB([lber], [ber_dump], [LDAP_LIBS=-llber])
fi
AC_CHECK_LIB([ldap], [ldap_open], [LDAP_LIBS="-lldap $LDAP_LIBS"], , -llber)
LDFLAGS=$WEBAUTH_LDFLAGS_save
LDAP_LIBS=`echo "$LDAP_LDFLAGS $LDAP_LIBS" | sed 's/^  *//'`
AC_SUBST(LDAP_LIBS)
AC_SUBST(LDAP_CPPFLAGS)])
