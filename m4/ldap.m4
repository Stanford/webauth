dnl krb5.m4 -- Find the Kerberos v5 libraries.
dnl $Id$
dnl
dnl Defines the macro WEBAUTH_LIB_KRB5, which probes for the Kerberos v5
dnl libraries and defines the output variables KRB5_LIBS and KRB5_CPPFLAGS to
dnl the appropriate preprocessor and linker flags.

AC_DEFUN([WEBAUTH_LIB_LDAP],
[AC_ARG_WITH([ldap],
             AC_HELP_STRING([--with-ldap=PATH], [Path to LDAP install]),
             [if test x"$withval" != xno ; then
                 LDAP_LDFLAGS=-L$withval/lib
                 LDAP_CPPFLAGS=-I$withval/include
              fi])
WEBAUTH_LDFLAGS_save=$LDFLAGS
LDFLAGS="$LDFLAGS $LDAP_LDFLAGS"
LDAP_LIBS=
AC_CHECK_LIB([lber], [ber_dump], [LDAP_LIBS=-llber])
AC_CHECK_LIB([ldap], [ldap_open], [LDAP_LIBS="-lldap $LDAP_LIBS"])
LDFLAGS=$WEBAUTH_LDFLAGS_save
LDAP_LIBS=`echo "$LDAP_LDFLAGS $LDAP_LIBS" | sed 's/^  *//'`
AC_SUBST(LDAP_LIBS)
AC_SUBST(LDAP_CPPFLAGS)])
