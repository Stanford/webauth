dnl krb5.m4 -- Find the Kerberos v5 libraries.
dnl $Id$
dnl
dnl Defines the macro WEBAUTH_LIB_KRB5, which probes for the Kerberos v5
dnl libraries and defines the output variables KRB5_LIBS and KRB5_CPPFLAGS to
dnl the appropriate preprocessor and linker flags.

AC_DEFUN([WEBAUTH_LIB_KRB5],
[AC_ARG_WITH([krb5],
             AC_HELP_STRING([--with-krb5=PATH], [Path to Kerberos v5 install]),
             [if test x"$withval" != xno ; then
                 KRB5_LDFLAGS=-L$withval/lib
                 KRB5_CPPFLAGS=-I$withval/include
              fi])
WEBAUTH_LDFLAGS_save=$LDFLAGS
LDFLAGS="$LDFLAGS $KRB5_LDFLAGS"
KRB5_LIBS=
AC_CHECK_LIB([com_err], [error_message], [KRB5_LIBS=-lcom_err])
AC_CHECK_LIB([k5crypto], [krb5_string_to_key],
    [KRB5_LIBS="-lk5crypto $KRB5_LIBS"], , $KRB5_LIBS)
AC_CHECK_LIB([krb5], [krb5_init_context],
    [KRB5_LIBS="-lkrb5 $KRB5_LIBS"], , $KRB5_LIBS)
WEBAUTH_LIBS_save=$LIBS
LIBS="$KRB5_LIBS $LIBS"
AC_CHECK_FUNCS(krb5_free_keytab_entry_contents)
LDFLAGS=$WEBAUTH_LDFLAGS_save
LIBS=$WEBAUTH_LIBS_save
KRB5_LIBS=`echo "$KRB5_LDFLAGS $KRB5_LIBS" | sed 's/^  *//'`
AC_SUBST(KRB5_LIBS)
AC_SUBST(KRB5_CPPFLAGS)])
