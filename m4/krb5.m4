dnl krb5.m4 -- Find the Kerberos v5 libraries.
dnl $Id$
dnl
dnl Defines the macro WEBAUTH_LIB_KRB5, which probes for the Kerberos v5
dnl libraries and defines the output variable KRB5_LIBS to the appropriate
dnl linker commands.

AC_DEFUN([WEBAUTH_LIB_KRB5],
[KRB5_LIBS=
AC_CHECK_LIB([com_err], [error_message], [KRB5_LIBS=-lcom_err])
AC_CHECK_LIB([k5crypto], [krb5_string_to_key],
    [KRB5_LIBS="-lk5crypto $KRB5_LIBS"])
AC_CHECK_LIB([krb5], [krb5_init_context],
    [KRB5_LIBS="-lkrb5 $KRB5_LIBS"])
AC_SUBST(KRB5_LIBS)])
