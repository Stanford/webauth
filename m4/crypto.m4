dnl crypto.m4 -- Find a suitable crypto library.
dnl $Id$
dnl
dnl Defines the macro WEBAUTH_LIB_CRYPTO, which probes for a suitable crypto
dnl library and defines the output variable CRYPTO_LIBS to the appropriate
dnl linker commands.

AC_DEFUN([WEBAUTH_LIB_CRYPTO],
[AC_ARG_WITH([krb5],
             AC_HELP_STRING([--with-openssl=PATH], [Path to OpenSSL install]),
             [if test x"$withval" != xno ; then
                 CRYPTO_LDFLAGS=-L$withval/lib
                 CRYPTO_CPPFLAGS=-I$withval/include
              fi])
WEBAUTH_LDFLAGS_save=$LDFLAGS
LDFLAGS="$LDFLAGS $CRYPTO_LIBS"
CRYPTO_LIBS=
AC_CHECK_LIB(crypto, HMAC_Init, [CRYPTO_LIBS=-lcrypto])
LDFLAGS="$WEBAUTH_LDFLAGS_save"
CRYPTO_LIBS=`echo "$CRYPTO_LDFLAGS $CRYPTO_LIBS" | sed 's/^  *//'`
AC_SUBST(CRYPTO_LIBS)
AC_SUBST(CRYPTO_CPPFLAGS)])
