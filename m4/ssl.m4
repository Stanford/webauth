dnl ssl.m4 -- Probe for the OpenSSL libraries.
dnl $Id$
dnl
dnl Defines the macro WEBAUTH_LIB_SSL, which probes for the OpenSSL libraries
dnl and defines SSL_CPPFLAGS and SSL_LIBS.  It also defines CRYPTO_CPPFLAGS
dnl and CRYPTO_LIBS for those programs that only need libcrypto.
dnl
dnl Also define the macro WEBAUTH_FUNC_AES, which looks for the AES routines
dnl in OpenSSL's libcrypto and if not found, sets WEBAUTH_AES_OBJS to the
dnl required object files for AES support.

AC_DEFUN([WEBAUTH_LIB_SSL],
[AC_ARG_WITH([openssl],
             AC_HELP_STRING([--with-openssl=PATH], [Path to OpenSSL install]),
             [if test x"$withval" != xno ; then
                 SSL_LDFLAGS=-L$withval/lib
                 SSL_CPPFLAGS=-I$withval/include
              fi])
WEBAUTH_LDFLAGS_save=$LDFLAGS
LDFLAGS="$LDFLAGS $SSL_LDFLAGS"
CRYPTO_LIBS=
SSL_LIBS=
AC_CHECK_LIB([crypto], [HMAC_Init], [CRYPTO_LIBS=-lcrypto])
AC_CHECK_LIB([ssl], [SSL_library_init], [SSL_LIBS=-lssl], , [-lcrypto])
LDFLAGS="$WEBAUTH_LDFLAGS_save"
CRYPTO_CPPFLAGS=$SSL_CPPFLAGS
CRYPTO_LIBS=`echo "$SSL_LDFLAGS $CRYPTO_LIBS" | sed 's/^  *//'`
SSL_LIBS=`echo "$SSL_LDFLAGS $CRYPTO_LIBS $SSL_LIBS" | sed 's/^  *//'`
AC_SUBST(CRYPTO_LIBS)
AC_SUBST(CRYPTO_CPPFLAGS)
AC_SUBST(SSL_LIBS)
AC_SUBST(SSL_CPPFLAGS)])

dnl Check for an implementation of AES, and if not found in the OpenSSL
dnl libraries, set WEBAUTH_AES_OBJS to the *.o files required for it.
AC_DEFUN([WEBAUTH_FUNC_AES],
[aes="aes_cbc.o aes_cfb.o aes_core.o aes_ctr.o aes_ecb.o aes_misc.o aes_ofb.o"
WEBAUTH_LIBS_save=$LIBS
LIBS="$CRYPTO_LIBS $LIBS"
AC_CHECK_FUNC(AES_cbc_encrypt,
    [AC_MSG_NOTICE([using AES support in -lcrypto])],
    [AC_MSG_NOTICE([building AES support in -lwebauth])
     WEBAUTH_AES_OBJS=$aes
     AC_SUBST(WEBAUTH_AES_OBJS)])
LIBS=$WEBAUTH_LIBS_save])
