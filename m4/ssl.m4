dnl ssl.m4 -- Probe for the OpenSSL libraries.
dnl
dnl Defines the macro WEBAUTH_LIB_SSL, which probes for the OpenSSL libraries
dnl and defines SSL_CPPFLAGS and SSL_LIBS.  It also defines CRYPTO_CPPFLAGS
dnl and CRYPTO_LIBS for those programs that only need libcrypto.
dnl
dnl Written by Russ Allbery <rra@stanford.edu>
dnl Copyright 2002, 2003, 2004, 2006, 2009
dnl     Board of Trustees, Leland Stanford Jr. University
dnl
dnl See LICENSE for licensing terms.

AC_DEFUN([WEBAUTH_LIB_SSL],
[AC_ARG_WITH([openssl],
    AC_HELP_STRING([--with-openssl=PATH], [Path to OpenSSL install]),
    [if test x"$withval" != xno && test x"$withval" != xyes ; then
        SSL_LDFLAGS=-L$withval/lib
        SSL_CPPFLAGS=-I$withval/include
     fi])
WEBAUTH_LDFLAGS_save="$LDFLAGS"
LDFLAGS="$LDFLAGS $SSL_LDFLAGS"
CRYPTO_LIBS=
SSL_LIBS=
AC_CHECK_LIB([crypto], [AES_cbc_encrypt], [CRYPTO_LIBS=-lcrypto],
    AC_MSG_ERROR([WebAuth needs OpenSSL 0.9.7 or later for AES support]))
AC_CHECK_LIB([ssl], [SSL_library_init], [SSL_LIBS=-lssl], , [-lcrypto])
LDFLAGS="$WEBAUTH_LDFLAGS_save"
CRYPTO_CPPFLAGS="$SSL_CPPFLAGS"
CRYPTO_LIBS=`echo "$SSL_LDFLAGS $CRYPTO_LIBS" | sed 's/^  *//'`
if test x"$reduced_depends" = xtrue ; then
    SSL_LIBS=`echo "$SSL_LDFLAGS $SSL_LIBS" | sed 's/^  *//'`
else
    SSL_LIBS=`echo "$SSL_LDFLAGS $SSL_LIBS $CRYPTO_LIBS" | sed 's/^  *//'`
fi
AC_SUBST(CRYPTO_LIBS)
AC_SUBST(CRYPTO_CPPFLAGS)
AC_SUBST(SSL_LIBS)
AC_SUBST(SSL_CPPFLAGS)])])
