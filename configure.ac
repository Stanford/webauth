dnl Process this file with autoconf to produce a configure script.
dnl $Id$

dnl Put more complex macros into separate files to make them easier to
dnl maintain.  (Also good for macros that should be used in other projects as
dnl well.)
m4_include([m4/int32.m4])
m4_include([m4/krb5.m4])

AC_REVISION($Revision$)
AC_PREREQ(2.53)
AC_INIT([src/libwebauth/webauth.h.in])
AC_CONFIG_AUX_DIR([tools])

dnl Make sure $prefix is set so that we can use it internally.
test x"$prefix" = xNONE && prefix="$ac_default_prefix"

dnl Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB

dnl Checks for libraries

dnl The rat's nest of networking libraries.  The common cases are not to
dnl need any extra libraries, or to need -lsocket -lnsl.  We need to avoid
dnl linking with libnsl unless we need it, though, since on some OSes where
dnl it isn't necessary it will totally break networking.  Unisys also
dnl includes gethostbyname in libsocket but needs libnsl for socket().
AC_SEARCH_LIBS(gethostbyname, nsl)
AC_SEARCH_LIBS(socket, socket, ,
    [AC_CHECK_LIB(nsl, socket, LIBS="$LIBS -lsocket -lnsl", , -lsocket)])

dnl FIXME: These probably need to be cleaned up.

dnl OpenSSL

AC_CHECK_LIB(crypto, HMAC_Init, [AC_SUBST(OPENSSL_CRYPTO_LIB, [-lcrypto])])
AC_CHECK_LIB(ssl, SSL_Library_init, [AC_SUBST(OPENSSL_SSL_LIB, [-lssl])])

AC_CHECK_LIB(crypto, AES_cbc_encrypt, 
    [AC_MSG_NOTICE([using AES support in -lcrypto])],
    [ AC_MSG_NOTICE([building AES support in -lwebauth])
      AC_SUBST(WEBAUTH_AES_OBJS, ["aes_cbc.o  aes_cfb.o  aes_core.o  aes_ctr.o  aes_ecb.o aes_misc.o  aes_ofb.o"])])

dnl Kerberos v5
WEBAUTH_LIB_KRB5

# Checks for header files.
AC_HEADER_STDC

dnl Checks for types.
WEBAUTH_TYPE_INT32_T

dnl Checks for structures.
dnl Checks for compiler characteristics.

dnl Crank up warnings if using GCC
if test "$GCC" = "yes" ; then
    CFLAGS="-Wall $CFLAGS"
fi

dnl Checks for library functions.
dnl Checks for system services.

dnl Output files.
AC_CONFIG_HEADERS([src/common/include/conf.h])
AC_CONFIG_FILES([
    Makefile
    src/Makefile
    src/bindings/perl/WebAuth/Makefile.PL
    src/libwebauth/Makefile
    src/libwebauth/webauth.h
    src/utils/Makefile
    tests/Makefile
    tests/libwebauth/Makefile
])
AC_OUTPUT
