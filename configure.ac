# Process this file with autoconf to produce a configure script.
AC_INIT(src/libwebauth/webauth.h)

# Make sure $prefix is set so that we can use it internally.
test x"$prefix" = xNONE && prefix="$ac_default_prefix"

# checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB

# checks for libraries
AC_SEARCH_LIBS(gethostbyname, nsl)
AC_SEARCH_LIBS(connect, socket)

# openssl

AC_CHECK_LIB(crypto, HMAC_Init, [AC_SUBST(OPENSSL_CRYPTO_LIB, [-lcrypto])])
AC_CHECK_LIB(ssl, SSL_Library_init, [AC_SUBST(OPENSSL_SSL_LIB, [-lssl])])

AC_CHECK_LIB(crypto, AES_cbc_encrypt, 
    [AC_MSG_NOTICE([using AES support in -lcrypto])],
    [ AC_MSG_NOTICE([building AES support in -lwebauth])
      AC_SUBST(WEBAUTH_AES_OBJS, ["aes_cbc.o  aes_cfb.o  aes_core.o  aes_ctr.o  aes_ecb.o aes_misc.o  aes_ofb.o"])])

# checks for header files.
AC_HEADER_STDC
AC_HEADER_DIRENT
AC_CHECK_HEADERS(unistd.h)

# checks for types
# checks for structures
# checks for compiler characteristics

# crank up warnings if using GCC
if test "$GCC" = "yes"; then
  CFLAGS="-Wall $CFLAGS"
fi
# checks for library functions
# checks for system services

# output files

AC_CONFIG_HEADERS([src/common/include/conf.h])

AC_CONFIG_FILES([Makefile src/Makefile src/libwebauth/Makefile
                 tests/Makefile tests/libwebauth/Makefile
])
AC_OUTPUT