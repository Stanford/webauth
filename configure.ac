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

##### FIXME: these probably need to be cleaned up

# openssl

AC_CHECK_LIB(crypto, HMAC_Init, [AC_SUBST(OPENSSL_CRYPTO_LIB, [-lcrypto])])
AC_CHECK_LIB(ssl, SSL_Library_init, [AC_SUBST(OPENSSL_SSL_LIB, [-lssl])])

AC_CHECK_LIB(crypto, AES_cbc_encrypt, 
    [AC_MSG_NOTICE([using AES support in -lcrypto])],
    [ AC_MSG_NOTICE([building AES support in -lwebauth])
      AC_SUBST(WEBAUTH_AES_OBJS, ["aes_cbc.o  aes_cfb.o  aes_core.o  aes_ctr.o  aes_ecb.o aes_misc.o  aes_ofb.o"])])

# krb5

AC_CHECK_LIB(k5crypto, krb5_string_to_key, [AC_SUBST(KRB5_CRYPTO_LIB, [-lk5crypto])])
AC_CHECK_LIB(krb5, krb5_init_context, [AC_SUBST(KRB5_LIB, [-lkrb5])])
AC_CHECK_LIB(com_err, error_message, [AC_SUBST(COM_ERR_LIB, [-lcom_err])])

# checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(unistd.h)

# checks for types

AC_DEFUN([WEBAUTH_TYPE_CACHE], translit([ac_cv_sizeof_$1], [ *], [_p]))

dnl A modified version of AC_CHECK_SIZEOF that doesn't always AC_DEFINE, but
dnl instead lets you execute shell code based on success or failure.  This is
dnl to avoid config.h clutter.
AC_DEFUN([WEBAUTH_IF_SIZEOF],
[AC_MSG_CHECKING([size of $1])
AC_CACHE_VAL(WEBAUTH_TYPE_CACHE([$1]),
[AC_TRY_RUN([#include <stdio.h>
main()
{
    FILE *f = fopen("conftestval", "w");
    if (!f) exit(1);
    fprintf(f, "%d\n", sizeof($1));
    exit(0);
}], WEBAUTH_TYPE_CACHE([$1])=`cat conftestval`, WEBAUTH_TYPE_CACHE([$1])=0,
ifelse([$2], , , WEBAUTH_TYPE_CACHE([$1])=$2))
])dnl
AC_MSG_RESULT($WEBAUTH_TYPE_CACHE([$1]))
if test x"$WEBAUTH_TYPE_CACHE([$1])" = x"$3" ; then
    ifelse([$4], , :, [$4])
else
    ifelse([$5], , :, [$5])
fi
])

dnl Find a 32 bit type, by trying likely candidates.  First, check for the C9X
dnl int32_t, then look for something else with a size of four bytes.
WEBAUTH_IF_SIZEOF(int, 4, 4, WEBAUTH_INT32=int,
    [WEBAUTH_IF_SIZEOF(long, 4, 4, WEBAUTH_INT32=long,
        [WEBAUTH_IF_SIZEOF(short, 2, 4, WEBAUTH_INT32=short)])])

AC_CHECK_TYPE(int32_t, ,
    [AC_DEFINE_UNQUOTED([int32_t], [$WEBAUTH_INT32],
        [Define to a 4-byte signed type if <inttypes.h> does not define.])])
AC_CHECK_TYPE(uint32_t, ,
    [AC_DEFINE_UNQUOTED([uint32_t], [unsigned $WEBAUTH_INT32],
        [Define to a 4-byte unsigned type if <inttypes.h> does not define.])])

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
                 src/utils/Makefile
                 tests/Makefile tests/libwebauth/Makefile
])
AC_OUTPUT
