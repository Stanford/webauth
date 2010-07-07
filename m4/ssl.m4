dnl Find the compiler and linker flags for OpenSSL.
dnl
dnl Finds the compiler and linker flags for linking with both the OpenSSL SSL
dnl library and its crypto library.  Provides the --with-openssl,
dnl --with-openssl-lib, and --with-openssl-include configure options to
dnl specify non-standard paths to the OpenSSL libraries.
dnl
dnl Provides the macro RRA_LIB_SSL and sets the substitution variables
dnl SSL_CPPFLAGS, SSL_LDFLAGS, SSL_LIBS, CRYPTO_CPPFLAGS, CRYPTO_LDFLAGS, and
dnl CRYPTO_LIBS.  Also provides RRA_LIB_SSL_SWITCH and RRA_LIB_CRYPT_SWITCH to
dnl set CPPFLAGS, LDFLAGS, and LIBS to include the SSL or crypto libraries,
dnl saving the current values first, and RRA_LIB_SSL_RESTORE and
dnl RRA_LIB_CRYPTO_RESTORE to restore those settings to before the last
dnl RRA_LIB_SSL_SWITCH or RRA_LIB_CRYPTO_SWITCH.
dnl
dnl Depends on RRA_SET_LDFLAGS and RRA_ENABLE_REDUCED_DEPENDS.
dnl
dnl Written by Russ Allbery <rra@stanford.edu>
dnl Copyright 2010 Board of Trustees, Leland Stanford Jr. University
dnl
dnl See LICENSE for licensing terms.

dnl Save the current CPPFLAGS, LDFLAGS, and LIBS settings and switch to
dnl versions that include the SSL flags.  Used as a wrapper, with
dnl RRA_LIB_SSL_RESTORE, around tests.
AC_DEFUN([RRA_LIB_SSL_SWITCH],
[rra_ssl_save_CPPFLAGS="$CPPFLAGS"
 rra_ssl_save_LDFLAGS="$LDFLAGS"
 rra_ssl_save_LIBS="$LIBS"
 CPPFLAGS="$SSL_CPPFLAGS $CPPFLAGS"
 LDFLAGS="$SSL_LDFLAGS $LDFLAGS"
 LIBS="$SSL_LIBS $LIBS"])

dnl Restore CPPFLAGS, LDFLAGS, and LIBS to their previous values (before
dnl RRA_LIB_SSL_SWITCH was called).
AC_DEFUN([RRA_LIB_SSL_RESTORE],
[CPPFLAGS="$rra_ssl_save_CPPFLAGS"
 LDFLAGS="$rra_ssl_save_LDFLAGS"
 LIBS="$rra_ssl_save_LIBS"])

dnl Save the current CPPFLAGS, LDFLAGS, and LIBS settings and switch to
dnl versions that include the crypto flags.  Used as a wrapper, with
dnl RRA_LIB_CRYPTO_RESTORE, around tests.
AC_DEFUN([RRA_LIB_CRYPTO_SWITCH],
[rra_crypto_save_CPPFLAGS="$CPPFLAGS"
 rra_crypto_save_LDFLAGS="$LDFLAGS"
 rra_crypto_save_LIBS="$LIBS"
 CPPFLAGS="$CRYPTO_CPPFLAGS $CPPFLAGS"
 LDFLAGS="$CRYPTO_LDFLAGS $LDFLAGS"
 LIBS="$CRYPTO_LIBS $LIBS"])

dnl Restore CPPFLAGS, LDFLAGS, and LIBS to their previous values (before
dnl RRA_LIB_CRYPTO_SWITCH was called).
AC_DEFUN([RRA_LIB_CRYPTO_RESTORE],
[CPPFLAGS="$rra_crypto_save_CPPFLAGS"
 LDFLAGS="$rra_crypto_save_LDFLAGS"
 LIBS="$rra_crypto_save_LIBS"])

dnl Set SSL_CPPFLAGS, SSL_LDFLAGS, CRYPTO_CPPFLAGS, and CRYPTO_LDFLAGS based
dnl on rra_ssl_root, rra_ssl_libdir, and rra_ssl_includedir.
AC_DEFUN([_RRA_LIB_SSL_PATHS],
[AS_IF([test x"$rra_ssl_libdir" != x],
    [SSL_LDFLAGS="-L$rra_ssl_libdir"],
    [AS_IF([test x"$rra_ssl_root" != x],
        [RRA_SET_LDFLAGS([SSL_LDFLAGS], [$rra_ssl_root])])])
 AS_IF([test x"$rra_ssl_includedir" != x],
    [SSL_CPPFLAGS="-I$rra_ssl_includedir"],
    [AS_IF([test x"$rra_ssl_root" != x],
        [AS_IF([test x"$rra_ssl_root" != x/usr],
            [SSL_CPPFLAGS="-I${rra_ssl_root}/include"])])])
 CRYPTO_CPPFLAGS="$SSL_CPPFLAGS"
 CRYPTO_LDFLAGS="$SSL_LDFLAGS"])

dnl The main macro.
AC_DEFUN([RRA_LIB_SSL],
[AC_REQUIRE([RRA_ENABLE_REDUCED_DEPENDS])
 rra_ssl_root=
 rra_ssl_libdir=
 rra_ssl_includedir=
 CRYPTO_CPPFLAGS=
 CRYPTO_LDFLAGS=
 CRYPTO_LIBS=
 SSL_CPPFLAGS=
 SSL_LDFLAGS=
 SSL_LIBS=
 AC_SUBST([CRYPTO_CPPFLAGS])
 AC_SUBST([CRYPTO_LDFLAGS])
 AC_SUBST([CRYPTO_LIBS])
 AC_SUBST([SSL_CPPFLAGS])
 AC_SUBST([SSL_LDFLAGS])
 AC_SUBST([SSL_LIBS])

 AC_ARG_WITH([openssl],
    [AS_HELP_STRING([--with-openssl=DIR],
        [Location of OpenSSL headers and libraries])],
    [AS_IF([test x"$withval" != xyes && test x"$withval" != xno],
        [rra_ssl_root="$withval"])])
 AC_ARG_WITH([openssl-include],
    [AS_HELP_STRING([--with-openssl-include=DIR],
        [Location of OpenSSL headers])],
    [AS_IF([test x"$withval" != xyes && test x"$withval" != xno],
        [rra_ssl_includedir="$withval"])])
 AC_ARG_WITH([openssl-lib],
    [AS_HELP_STRING([--with-openssl-lib=DIR],
        [Location of SSL libraries])],
    [AS_IF([test x"$withval" != xyes && test x"$withval" != xno],
        [rra_ssl_libdir="$withval"])])

 _RRA_LIB_SSL_PATHS
 RRA_LIB_SSL_SWITCH
 AC_CHECK_LIB([crypto], [AES_cbc_encrypt], [CRYPTO_LIBS=-lcrypto],
    [AC_MSG_ERROR([cannot find usable OpenSSL crypto library])])
 AS_IF([test x"$rra_reduced_depends" = xtrue],
    [AC_CHECK_LIB([ssl], [SSL_library_init], [SSL_LIBS="-lssl $CRYPTO_LIBS"],
        [AC_MSG_ERROR([cannot find usable OpenSSL library])],
        [$CRYPTO_LIBS])],
    [AC_CHECK_LIB([ssl], [SSL_library_init], [SSL_LIBS=-lssl],
        [AC_MSG_ERROR([cannot find usable OpenSSL library])])])
 RRA_LIB_SSL_RESTORE])
