dnl sident.m4 -- Find the sident libraries.
dnl $Id$
dnl
dnl Defines the macro WEBAUTH_LIB_SIDENT, which probes for the sident libraries
dnl and defines the output variables SIDENT_CPPFLAGS and SIDENT_LIBS to the
dnl appropriate preprocessor and linker flags.  --disable-sident is honored
dnl and disables the checks and S/Ident support.  -DHAVE_SIDENT=1 is added to
dnl SIDENT_CPPFLAGS if support is enabled so that mod_webkdc doesn't have to
dnl include the config.h file (some of it conflicts with Apache's config.h
dnl file since they don't rename symbols).
dnl
dnl This macro uses the KRB5_LDFLAGS variable set by the WEBAUTH_LIB_KRB5 to
dnl find the Kerberos libraries.

AC_DEFUN([WEBAUTH_LIB_SIDENT],
[AC_ARG_ENABLE([sident],
    AC_HELP_STRING([--disable-sident], [Disable S/Ident support]))
AC_ARG_WITH([sident],
    AC_HELP_STRING([--with-sident=PATH], [Path to S/Ident install]),
    [if test x"$withval" != xno ; then
        SIDENT_LDFLAGS=-L$withval/lib
        SIDENT_CPPFLAGS=-I$withval/include
    fi])
if test x"$enable_sident" != xno ; then
    WEBAUTH_LDFLAGS_save=$LDFLAGS
    LDFLAGS="$LDFLAGS $SIDENT_LDFLAGS $KRB5_LDFLAGS"
    SIDENT_LIBS=
    WEBAUTH_LIBS_save=$LIBS
    AC_SEARCH_LIBS([crypt], [crypt], [SIDENT_LIBS="$LIBS"])
    LIBS=$WEBAUTH_LIBS_save
    AC_CHECK_LIB([des425], [des_key_sched],
        [SIDENT_LIBS="-ldes425 $SIDENT_LIBS"], ,
        [$SIDENT_LIBS $KRB5_LIBS])
    AC_CHECK_LIB([krb4], [krb_rd_req],
        [SIDENT_LIBS="-lkrb4 $SIDENT_LIBS"], ,
        [$SIDENT_LIBS $KRB5_LIBS])
    AC_CHECK_LIB([gssapi_krb5], [gss_init_sec_context],
        [SIDENT_LIBS="-lgssapi_krb5 $SIDENT_LIBS"], ,
        [$SIDENT_LIBS $KRB5_LIBS])
    AC_CHECK_LIB([sident], [ident_set_authtype],
        [SIDENT_LIBS="-lsident $SIDENT_LIBS"
         AC_DEFINE([HAVE_SIDENT], 1,
             [Define to 1 to include S/Ident support.])
         SIDENT_CPPFLAGS="-DHAVE_SIDENT=1 $SIDENT_CPPFLAGS"],
        [if test x"$enable_sident" = xyes ; then
            AC_MSG_ERROR([No working S/Ident library found])
         else
            SIDENT_LDFLAGS=""
            SIDENT_LIBS=""
            SIDENT_CPPFLAGS=""
         fi],
        [$SIDENT_LIBS $KRB5_LIBS])
    LDFLAGS=$WEBAUTH_LDFLAGS_save
    SIDENT_LIBS="$SIDENT_LDFLAGS $KRB5_LDFLAGS $SIDENT_LIBS"
    SIDENT_LIBS=`echo "$SIDENT_LIBS" | sed 's/^  *//'`
fi
AC_SUBST(SIDENT_LIBS)
AC_SUBST(SIDENT_CPPFLAGS)])
