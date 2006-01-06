dnl krb5.m4 -- Find the compiler and linker flags for Kerberos v5.
dnl $Id$
dnl
dnl Finds the compiler and linker flags and adds them to CPPFLAGS and LIBS.
dnl Provides --with-kerberos and --enable-reduced-depends configure options to
dnl control how linking with Kerberos is done.  Uses krb5-config where
dnl available unless reduced dependencies is requested.  Provides the macro
dnl WEBAUTH_LIB_KRB5.
dnl
dnl This is a modified version of this standard set of probes to remove
dnl --enable-static and to set KRB5_LIBS and KRB5_CPPFLAGS instead of
dnl modifying the main variables.  All of the non-krb5 stuff has been
dnl stripped out, as has the initial probe for reduced dependencies and some
dnl other things that we're doing in the main configure script.  Don't just
dnl blindly replace it with updates from other packages.

dnl Does the appropriate library checks for reduced-dependency krb5 linkage.
AC_DEFUN([_WEBAUTH_LIB_KRB5_KRB5_REDUCED],
[AC_CHECK_LIB([krb5], [krb5_init_context], [KRB5_LIBS="-lkrb5"],
    [AC_MSG_ERROR([cannot find usable Kerberos v5 library])])
AC_CHECK_LIB([com_err], [com_err], [KRB5_LIBS="$KRB5_LIBS -lcom_err"],
    [AC_MSG_ERROR([cannot find usable com_err library])])])

dnl Does the appropriate library checks for krb5 linkage.  Note that we have
dnl to check for a different function the second time since the Heimdal and
dnl MIT libraries have the same name.
AC_DEFUN([_WEBAUTH_LIB_KRB5_KRB5],
[AC_CHECK_LIB([krb5], [krb5_init_context],
    [KRB5_LIBS="-lkrb5 -lasn1 -lroken -lcrypto -lcom_err"],
    [KRB5EXTRA="-lk5crypto -lcom_err"
     AC_CHECK_LIB([krb5support], [krb5int_getspecific],
        [KRB5EXTRA="$KRB5EXTRA -lkrb5support"],
        [AC_SEARCH_LIBS([pthread_setspecific], [pthreads pthread])
         AC_CHECK_LIB([krb5support], [krb5int_setspecific],
            [KRB5EXTRA="$KRB5EXTRA -lkrb5support"])])
     AC_CHECK_LIB([krb5], [krb5_cc_default],
        [KRB5_LIBS="-lkrb5 $KRB5EXTRA"],
        [AC_MSG_ERROR([cannot find usable Kerberos v5 library])],
        [$KRB5EXTRA])],
    [-lasn1 -lroken -lcrypto -lcom_err])])

dnl Additional checks for portability between MIT and Heimdal if krb5
dnl libraries were requested.
AC_DEFUN([_WEBAUTH_LIB_KRB5_KRB5_EXTRA],
[AC_CHECK_HEADERS([et/com_err.h])
LIBS_save=$LIBS
LIBS="$KRB5_LIBS $LIBS"
AC_CHECK_FUNCS([krb5_free_keytab_entry_contents])
LIBS=$LIBS_save])

dnl The main macro.
AC_DEFUN([WEBAUTH_LIB_KRB5],
[LDFLAGS_save=$LDFLAGS
KRBROOT=
AC_ARG_WITH([kerberos],
    AC_HELP_STRING([--with-kerberos=DIR],
        [Location of Kerberos headers and libraries]),
    [if test x"$withval" != xno ; then
        KRBROOT="$withval"
     fi])

dnl Handle the reduced depends case, which is much simpler.
if test x"$reduced_depends" = xtrue ; then
    if test x"$KRBROOT" != x ; then
        if test x"$KRBROOT" != x/usr ; then
            KRB5_CPPFLAGS="-I$KRBROOT/include"
        fi
        LDFLAGS="$LDFLAGS -L$KRBROOT/lib"
    fi
    _WEBAUTH_LIB_KRB5_KRB5_REDUCED
fi

dnl Checking for the neworking libraries shouldn't be necessary for the
dnl krb5-config case, but apparently it is at least for MIT Kerberos 1.2.
dnl This will unfortunately mean multiple -lsocket -lnsl references when
dnl building with current versions of Kerberos, but this shouldn't cause
dnl any practical problems.
if test x"$reduced_depends" != xtrue ; then
    AC_ARG_VAR([KRB5_CONFIG], [Path to krb5-config])
    if test x"$KRBROOT" != x ; then
        if test -x "$KRBROOT/bin/krb5-config" ; then
            KRB5_CONFIG="$KRBROOT/bin/krb5-config"
        fi
    else
        AC_PATH_PROG([KRB5_CONFIG], [krb5-config])
    fi

    if test x"$KRB5_CONFIG" != x ; then
        AC_MSG_CHECKING([for krb5 support in krb5-config])
        if "$KRB5_CONFIG" | grep krb5 > /dev/null 2>&1 ; then
            AC_MSG_RESULT([yes])
            KRB5_CPPFLAGS=`"$KRB5_CONFIG" --cflags krb5`
            KRB5_LIBS=`"$KRB5_CONFIG" --libs krb5`
        else
            AC_MSG_RESULT([no])
            KRB5_CPPFLAGS=`"$KRB5_CONFIG" --cflags`
            KRB5_LIBS=`"$KRB5_CONFIG" --libs`
        fi
        KRB5_CPPFLAGS=`echo "$KRB5_CPPFLAGS" | sed 's%-I/usr/include ?%%'`
    else
        if test x"$KRBROOT" != x ; then
            if test x"$KRBROOT" != x/usr ; then
                KRB5_CPPFLAGS="-I$KRBROOT/include"
            fi
            LDFLAGS="$LDFLAGS -L$KRBROOT/lib"
        fi
        AC_SEARCH_LIBS([res_search], [resolv], ,
            [AC_SEARCH_LIBS([__res_search], [resolv])])
        AC_SEARCH_LIBS([crypt], [crypt])
        _WEBAUTH_LIB_KRB5_KRB5
    fi
fi

dnl Generate the final library list and put it into the standard variables.
KRB5_LIBS="$LDFLAGS $KRB5_LIBS"
KRB5_CPPFLAGS=`echo "$CPPFLAGS" | sed 's/^  *//'`
KRB5_LDFLAGS=`echo "$LDFLAGS" | sed 's/^  *//'`
AC_SUBST([KRB5_CPPFLAGS])
AC_SUBST([KRB5_LIBS])
LDFLAGS=$LDFLAGS_save

dnl Run any extra checks for the desired libraries.
_WEBAUTH_LIB_KRB5_KRB5_EXTRA])
