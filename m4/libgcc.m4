dnl libgcc.m4 -- Find libgcc if needed.
dnl $Id$
dnl
dnl We unfortunately need this hack for the time being on Solaris because when
dnl built with gcc, modules and some of their dependent libraries can use
dnl internal libgcc routines that won't be defined by Apache if Apache is
dnl built with a different compiler.
dnl
dnl Sets LIBGCC_LIBS to the appropriate -L and -l flags to link with libgcc
dnl explicitly.
dnl
dnl FIXME: Should be dependent on older dnl versions of GCC that don't have a
dnl shared library.

AC_DEFUN([WEBAUTH_LIB_LIBGCC],
[AC_REQUIRE([AC_CANONICAL_HOST])
LIBGCC_LIBS=
if test "$GCC" = "yes" ; then
    case "$host" in
    *-solaris*)
        libgcc_path=`$CC -print-libgcc-file-name | sed 's%/[[^/]]*$%%'`
        LIBGCC_LIBS="$CURL_LIBS -L$libgcc_path -lgcc"
        ;;
    esac
fi
AC_SUBST(LIBGCC_LIBS)])
