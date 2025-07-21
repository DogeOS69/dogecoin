AC_PREREQ([2.60])

define(_PKG_VERSION_MAJOR, 0)
define(_PKG_VERSION_MINOR, 1)
define(_PKG_VERSION_BUILD, 0)
define(_PKG_VERSION_IS_RELEASE, false)

define(_LIB_VERSION_CURRENT, 0)
define(_LIB_VERSION_REVISION, 0)
define(_LIB_VERSION_AGE, 0)
AC_INIT([libbls], m4_join([.], _PKG_VERSION_MAJOR, _PKG_VERSION_MINOR, _PKG_VERSION_BUILD)m4_if(_PKG_VERSION_IS_RELEASE, [true], [], [-pre]), [https://github.com/QEDProtocol/bls12-381/issues], [libbls], [https://github.com/QEDProtocol/bls12-381])

AC_SUBST(LIB_VERSION_CURRENT, _LIB_VERSION_CURRENT)
AC_SUBST(LIB_VERSION_REVISION, _LIB_VERSION_REVISION)
AC_SUBST(LIB_VERSION_AGE, _LIB_VERSION_AGE)

AM_INIT_AUTOMAKE([1.11.2 foreign subdir-objects])

AC_ARG_ENABLE([blsasm], [AS_HELP_STRING([--enable-blsasm=yes|no], [Enable blsasm option])], [], [enable_blsasm=no])

AC_PROG_CXX
AM_PROG_AR

LT_INIT([win32-dll])


CXXFLAGS="-O3 -I include"

AC_CANONICAL_HOST
AC_CANONICAL_TARGET
case $target_cpu in 
    x86_64*) 
    AC_MSG_NOTICE(["The target platform is $target_cpu"])
    if test "x$enable_blsasm" = "xyes"; then
        AC_MSG_NOTICE(["Enable blsasm"])
        CXXFLAGS="$CXXFLAGS -D__x86_64_asm__"
    else
        AC_MSG_NOTICE(["Disable blsasm $host_os"])
        case $host_os in
            darwin*)
            CXXFLAGS="$CXXFLAGS"
            ;;
            *)
            CXXFLAGS="$CXXFLAGS -flto"
            ;;
        esac
    fi
    ;;
    *)
    AC_MSG_NOTICE([The target platform is not x86_64])
    CXXFLAGS="$CXXFLAGS -flto"
    ;;
esac


AC_SUBST(CXX)
AC_SUBST(CXXFLAGS)

AC_CONFIG_FILES([Makefile libbls.pc])

AC_OUTPUT

echo
echo "  target os     = $TARGET_OS"
echo "  build os      = $BUILD_OS"
echo
echo "  CC            = $CC"
echo "  CPPFLAGS      = $CPPFLAGS"
echo "  CXX           = $CXX"
echo "  CXXFLAGS      = $CXXFLAGS"
echo "  LDFLAGS       = $LDFLAGS"
echo "  ENABLE_BLSASM = $enable_blsasm"
echo
