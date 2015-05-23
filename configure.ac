AC_PREREQ([2.69])
AC_INIT([sasl2-oauth],[0.01],[robn@fastmail.com])
AM_INIT_AUTOMAKE([foreign])

AC_PROG_CC

AM_SILENT_RULES([yes])

AC_ENABLE_SHARED
AC_DISABLE_STATIC
AC_PROG_LIBTOOL

LT_INIT

AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h netdb.h netinet/in.h string.h sys/socket.h unistd.h])

AC_TYPE_SIZE_T
AC_TYPE_UINT32_T

AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memset strchr strerror uname])

dnl XXX wheezy doesn't carry libsasl2.pc :/
dnl PKG_CHECK_MODULES([SASL2],[libsasl2])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])

dnl XXX pretty horrid
libdir='${exec_prefix}'/lib/sasl2

AC_OUTPUT
