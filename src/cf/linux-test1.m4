# AC_TRY_KBUILD26([INCLUDES], [FUNCTION-BODY],
#                 [ACTION-IF-SUCCESS], [ACTION-IF-FAILURE])
#
AC_DEFUN([AC_TRY_KBUILD26],[  rm -fr conftest.dir
  if test "x$ac_linux_kbuild_requires_extra_cflags" = "xyes" ; then
    CFLAGS_PREFIX='EXTRA_'
  fi
  if mkdir conftest.dir &&
    cat >conftest.dir/Makefile <<_ACEOF &&
${CFLAGS_PREFIX}CFLAGS += $CPPFLAGS

obj-m += conftest.o
_ACEOF
    cat >conftest.dir/conftest.c <<\_ACEOF &&
/* confdefs.h */
_ACEOF
    cat confdefs.h >>conftest.dir/conftest.c &&
    cat >>conftest.dir/conftest.c <<\_ACEOF &&
/* end confdefs.h */
#include <linux/module.h>
$1

void conftest(void)
{ 
$2
} 

MODULE_LICENSE("http://www.openafs.org/dl/license10.html");
_ACEOF
    echo make -C $LINUX_KERNEL_BUILD M=$SRCDIR_PARENT/conftest.dir modules KBUILD_VERBOSE=1 >&AS_MESSAGE_LOG_FD &&
    make -C $LINUX_KERNEL_BUILD M=$SRCDIR_PARENT/conftest.dir modules KBUILD_VERBOSE=1 >&AS_MESSAGE_LOG_FD 2>conftest.err &&
    ! grep -i "WARNING: .* undefined!$" conftest.err >/dev/null 2>&1
    then [$3]
    else
      sed '/^ *+/d' conftest.err >&AS_MESSAGE_LOG_FD
      echo "$as_me: failed using Makefile:" >&AS_MESSAGE_LOG_FD
      sed 's/^/| /' conftest.dir/Makefile >&AS_MESSAGE_LOG_FD
      echo "$as_me: and program was:" >&AS_MESSAGE_LOG_FD
      sed 's/^/| /' conftest.dir/conftest.c >&AS_MESSAGE_LOG_FD
      [$4]
  fi; rm -fr conftest.err conftest.dir])

  
# AC_TRY_KBUILD24([INCLUDES], [FUNCTION-BODY],
#                 [ACTION-IF-SUCCESS], [ACTION-IF-FAILURE])
#
AC_DEFUN([AC_TRY_KBUILD24], [
  ac_save_CPPFLAGS="$CPPFLAGS"
  CPPFLAGS="-I$LINUX_KERNEL_PATH/include -D__KERNEL__ -Werror-implicit-function-declaration $CPPFLAGS"
  AC_TRY_COMPILE([
#include <linux/kernel.h>
$1], [$2], [$3], [$4])
  CPPFLAGS="$ac_save_CPPFLAGS"])


# AC_TRY_KBUILD([INCLUDES], [FUNCTION-BODY],
#               [ACTION-IF-SUCCESS], [ACTION-IF-FAILURE])
#
AC_DEFUN([AC_TRY_KBUILD], [
  if test $AFS_SYSKVERS -ge 26 ; then
    AC_TRY_KBUILD26([$1], [$2], [$3], [$4])
  else
    AC_TRY_KBUILD24([$1], [$2], [$3], [$4])
  fi])

AC_DEFUN([LINUX_KERNEL_COMPILE_WORKS], [
  AC_MSG_CHECKING([for linux kernel module build works])
  AC_TRY_KBUILD(
[#include <linux/sched.h>
#include <linux/fs.h>],
    [],:,AC_MSG_RESULT(no)
    AC_MSG_FAILURE([Fix problem or use --disable-kernel-module...]))
  AC_MSG_RESULT(yes)])

AC_DEFUN([LINUX_KBUILD_USES_EXTRA_CFLAGS], [
  AC_MSG_CHECKING([if linux kbuild requires EXTRA_CFLAGS])
  save_CPPFLAGS="$CPPFLAGS"
  CPPFLAGS=-Wall
  AC_TRY_KBUILD(
[#include <linux/sched.h>
#include <linux/fs.h>],
    [],
    ac_linux_kbuild_requires_extra_cflags=no,
    ac_linux_kbuild_requires_extra_cflags=yes)
    CPPFLAGS="$save_CPPFLAGS"
    AC_MSG_RESULT($ac_linux_kbuild_requires_extra_cflags)])

dnl AC_CHECK_LINUX_BUILD([msg], [var], [includes], [code], [define])
AC_DEFUN([AC_CHECK_LINUX_BUILD],
 [AS_VAR_PUSHDEF([ac_linux_build], [$2])dnl
  AC_CACHE_CHECK([$1], [ac_linux_build],
   [AC_TRY_KBUILD([$3], [$4],
		  AS_VAR_SET([ac_linux_build], [yes]),
		  AS_VAR_SET([ac_linux_build], [no]))
   ])
  AS_IF([test AS_VAR_GET([ac_linux_build]) = yes],
        [AC_DEFINE([$5],1,[$6])])
 ])

dnl AC_CHECK_LINUX_HEADER(header)
AC_DEFUN([AC_CHECK_LINUX_HEADER],
 [AC_CHECK_LINUX_BUILD([for linux/$1], [ac_cv_linux_header_$1],
		       [#include <linux/$1>],
		       [return;],
		       AS_TR_CPP(HAVE_LINUX_$1),
		       [Define if your kernel has linux/$1])
 ])

dnl AC_CHECK_LINUX_FUNC([function], [includes], [code])
AC_DEFUN([AC_CHECK_LINUX_FUNC],
 [AS_VAR_PUSHDEF([ac_linux_func], [ac_cv_linux_func_$1])dnl
  AC_CACHE_CHECK([for $1], [ac_linux_func],
    [save_CPPFLAGS="$CPPFLAGS"
     CPPFLAGS="$CPPFLAGS -Werror-implicit-function-declaration"
     AC_TRY_KBUILD([$2], [$3],
		   AS_VAR_SET([ac_linux_func], [yes]),
		   AS_VAR_SET([ac_linux_func], [no]))
     CPPFLAGS="$save_CPPFLAGS"
    ])
  AS_IF([test AS_VAR_GET([ac_linux_func]) = yes],
	[AC_DEFINE(AS_TR_CPP(HAVE_LINUX_$1), 1,
		   [Define if your kernel has the $1 function])])
 ])

dnl AC_CHECK_LINUX_STRUCT([structure], [element], [includes])
AC_DEFUN([AC_CHECK_LINUX_STRUCT],
 [AC_CHECK_LINUX_BUILD([for $2 in struct $1],
		       [ac_cv_linux_struct_$1_has_$2],
		       [#include <linux/$3>],
		       [struct $1 _test; printk("%x\n", &_test.$2); ],
		       AS_TR_CPP(STRUCT_$1_HAS_$2),
		       [Define if kernel struct $1 has the $2 element])
 ])

