
AC_DEFUN([OPENAFS_OSCONF], [

dnl defaults, override in case below as needed
CFLAGS=
XCFLAGS='${DBG} ${OPTMZ}'
RXDEBUG="-DRXDEBUG"
SHLIB_SUFFIX="so"
CCOBJ="$CC"
MT_CC="$CC"
XLIBS="${LIB_AFSDB} ${XBSA_XLIBS} ${LIB_libintl}"

dnl debugging and optimization flag defaults
dnl Note, these are all the defaults for if debug/optimize turned on, and
dnl the arch cases below do override as needed
KERN_DBG=-g
KERN_OPTMZ=-O
DBG=-g
OPTMZ=-O
LWP_DBG=-g
NO_STRIP_BIN=
LWP_OPTMZ=-O
PAM_DBG=-g
PAM_OPTMZ=

dnl standard programs
AC_PROG_RANLIB
AC_CHECK_PROGS(AS, as, [${am_missing_run}as])
AC_CHECK_PROGS(AR, ar, [${am_missing_run}ar])
AC_CHECK_PROGS(MV, mv, [${am_missing_run}mv])
AC_CHECK_PROGS(RM, rm, [${am_missing_run}rm])
AC_CHECK_PROGS(LD, ld, [${am_missing_run}ld])
AC_CHECK_PROGS(CP, cp, [${am_missing_run}cp])
AC_CHECK_PROGS(STRIP, strip, [${am_missing_run}strip])
AC_CHECK_PROGS(LORDER, lorder, [${am_missing_run}lorder])

dnl TODO - need to disable STRIP if we are doing debugging in any user space code

case $AFS_SYSNAME in
	alpha_dux40)
		CC="cc"
		CCOBJ="cc"
		MT_CC="cc"
		CSTATIC="-non_shared"
		DBG="-g3"
		MT_CFLAGS='-D_REENTRANT=1 -pthread -DAFS_PTHREAD_ENV ${XCFLAGS}'
		MT_LIBS="-pthread -lpthread -lmach -lexc -lc"
		TXLIBS="-lcurses"
		XCFLAGS="-D_NO_PROTO -DOSF"
		SHLIB_LINKER="${CC} -all -shared -expect_unresolved \"*\""
		;;

	alpha_dux50)
		CC="cc"
		CCOBJ="cc"
		MT_CC="cc"
		LEX="flex -l"
		DBG="-g3"
		CSTATIC="-non_shared"
		MT_CFLAGS='-D_REENTRANT=1 -pthread -DAFS_PTHREAD_ENV ${XCFLAGS}'
		MT_LIBS="-pthread -lpthread -lmach -lexc -lc"
		TXLIBS="-lcurses"
		XCFLAGS="-D_NO_PROTO -DOSF"
		SHLIB_LINKER="${CC} -all -shared -expect_unresolved \"*\""
		;;

	alpha_dux51)
		CC="cc"
		CCOBJ="cc"
		MT_CC="cc"
		DBG="-g3"
		CSTATIC="-non_shared"
		LWP_OPTMZ="-O2"
		MT_CFLAGS='-D_REENTRANT=1 -pthread -DAFS_PTHREAD_ENV ${XCFLAGS}'
		MT_LIBS="-pthread -lpthread -lmach -lexc -lc"
		TXLIBS="-lcurses"
		XCFLAGS="-D_NO_PROTO -DOSF"
		SHLIB_LINKER="${CC} -all -shared -expect_unresolved \"*\""
		;;

	alpha_linux_22)
		KERN_OPTMZ=-O2
		MT_CFLAGS='-DAFS_PTHREAD_ENV -pthread -D_REENTRANT ${XCFLAGS}'
		MT_LIBS="-lpthread"
		PAM_OPTMZ=-O2
		PAM_CFLAGS="-Dlinux -DLINUX_PAM -fPIC"
		SHLIB_CFLAGS="-fPIC"
		SHLIB_LDFLAGS="-shared -Xlinker -x"
		TXLIBS="-lncurses"
		XCFLAGS="-D_LARGEFILE64_SOURCE"
		SHLIB_LINKER="${MT_CC} -shared"
		;;

	alpha_linux_24)
		CCOBJ="${CC} -fPIC"
		KERN_OPTMZ=-O2
		MT_CFLAGS='-DAFS_PTHREAD_ENV -pthread -D_REENTRANT ${XCFLAGS}'
		MT_LIBS="-lpthread"
		PAM_OPTMZ=-O2
		PAM_CFLAGS="-Dlinux -DLINUX_PAM -fPIC"
		SHLIB_CFLAGS="-fPIC"
		SHLIB_LDFLAGS="-shared -Xlinker -x"
		TXLIBS="-lncurses"
		XCFLAGS="-D_LARGEFILE64_SOURCE"
		SHLIB_LINKER="${MT_CC} -shared"
		;;

	alpha_linux_26)
		CCOBJ="${CC} -fPIC"
		KERN_OPTMZ=-O2
		MT_CFLAGS='-DAFS_PTHREAD_ENV -pthread -D_REENTRANT ${XCFLAGS}'
		MT_LIBS="-lpthread"
		PAM_OPTMZ=-O2
		PAM_CFLAGS="-Dlinux -DLINUX_PAM -fPIC"
		SHLIB_CFLAGS="-fPIC"
		SHLIB_LDFLAGS="-shared -Xlinker -x"
		TXLIBS="-lncurses"
		XCFLAGS="-D_LARGEFILE64_SOURCE"
		SHLIB_LINKER="${MT_CC} -shared"
		;;

	arm_linux24)
		CCOBJ="${CC} -fPIC"
		KERN_OPTMZ=-O2
		MT_CFLAGS='-DAFS_PTHREAD_ENV -pthread -D_REENTRANT ${XCFLAGS}'
		MT_LIBS="-lpthread"
		PAM_OPTMZ=-O2
		PAM_CFLAGS="-Dlinux -DLINUX_PAM -fPIC"
		SHLIB_CFLAGS="-fPIC"
		SHLIB_LDFLAGS="-shared -Xlinker -x"
		TXLIBS="-lncurses"
		XCFLAGS="-D_LARGEFILE64_SOURCE"
		SHLIB_LINKER="${MT_CC} -shared"
		;;

	arm_linux26)
		CCOBJ="${CC} -fPIC"
		KERN_OPTMZ=-O2
		MT_CFLAGS='-DAFS_PTHREAD_ENV -pthread -D_REENTRANT ${XCFLAGS}'
		MT_LIBS="-lpthread"
		PAM_OPTMZ=-O2
		PAM_CFLAGS="-Dlinux -DLINUX_PAM -fPIC"
		SHLIB_CFLAGS="-fPIC"
		SHLIB_LDFLAGS="-shared -Xlinker -x"
		TXLIBS="-lncurses"
		XCFLAGS="-D_LARGEFILE64_SOURCE"
		SHLIB_LINKER="${MT_CC} -shared"
		;;

	hp_ux102)
		AS="/usr/ccs/bin/as"
		CC="/opt/ansic/bin/cc -Ae"
		CCOBJ="/opt/ansic/bin/cc -Ae"
		DBM="/lib/libndbm.a"
		LD="/bin/ld"
		LEX="/opt/langtools/bin/lex"
		LWP_OPTMZ="-O"
		MT_CC="/opt/ansic/bin/cc -Ae"
		MT_CFLAGS='-D_POSIX_C_SOURCE=199506L -DAFS_PTHREAD_ENV ${XCFLAGS}'
		MT_LIBS="-L/opt/dce/lib -ldce"
		MV="/bin/mv"
		OPTMZ="-O"
		PAM_CFLAGS="+DA1.0 +z -Wl,+k"
		PAM_LIBS="/usr/lib/libpam.1"
		RANLIB="/usr/bin/ranlib"
		RM="/bin/rm"
		SHLIB_LDFLAGS="-b -Bsymbolic"
		SHLIB_SUFFIX="sl"
		TXLIBS="/usr/lib/libHcurses.a"
		VFSCK_CFLAGS="-D_FILE64"
		XCFLAGS0="-ldld -lc -Wp,-H200000 -Wl,-a,archive -DAUTH_DBM_LOG +z -Wl,+k -D_LARGEFILE64_SOURCE"
		XCFLAGS64="${XCFLAGS0} +DA2.0W"
		XCFLAGS="${XCFLAGS0} +DA1.0"
		YACC="/opt/langtools/bin/yacc"
		SHLIB_LINKER="ld -b"
		;;

	hp_ux11*)
		AR="/usr/bin/ar"
		AS="/usr/ccs/bin/as"
		CC="/opt/ansic/bin/cc"
		CCOBJ="/opt/ansic/bin/cc"
		DBM="/lib/libndbm.a"
		LD="/bin/ld   "
		LEX="/opt/langtools/bin/lex"
		LWP_OPTMZ="-O"
		MT_CC="$CC"
		MT_CFLAGS='-D_POSIX_C_SOURCE=199506L -DAFS_PTHREAD_ENV ${XCFLAGS}'
		MT_LIBS="-lpthread"
		MV="/bin/mv"
		OPTMZ="-O"
		PAM_CFLAGS="+DA1.0 +z -Wl,+k"
		PAM_LIBS="/usr/lib/libpam.1"
		RANLIB="/usr/bin/ranlib"
		RM="/bin/rm"
		SHLIB_LDFLAGS="-b -Bsymbolic"
		SHLIB_SUFFIX="sl"
		TXLIBS="/usr/lib/libHcurses.a"
		VFSCK_CFLAGS="-I/usr/old/usr/include -D_FILE64"
		XCFLAGS0="-ldld -lc -Wp,-H200000 -Wl,-a,archive -DAUTH_DBM_LOG +z -Wl,+k -D_LARGEFILE64_SOURCE"
		XCFLAGS64="${XCFLAGS0} +DA2.0W"
		XCFLAGS="${XCFLAGS0} +DA1.0"
		XLIBELFA="-lelf"
		#XLIBS="${LIB_AFSDB} -lnsl"
		YACC="/opt/langtools/bin/yacc"
		SHLIB_LINKER="ld -b"
		;;

	ia64_hpux*)
		AR="/usr/bin/ar"
		AS="/usr/ccs/bin/as"
		CC="/opt/ansic/bin/cc"
		CCOBJ="/opt/ansic/bin/cc"
		DBM="/lib/hpux32/libndbm.so"
		LD="/bin/ld   "
		LEX="/opt/langtools/bin/lex"
		LWP_OPTMZ=""
		MT_CC="$CC"
		MT_CFLAGS='-D_POSIX_C_SOURCE=199506L -DAFS_PTHREAD_ENV ${XCFLAGS}'
		MT_LIBS="-lpthread"
		MV="/bin/mv"
		OPTMZ="-O"
		PAM_CFLAGS="-b +z -Wl,+k"
		PAM_LIBS="/usr/lib/hpux32/libpam.so"
		RANLIB="/usr/bin/ranlib"
		RM="/bin/rm"
		SHLIB_LDFLAGS="-b -Bsymbolic"
		SHLIB_SUFFIX="sl"
		TXLIBS="/usr/lib/hpux32/libcurses.so"
		VFSCK_CFLAGS="-I/usr/old/usr/include -D_FILE64"
		XCFLAGS0="-ldld -lc -Wp,-H200000 -Wl,-a,archive_shared -DAUTH_DBM_LOG +z -Wl,+k -D_LARGEFILE64_SOURCE"
		XCFLAGS64="${XCFLAGS0} +DD64"
		XCFLAGS="${XCFLAGS0}"
		XLIBELFA="-lelf"
		#XLIBS="${LIB_AFSDB} -lnsl"
		YACC="/opt/langtools/bin/yacc"
		SHLIB_LINKER="ld -b"
		;;

	i386_fbsd_*)
		MT_CFLAGS='-DAFS_PTHREAD_ENV -pthread -D_REENTRANT ${XCFLAGS}'
		MT_LIBS="-pthread"
		PAM_OPTMZ=-O2
		PAM_CFLAGS="-pipe -fPIC"
		SHLIB_LDFLAGS="-shared -Xlinker -x"
		SHLIB_LINKER="${MT_CC} -shared"
		TXLIBS="-lncurses"
		XCFLAGS="-pipe"
		;;

	i386_dfbsd_*)
		MT_CFLAGS='-DAFS_PTHREAD_ENV -pthread -D_REENTRANT ${XCFLAGS}'
		MT_LIBS="-pthread"
		PAM_OPTMZ=-O2
		PAM_CFLAGS="-pipe -fPIC"
		SHLIB_LDFLAGS="-shared -Xlinker -x"
		SHLIB_LINKER="${MT_CC} -shared"
		TXLIBS="-lncurses"
		XCFLAGS="-pipe"
		;;

	amd64_fbsd_*)
		MT_CFLAGS='-DAFS_PTHREAD_ENV -pthread -D_REENTRANT ${XCFLAGS}'
		MT_LIBS="-pthread"
		PAM_CFLAGS="-O2 -pipe -fPIC"
		SHLIB_LDFLAGS="-shared -Xlinker -x"
		SHLIB_LINKER="${MT_CC} -shared"
		TXLIBS="-lncurses"
		XCFLAGS="-O2 -pipe -fPIC"
		;;

	*nbsd2*|*nbsd3*|*nbsd4*|*nbsd5*)
		MT_CFLAGS='-DAFS_PTHREAD_ENV -pthread -D_REENTRANT ${XCFLAGS}'
		MT_LIBS="-pthread"
		PAM_OPTMZ=-O2
		PAM_CFLAGS="-pipe -fPIC"
		SHLIB_CFLAGS="-fPIC"
		SHLIB_LDFLAGS="-shared -Xlinker -x"
		SHLIB_LINKER="${MT_CC} -shared"
		TXLIBS="-lcurses"
		XCFLAGS="-pipe"
		;;

	*nbsd15|*nbsd16)
		MT_CFLAGS='${XCFLAGS}'
		MT_LIBS=""
		PAM_OPTMZ=-O2
		PAM_CFLAGS="-pipe -fPIC"
		SHLIB_LDFLAGS="-shared -Xlinker -x"
		SHLIB_LINKER="${MT_CC} -shared"
		TXLIBS="/usr/lib/libcurses.so"
		XCFLAGS="-pipe"
		;;

	ia64_linux24|ia64_linux26)
		KERN_OPTMZ=-O2
		MT_CFLAGS='-DAFS_PTHREAD_ENV -pthread -D_REENTRANT ${XCFLAGS}'
		MT_LIBS="-lpthread"
		PAM_OPTMZ=-O2
		PAM_CFLAGS="-Dlinux -DLINUX_PAM -fPIC"
		SHLIB_CFLAGS="-fPIC"
		SHLIB_LDFLAGS="-shared -Xlinker -x"
		TXLIBS="-lncurses"
		XCFLAGS="-D_LARGEFILE64_SOURCE -G0"
		SHLIB_LINKER="${MT_CC} -shared"
		;;

	amd64_linux*)
		CCOBJ="${CC} -fPIC"
		KERN_OPTMZ=-O2
		MT_CFLAGS='-DAFS_PTHREAD_ENV -pthread -D_REENTRANT ${XCFLAGS}'
		MT_LIBS="-lpthread"
		PAM_OPTMZ=-O2
		PAM_CFLAGS="-Dlinux -DLINUX_PAM -fPIC"
		SHLIB_CFLAGS="-fPIC"
		SHLIB_LDFLAGS="-shared -Xlinker -x"
		TXLIBS="-lncurses"
		XCFLAGS="-D_LARGEFILE64_SOURCE"
		SHLIB_LINKER="${MT_CC} -shared"
		;;

	ppc64_linux24)
		KERN_OPTMZ=-O2
		MT_CFLAGS='-DAFS_PTHREAD_ENV -pthread -D_REENTRANT ${XCFLAGS}'
		MT_LIBS="-lpthread"
		PAM_OPTMZ=-O2
		PAM_CFLAGS="-Dlinux -DLINUX_PAM -fPIC"
		SHLIB_LDFLAGS="-shared -Xlinker -x"
		SHLIB_CFLAGS="-fPIC"
		TXLIBS="/usr/lib64/libncurses.so"
		XCFLAGS="-D_LARGEFILE64_SOURCE"
		SHLIB_LINKER="${MT_CC} -shared"
		;;

	ppc64_linux26)
		KERN_OPTMZ=-O2
		MT_CFLAGS='-DAFS_PTHREAD_ENV -pthread -D_REENTRANT ${XCFLAGS}'
		MT_LIBS="-lpthread"
		PAM_OPTMZ=-O2
		PAM_CFLAGS="-Dlinux -DLINUX_PAM -fPIC"
		SHLIB_LDFLAGS="-shared -Xlinker -x"
		SHLIB_CFLAGS="-fPIC"
		TXLIBS="-lncurses"
		XCFLAGS="-D_LARGEFILE64_SOURCE -fPIC"
		SHLIB_LINKER="${MT_CC} -shared"
		;;

	i386_umlinux22)
		KERN_OPTMZ=-O2
		MT_CFLAGS='-DAFS_PTHREAD_ENV -pthread -D_REENTRANT ${XCFLAGS}'
		MT_LIBS="-lpthread"
		PAM_OPTMZ=-O2
		PAM_CFLAGS="-Dlinux -DLINUX_PAM -fPIC"
		SHLIB_CFLAGS="-fPIC"
		SHLIB_LDFLAGS="-shared -Xlinker -x"
		TXLIBS="-lncurses"
		XCFLAGS="-D_LARGEFILE64_SOURCE"
		SHLIB_LINKER="${MT_CC} -shared"
		;;

	i386_linux*)
		KERN_OPTMZ=-O2
		MT_CFLAGS='-DAFS_PTHREAD_ENV -pthread -D_REENTRANT ${XCFLAGS}'
		MT_LIBS="-lpthread"
		DBG=-g
		KERN_DBG=-g
		LWP_DBG=-g
		LWP_OPTMZ=-O2
		OPTMZ=-O2
		PAM_CFLAGS="-Dlinux -DLINUX_PAM -fPIC"
		SHLIB_CFLAGS="-fPIC"
		SHLIB_LDFLAGS="-shared -Xlinker -x"
		TXLIBS="-lncurses"
		XCFLAGS="-D_LARGEFILE64_SOURCE"
		SHLIB_LINKER="${MT_CC} -shared"
		;;

	i386_umlinux24)
		KERN_OPTMZ=-O2
		MT_CFLAGS='-DAFS_PTHREAD_ENV -pthread -D_REENTRANT ${XCFLAGS}'
		MT_LIBS="-lpthread"
		DBG=-g
		KERN_DBG=-g
		LWP_DBG=-g
		LWP_OPTMZ=-O2
		OPTMZ=-O2
		PAM_OPTMZ=-O2
		PAM_CFLAGS="-Dlinux -DLINUX_PAM -fPIC"
		SHLIB_CFLAGS="-fPIC"
		SHLIB_LDFLAGS="-shared -Xlinker -x"
		TXLIBS="-lncurses"
		XCFLAGS="-D_LARGEFILE64_SOURCE"
		SHLIB_LINKER="${MT_CC} -shared"
		;;

	i386_umlinux26)
		KERN_OPTMZ=-O2
		MT_CFLAGS='-DAFS_PTHREAD_ENV -pthread -D_REENTRANT ${XCFLAGS}'
		MT_LIBS="-lpthread"
		DBG=-g
		KERN_DBG=-g
		LWP_DBG=-g
		LWP_OPTMZ=-O2
		OPTMZ=-O2
		PAM_OPTMZ=-O2
		PAM_CFLAGS="-Dlinux -DLINUX_PAM -fPIC"
		SHLIB_CFLAGS="-fPIC"
		SHLIB_LDFLAGS="-shared -Xlinker -x"
		TXLIBS="-lncurses"
		XCFLAGS="-D_LARGEFILE64_SOURCE"
		SHLIB_LINKER="${MT_CC} -shared"
		;;

	*_obsd*)
		MT_CFLAGS='-DAFS_PTHREAD_ENV -pthread -D_REENTRANT ${XCFLAGS}'
		MT_LIBS="-pthread"
		PAM_OPTMZ=-O2
		PAM_CFLAGS="-pipe -fpic"
		SHLIB_CFLAGS="-fpic"
		SHLIB_LDFLAGS="-shared -Xlinker -x"
		SHLIB_LINKER="${MT_CC} -shared"
		TXLIBS="/usr/lib/libcurses.a"
		XCFLAGS=
		;;

	parisc_linux24)
		KERN_OPTMZ=-O2
		MT_CFLAGS='-DAFS_PTHREAD_ENV -pthread -D_REENTRANT ${XCFLAGS}'
		MT_LIBS="-lpthread"
		PAM_OPTMZ=-O2
		PAM_CFLAGS="-Dlinux -DLINUX_PAM -fPIC"
		SHLIB_CFLAGS="-fPIC"
		SHLIB_LDFLAGS="-shared -Xlinker -x"
		TXLIBS="-lncurses"
		XCFLAGS="-D_LARGEFILE64_SOURCE"
		SHLIB_LINKER="${MT_CC} -shared"
		;;

	ppc_darwin_70)
		CC="cc"
		CCOBJ="cc"
		MT_CC="cc"
		AFSD_LDFLAGS="-F/System/Library/PrivateFrameworks -framework DiskArbitration -framework SystemConfiguration -framework IOKit -framework CoreFoundation"
		MT_CFLAGS='-DAFS_PTHREAD_ENV -D_REENTRANT ${XCFLAGS}'
		KROOT=
		KINCLUDES='-I$(KROOT)/System/Library/Frameworks/Kernel.framework/Headers'
		LWP_OPTMZ="-O2"
		REGEX_OBJ="regex.o"
		XCFLAGS="-no-cpp-precomp"
		TXLIBS="-lncurses"
		EXTRA_VLIBOBJS="fstab.o"
		SHLIB_LINKER="${MT_CC} -dynamiclib"
		SHLIB_SUFFIX="dylib"
		XLIBS="${LIB_AFSDB} ${XBSA_XLIBS} -framework CoreFoundation"
		;;

	*_darwin_80)
		CC="cc"
		CCOBJ="cc"
		MT_CC="cc"
		AFSD_LDFLAGS="-F/System/Library/PrivateFrameworks -framework DiskArbitration -framework SystemConfiguration -framework IOKit -framework CoreFoundation"
		MT_CFLAGS='-DAFS_PTHREAD_ENV -D_REENTRANT ${XCFLAGS} ${ARCHFLAGS}'
		KROOT=
		KINCLUDES='-I$(KROOT)/System/Library/Frameworks/Kernel.framework/Headers'
		KERN_OPTMZ="-Os"
		LWP_OPTMZ="-Os"
		OPTMZ="-Os"
		REGEX_OBJ="regex.o"
		TXLIBS="-lncurses"
		EXTRA_VLIBOBJS="fstab.o"
		SHLIB_LINKER="${MT_CC} -dynamiclib"
		SHLIB_SUFFIX="dylib"
		RANLIB="ranlib -c"
		XLIBS="${LIB_AFSDB} ${XBSA_XLIBS} -framework CoreFoundation"
		;;

	*_darwin_90)
		AFSD_LDFLAGS="-F/System/Library/PrivateFrameworks -framework DiskArbitration -framework SystemConfiguration -framework IOKit -framework CoreFoundation"
		MT_CFLAGS='-DAFS_PTHREAD_ENV -D_REENTRANT ${XCFLAGS} ${ARCHFLAGS}'
		KROOT=
		KINCLUDES='-I$(KROOT)/System/Library/Frameworks/Kernel.framework/Headers'
		LD="cc"
		KERN_OPTMZ="-Os"
		LWP_OPTMZ="-Os"
		OPTMZ="-Os"
		REGEX_OBJ="regex.o"
		TXLIBS="-lncurses"
		EXTRA_VLIBOBJS="fstab.o"
		SHLIB_LINKER="${MT_CC} -dynamiclib"
		SHLIB_SUFFIX="dylib"
		RANLIB="ranlib -c"
		XLIBS="${LIB_AFSDB} ${XBSA_XLIBS} -framework CoreFoundation"
		;;

	*_darwin_100)
		AFSD_LDFLAGS="-F/System/Library/PrivateFrameworks -framework DiskArbitration -framework SystemConfiguration -framework IOKit -framework CoreFoundation"
		MT_CFLAGS='-DAFS_PTHREAD_ENV -D_REENTRANT ${XCFLAGS} ${ARCHFLAGS}'
		MT_LIBS="${LIB_AFSDB} -framework CoreFoundation"
		KROOT=
		KINCLUDES='-I$(KROOT)/System/Library/Frameworks/Kernel.framework/Headers'
		LD="cc"
		KERN_OPTMZ="-Os"
		LWP_OPTMZ="-Os"
		OPTMZ="-Os"
		PAM_LIBS="-lpam"
		REGEX_OBJ="regex.o"
		TXLIBS="-lncurses"
		EXTRA_VLIBOBJS="fstab.o"
		SHLIB_LINKER="${MT_CC} -dynamiclib"
		SHLIB_SUFFIX="dylib"
		RANLIB="ranlib"
		XLIBS="${LIB_AFSDB} ${XBSA_XLIBS} -framework CoreFoundation"
		;;

	ppc_linux*)
		KERN_OPTMZ=-O2
		MT_CFLAGS='-DAFS_PTHREAD_ENV -pthread -D_REENTRANT ${XCFLAGS}'
		MT_LIBS="-lpthread"
		PAM_OPTMZ=-O2
		PAM_CFLAGS="-Dlinux -DLINUX_PAM -fPIC"
		SHLIB_CFLAGS="-fPIC"
		SHLIB_LDFLAGS="-shared -Xlinker -x"
		TXLIBS="-lncurses"
		XCFLAGS="-D_LARGEFILE64_SOURCE"
		SHLIB_LINKER="${MT_CC} -shared"
		;;

	rs_aix42)
		CC="cc"
		CCOBJ="cc"
		DBG=""
		LIBSYS_AIX_EXP="afsl.exp"
		MT_CC="xlc_r"
		MT_CFLAGS='-DAFS_PTHREAD_ENV ${XCFLAGS}'
		MT_LIBS="-lpthreads"
		SHLIB_SUFFIX="o"
		TXLIBS="-lcurses"
		XCFLAGS="-K -D_NONSTD_TYPES -D_MBI=void"
		XLIBS="${LIB_AFSDB} ${LIB_libintl} -ldl"
		SHLIB_LINKER="${MT_CC} -bM:SRE -berok"
		AIX32=""
		AIX64="#"
		;;


	rs_aix51)
		CC="cc"
		CCOBJ="cc"
		DBG=""
		LIBSYS_AIX_EXP="afsl.exp"
		MT_CC="xlc_r"
		MT_CFLAGS='-DAFS_PTHREAD_ENV ${XCFLAGS}'
		MT_LIBS="-lpthreads"
		SHLIB_SUFFIX="o"
		TXLIBS="-lcurses"
		XCFLAGS="-K -D_NONSTD_TYPES -D_MBI=void"
		XLIBS="${LIB_AFSDB} ${LIB_libintl} -ldl"
		SHLIB_LINKER="${MT_CC} -bM:SRE -berok"
		AIX32=""
		AIX64=""
		;;

	rs_aix52)	
		CC="cc"
		CCOBJ="cc"
		DBG=""
		LIBSYS_AIX_EXP="afsl.exp"
		MT_CC="xlc_r"
		MT_CFLAGS='-DAFS_PTHREAD_ENV ${XCFLAGS}'
		MT_LIBS="-lpthreads"
		SHLIB_SUFFIX="o"
		TXLIBS="-lcurses"
		XCFLAGS="-K -D_NONSTD_TYPES -D_MBI=void"
		XLIBS="${LIB_AFSDB} ${LIB_libintl} -ldl"
		SHLIB_LINKER="${MT_CC} -bM:SRE -berok"
		AIX32=""
		AIX64=""
		;;

	rs_aix53)	
		CC="cc"
		CCOBJ="cc"
		DBG="-g"
		LIBSYS_AIX_EXP="afsl.exp"
		MT_CC="xlc_r"
		MT_CFLAGS='-DAFS_PTHREAD_ENV ${XCFLAGS}'
		MT_LIBS="-lpthreads"
		SHLIB_SUFFIX="o"
		TXLIBS="-lcurses"
		XCFLAGS="-K -D_NONSTD_TYPES -D_MBI=void"
		XLIBS="${LIB_AFSDB} ${LIB_libintl} -ldl"
		SHLIB_LINKER="${MT_CC} -bM:SRE -berok"
		AIX32=""
		AIX64=""
		;;

	rs_aix61)	
		CC="cc"
		CCOBJ="cc"
		DBG="-g"
		LIBSYS_AIX_EXP="afsl.exp"
		MT_CC="xlc_r"
		MT_CFLAGS='-DAFS_PTHREAD_ENV ${XCFLAGS}'
		MT_LIBS="-lpthreads"
		SHLIB_SUFFIX="o"
		TXLIBS="-lcurses"
		XCFLAGS="-K -D_NONSTD_TYPES -D_MBI=void"
		XLIBS="${LIB_AFSDB} ${LIB_libintl} -ldl"
		SHLIB_LINKER="${MT_CC} -bM:SRE -berok"
		AIX32="#"
		AIX64=""
		;;

	s390_linux22)
		LD="ld"
		KERN_OPTMZ=-O2
		MT_CC="$CC"
		MT_CFLAGS='-DAFS_PTHREAD_ENV -pthread -D_REENTRANT ${XCFLAGS}'
		MT_LIBS="-lpthread"
		PAM_OPTMZ=-O
		PAM_CFLAGS="-Dlinux -DLINUX_PAM -fPIC"
		SHLIB_CFLAGS="-fPIC"
		SHLIB_LDFLAGS="-shared -Xlinker -x"
		TXLIBS="-lncurses"
		OPTMZ=-O
		XCFLAGS="-D_LARGEFILE64_SOURCE"
		SHLIB_LINKER="${MT_CC} -shared"
		;;

	s390_linux24|s390_linux26)
		LD="ld"
		KERN_OPTMZ=-O2
		MT_CC="$CC"
		MT_CFLAGS='-DAFS_PTHREAD_ENV -pthread -D_REENTRANT ${XCFLAGS}'
		MT_LIBS="-lpthread"
		PAM_OPTMZ=-O2
		PAM_CFLAGS="-Dlinux -DLINUX_PAM -fPIC"
		SHLIB_CFLAGS="-fPIC"
		SHLIB_LDFLAGS="-shared -Xlinker -x"
		TXLIBS="-lncurses"
		XCFLAGS="-D_LARGEFILE64_SOURCE"
		SHLIB_LINKER="${MT_CC} -shared"
		;;

	s390x_linux24|s390x_linux26)
		CCOBJ="${CC} -fPIC"
		LD="ld"
		KERN_OPTMZ=-O2
		MT_CC="$CC"
		MT_CFLAGS='-DAFS_PTHREAD_ENV -pthread -D_REENTRANT ${XCFLAGS}'
		MT_LIBS="-lpthread"
		PAM_OPTMZ=-O
		PAM_CFLAGS="-Dlinux -DLINUX_PAM -fPIC"
		SHLIB_CFLAGS="-fPIC"
		SHLIB_LDFLAGS="-shared -Xlinker -x -Xlinker -Bsymbolic"
		TXLIBS="-lncurses"
		OPTMZ=-O
		XCFLAGS="-D_LARGEFILE64_SOURCE -D__s390x__"
		SHLIB_LINKER="${MT_CC} -shared"
		;;

	sgi_62)
		CC="cc"
		CCOBJ="cc"
		MT_CC="cc"
		AFSD_LIBS="/usr/lib/libdwarf.a /usr/lib/libelf.a"
		FSINCLUDES="-I/usr/include/sys/fs"
		MT_CFLAGS='-D_SGI_MP_SOURCE -DAFS_PTHREAD_ENV ${XCFLAGS}'
		MT_LIBS="-lpthread"
		TXLIBS="-lcurses"
		XCFLAGS64="-64 -mips3"
		XCFLAGS="-o32"
		XLDFLAGS64="-64"
		XLDFLAGS="-o32"
		SHLIB_LINKER="${CC} -shared"
		;;

	sgi_63)
		CC="cc"
		CCOBJ="cc"
		MT_CC="cc"
		AFSD_LIBS="/usr/lib/libdwarf.a /usr/lib/libelf.a"
		FSINCLUDES="-I/usr/include/sys/fs"
		MT_CFLAGS='-D_SGI_MP_SOURCE -DAFS_PTHREAD_ENV ${XCFLAGS}'
		MT_LIBS="-lpthread"
		TXLIBS="-lcurses"
		XCFLAGS64="-D_BSD_COMPAT -64 -mips3"
		XCFLAGS="-D_OLD_TERMIOS -D_BSD_COMPAT -o32"
		XLDFLAGS64="-64"
		XLDFLAGS="-o32"
		SHLIB_LINKER="${CC} -shared"
		;;

	sgi_64)
		CC="cc"
		CCOBJ="cc"
		MT_CC="cc"
		AFSD_LIBS="/usr/lib32/libdwarf.a /usr/lib32/libelf.a"
		FSINCLUDES="-I/usr/include/sys/fs"
		MT_CFLAGS='-D_SGI_MP_SOURCE -DAFS_PTHREAD_ENV ${XCFLAGS}'
		MT_LIBS="-lpthread"
		TXLIBS="-lcurses"
		XCFLAGS64="-D_BSD_COMPAT -64 -mips3"
		XCFLAGS="-D_OLD_TERMIOS -D_BSD_COMPAT -n32 -woff 1009,1110,1116,1164,1171,1177,1183,1185,1204,1233,1515,1516,1548,1169,1174,1177,1196,1498,1506,1552"
		XLDFLAGS64="-64"
		XLDFLAGS="-n32"
		SHLIB_LINKER="${CC} -shared"
		;;

	sgi_65)
		AFSD_LIBS="/usr/lib32/libdwarf.a /usr/lib32/libelf.a"
		CC="/usr/bin/cc"
		CCOBJ="/usr/bin/cc"
		FSINCLUDES="-I/usr/include/sys/fs"
		LD="/usr/bin/ld"
		MT_CC="/usr/bin/cc"
		MT_CFLAGS='-D_SGI_MP_SOURCE -DAFS_PTHREAD_ENV ${XCFLAGS}'
		MT_LIBS="-lpthread"
		TXLIBS="-lcurses"
		XCFLAGS64="-64 -mips3"
		XCFLAGS="-n32 -mips3 -woff 1009,1110,1116,1164,1171,1177,1183,1185,1204,1233,1515,1516,1548,1169,1174,1177,1196,1498,1506,1552"
		XLDFLAGS64="-64 -mips3"
		XLDFLAGS="-n32 -mips3"
		SHLIB_LINKER="${CC} -shared"
		;;

	sparc*_linux*)
		KERN_OPTMZ=-O2
		MT_CFLAGS='-DAFS_PTHREAD_ENV -pthread -D_REENTRANT ${XCFLAGS}'
		MT_LIBS="-lpthread"
		PAM_OPTMZ=-O2
		PAM_CFLAGS="-Dlinux -DLINUX_PAM -fPIC"
		SHLIB_CFLAGS="-fPIC"
		SHLIB_LDFLAGS="-shared -Xlinker -x"
		TXLIBS="-lncurses"
		XCFLAGS="-D_LARGEFILE64_SOURCE"
		XCFLAGS64="-D_LARGEFILE64_SOURCE -m64"
		XLDFLAGS64="-m64"
		SHLIB_LINKER="${MT_CC} -shared"
		;;

	sun4_413)
		CCXPG2="/usr/xpg2bin/cc"
		CC="gcc"
		CCOBJ="gcc"
		SHLIB_CFLAGS="-PIC"
		TXLIBS="-lcurses -ltermcap"
		XCFLAGS=""
		XLIBELFA="-lelf"
		XLIBKVM="-lkvm"
		XLIBS="${LIB_AFSDB}"
		LD="ld"
		;;

	sun4x_55)
		CC=$SOLARISCC
		CCOBJ=$SOLARISCC
		MT_CC=$SOLARISCC
		MT_CFLAGS='-mt -DAFS_PTHREAD_ENV ${XCFLAGS}'
		MT_LIBS="-lpthread -lsocket"
		SHLIB_CFLAGS="-KPIC"
		TXLIBS="-lcurses"
		XCFLAGS="-dy -Bdynamic"
		XLIBELFA="-lelf"
		XLIBKVM="-lkvm"
		XLIBS="${LIB_AFSDB} -lsocket -lnsl -lintl -ldl"
		LD="/usr/ccs/bin/ld"
		SHLIB_LINKER="${CC} -G -dy -Bsymbolic -z text"
		LWP_OPTMZ="-g"
		;;

	sun4x_56)
		CC=$SOLARISCC
		CCOBJ=$SOLARISCC
		MT_CC=$SOLARISCC
		MT_CFLAGS='-mt -DAFS_PTHREAD_ENV ${XCFLAGS}'
		MT_LIBS="-lpthread -lsocket"
		PAM_CFLAGS="-KPIC"
		PAM_LIBS="-lc -lpam -lsocket -lnsl -lm"
		SHLIB_CFLAGS="-KPIC"
		SHLIB_LDFLAGS="-G -Bsymbolic"
		TXLIBS="-L/usr/ccs/lib -lcurses"
		XCFLAGS="-dy -Bdynamic"
		XLIBELFA="-lelf"
		LD="/usr/ccs/bin/ld"
		XLIBKVM="-lkvm"
		XLIBS="${LIB_AFSDB} -lsocket -lnsl -lintl -ldl"
		SHLIB_LINKER="${CC} -G -dy -Bsymbolic -z text"
		LWP_OPTMZ="-g"
		;;

	sun4x_57)
		CC=$SOLARISCC
		CCOBJ=$SOLARISCC
		LD="/usr/ccs/bin/ld"
		MT_CC=$SOLARISCC
		MT_CFLAGS='-mt -DAFS_PTHREAD_ENV ${XCFLAGS}'
		MT_LIBS="-lpthread -lsocket"
		PAM_CFLAGS="-KPIC"
		PAM_LIBS="-lc -lpam -lsocket -lnsl -lm"
		SHLIB_CFLAGS="-KPIC"
		SHLIB_LDFLAGS="-G -Bsymbolic"
		TXLIBS="-lcurses"
		XCFLAGS64='${XCFLAGS} -xarch=v9'
		XCFLAGS="-dy -Bdynamic"
		XLIBELFA="-lelf"
		XLIBKVM="-lkvm"
		XLIBS="${LIB_AFSDB} -lsocket -lnsl -lintl -ldl"
		SHLIB_LINKER="${CC} -G -dy -Bsymbolic -z text"
		LWP_OPTMZ="-g"
		;;

	sun4x_58)
		CC=$SOLARISCC
		CCOBJ=$SOLARISCC
		LD="/usr/ccs/bin/ld"
		MT_CC=$SOLARISCC
		MT_CFLAGS='-mt -DAFS_PTHREAD_ENV ${XCFLAGS}'
		MT_LIBS="-lpthread -lsocket"
		PAM_CFLAGS="-KPIC"
		PAM_LIBS="-lc -lpam -lsocket -lnsl -lm"
		SHLIB_CFLAGS="-KPIC"
		SHLIB_LDFLAGS="-G -Bsymbolic"
		TXLIBS="-lcurses"
		XCFLAGS64='${XCFLAGS} -xarch=v9'
		XCFLAGS="-dy -Bdynamic"
		XLIBELFA="-lelf"
		XLIBKVM="-lkvm"
		XLIBS="${LIB_AFSDB} -lsocket -lnsl -lintl -ldl"
		SHLIB_LINKER="${CC} -G -dy -Bsymbolic -z text"
		LWP_OPTMZ="-g"
		;;

	sun4x_59)
		CC=$SOLARISCC
		CCOBJ=$SOLARISCC
		LD="/usr/ccs/bin/ld"
		MT_CC=$SOLARISCC
		MT_CFLAGS='-mt -DAFS_PTHREAD_ENV ${XCFLAGS}'
		MT_LIBS="-lpthread -lsocket"
		PAM_CFLAGS="-KPIC"
		PAM_LIBS="-lc -lpam -lsocket -lnsl -lm"
		SHLIB_CFLAGS="-KPIC"
		SHLIB_LDFLAGS="-G -Bsymbolic"
		TXLIBS="-lcurses"
		XCFLAGS64='${XCFLAGS} -xarch=v9'
		XCFLAGS="-dy -Bdynamic"
		XLIBELFA="-lelf"
		XLIBKVM="-lkvm"
		XLIBS="${LIB_AFSDB} -lsocket -lnsl -lintl -ldl"
		SHLIB_LINKER="${CC} -G -dy -Bsymbolic -z text"
		LWP_OPTMZ="-g"
		;;

	sun4x_510)
		CC=$SOLARISCC
		CCOBJ=$SOLARISCC
		LD="/usr/ccs/bin/ld"
		MT_CC=$SOLARISCC
		MT_CFLAGS='-mt -DAFS_PTHREAD_ENV ${XCFLAGS}'
		MT_LIBS="-lpthread -lsocket"
		PAM_CFLAGS="-KPIC"
		PAM_LIBS="-lc -lpam -lsocket -lnsl -lm"
		SHLIB_CFLAGS="-KPIC"
		SHLIB_LDFLAGS="-G -Bsymbolic"
		TXLIBS="-lcurses"
		XCFLAGS64='${XCFLAGS} -m64'
		XCFLAGS="-dy -Bdynamic"
		XLIBELFA="-lelf"
		XLIBKVM="-lkvm"
		XLIBS="${LIB_AFSDB} -lsocket -lnsl -lintl -ldl"
		SHLIB_LINKER="${CC} -G -dy -Bsymbolic -z text"
		LWP_OPTMZ="-g"
		;;

	sun4x_511)
		CC=$SOLARISCC
		CCOBJ=$SOLARISCC
		LD="/usr/ccs/bin/ld"
		MT_CC=$SOLARISCC
		MT_CFLAGS='-mt -DAFS_PTHREAD_ENV ${XCFLAGS}'
		MT_LIBS="-lpthread -lsocket"
		PAM_CFLAGS="-KPIC"
		PAM_LIBS="-lc -lpam -lsocket -lnsl -lm"
		SHLIB_CFLAGS="-KPIC"
		SHLIB_LDFLAGS="-G -Bsymbolic"
		TXLIBS="-lcurses"
		XCFLAGS64='${XCFLAGS} -xarch=v9'
		XCFLAGS="-dy -Bdynamic"
		XLIBELFA="-lelf"
		XLIBKVM="-lkvm"
		XLIBS="${LIB_AFSDB} -lsocket -lnsl -lintl -ldl"
		SHLIB_LINKER="${CC} -G -dy -Bsymbolic -z text"
		LWP_OPTMZ="-g"
		;;

	sunx86_57)
		CC=$SOLARISCC
		CCOBJ=$SOLARISCC
		LD="/usr/ccs/bin/ld"
		MT_CC=$SOLARISCC
		MT_CFLAGS='-mt -DAFS_PTHREAD_ENV ${XCFLAGS}'
		MT_LIBS="-lpthread -lsocket"
		PAM_CFLAGS="-KPIC"
		PAM_LIBS="-lc -lpam -lsocket -lnsl -lm"
		SHLIB_CFLAGS="-KPIC"
		SHLIB_LDFLAGS="-G -Bsymbolic"
		TXLIBS="-lcurses"
		XCFLAGS64='${XCFLAGS} -xarch=amd64'
		XCFLAGS="-dy -Bdynamic"
		XLIBELFA="-lelf"
		XLIBKVM="-lkvm"
		XLIBS="${LIB_AFSDB} -lsocket -lnsl -lintl -ldl"
		SHLIB_LINKER="${CC} -G -dy -Bsymbolic -z text"
		;;

	sunx86_58)
		CC=$SOLARISCC
		CCOBJ=$SOLARISCC
		LD="/usr/ccs/bin/ld"
		MT_CC=$SOLARISCC
		MT_CFLAGS='-mt -DAFS_PTHREAD_ENV ${XCFLAGS}'
		MT_LIBS="-lpthread -lsocket"
		PAM_CFLAGS="-KPIC"
		PAM_LIBS="-lc -lpam -lsocket -lnsl -lm"
		SHLIB_CFLAGS="-KPIC"
		SHLIB_LDFLAGS="-G -Bsymbolic"
		TXLIBS="-lcurses"
		XCFLAGS64='${XCFLAGS} -xarch=amd64'
		XCFLAGS="-dy -Bdynamic"
		XLIBELFA="-lelf"
		XLIBKVM="-lkvm"
		XLIBS="${LIB_AFSDB} -lsocket -lnsl -lintl -ldl"
		SHLIB_LINKER="${CC} -G -dy -Bsymbolic -z text"
		;;

	sunx86_59)
		CC=$SOLARISCC
		CCOBJ=$SOLARISCC
		LD="/usr/ccs/bin/ld"
		MT_CC=$SOLARISCC
		MT_CFLAGS='-mt -DAFS_PTHREAD_ENV ${XCFLAGS}'
		MT_LIBS="-lpthread -lsocket"
		PAM_CFLAGS="-KPIC"
		PAM_LIBS="-lc -lpam -lsocket -lnsl -lm"
		SHLIB_CFLAGS="-KPIC"
		SHLIB_LDFLAGS="-G -Bsymbolic"
		TXLIBS="-lcurses"
		XCFLAGS64='${XCFLAGS} -xarch=amd64'
		XCFLAGS="-dy -Bdynamic"
		XLIBELFA="-lelf"
		XLIBKVM="-lkvm"
		XLIBS="${LIB_AFSDB} -lsocket -lnsl -lintl -ldl"
		SHLIB_LINKER="${CC} -G -dy -Bsymbolic -z text"
		;;

	sunx86_510)
		CC=$SOLARISCC
		CCOBJ=$SOLARISCC
		LD="/usr/ccs/bin/ld"
		MT_CC=$SOLARISCC
		MT_CFLAGS='-mt -DAFS_PTHREAD_ENV ${XCFLAGS}'
		MT_LIBS="-lpthread -lsocket"
		PAM_CFLAGS="-KPIC"
		PAM_LIBS="-lc -lpam -lsocket -lnsl -lm"
		SHLIB_CFLAGS="-KPIC"
		SHLIB_LDFLAGS="-G -Bsymbolic"
		TXLIBS="-lcurses"
		XCFLAGS64='${XCFLAGS} -m64'
		XCFLAGS="-dy -Bdynamic"
		XLIBELFA="-lelf"
		XLIBKVM="-lkvm"
		XLIBS="${LIB_AFSDB} -lsocket -lnsl -lintl -ldl"
		SHLIB_LINKER="${CC} -G -dy -Bsymbolic -z text"
		;;

	sunx86_511)
		CC=$SOLARISCC
		CCOBJ=$SOLARISCC
		LD="/usr/ccs/bin/ld"
		MT_CC=$SOLARISCC
		MT_CFLAGS='-mt -DAFS_PTHREAD_ENV ${XCFLAGS}'
		MT_LIBS="-lpthread -lsocket"
		PAM_CFLAGS="-KPIC"
		PAM_LIBS="-lc -lpam -lsocket -lnsl -lm"
		SHLIB_CFLAGS="-KPIC"
		SHLIB_LDFLAGS="-G -Bsymbolic"
		TXLIBS="-lcurses"
		XCFLAGS64='${XCFLAGS} -xarch=amd64'
		XCFLAGS="-dy -Bdynamic"
		XLIBELFA="-lelf"
		XLIBKVM="-lkvm"
		XLIBS="${LIB_AFSDB} -lsocket -lnsl -lintl -ldl"
		SHLIB_LINKER="${CC} -G -dy -Bsymbolic -z text"
		;;
esac

#
# Special build targets
#
case $AFS_SYSNAME in
	sgi_6*)
		IRIX_SYS_SYSTM_H_HAS_MEM_FUNCS
		XFS_SIZE_CHECK="xfs_size_check"
		install_XFS_SIZE_CHECK='$(DESTDIR)${afssrvsbindir}/xfs_size_check'
		dest_XFS_SIZE_CHECK='$(DEST)/root.server/usr/afs/bin/xfs_size_check'
	
		AC_SUBST(XFS_SIZE_CHECK)
		AC_SUBST(install_XFS_SIZE_CHECK)
		AC_SUBST(dest_XFS_SIZE_CHECK)
	;;
esac

dnl Disable the default for debugging/optimization if not enabled
if test "x$enable_debug_kernel" = "xno"; then
  KERN_DBG=
fi

if test "x$enable_optimize_kernel" = "xno"; then
  KERN_OPTMZ=
fi

if test "x$enable_debug" = "xno"; then
  DBG=
  NO_STRIP_BIN=-s
fi

if test "x$enable_optimize" = "xno"; then
  OPTMZ=
fi

if test "x$enable_debug_lwp" = "xno"; then
  LWP_DBG=
fi

if test "x$enable_optimize_lwp" = "xno"; then
  LWP_OPTMZ=
fi

if test "x$enable_strip_binaries" != "xno"; then
  if test "x$enable_strip_binaries" = "xmaybe" -a "x$enable_debug" = "xyes"; then
    NO_STRIP_BIN=
  else
    NO_STRIP_BIN=-s
  fi
else
  NO_STRIP_BIN=
fi

CFLAGS_NOERROR=

if test "x$GCC" = "xyes"; then
  if test "x$enable_warnings" = "xyes"; then
    XCFLAGS="${XCFLAGS} -Wall -Wstrict-prototypes -Wold-style-definition -Wpointer-arith"
  fi
  if test "x$enable_checking" != "xno"; then
    XCFLAGS="${XCFLAGS} -Wall -Wstrict-prototypes -Wold-style-definition -Werror -fdiagnostics-show-option -Wpointer-arith"
    if test "x$enable_checking" != "xall"; then
      CFLAGS_NOERROR="-Wno-error"
      AC_DEFINE(IGNORE_SOME_GCC_WARNINGS, 1, [define to disable some gcc warnings in warnings-as-errors mode])
    fi
  fi
fi

CFLAGS_NOSTRICT=

if test "x$GCC" = "xyes"; then
  CFLAGS_NOSTRICT="-fno-strict-aliasing"
fi

if test "x$GCC" = "xyes"; then
  CFLAGS_NOUNUSED="-Wno-unused"
else
  CFLAGS_NOUNUSED=
fi

dnl horribly cheating, assuming double / is ok.
case $INSTALL in
  ./* ) 
    INSTALL="/@abs_top_srcdir@/install-sh -c"
  ;;
  *) 
  ;;
esac

INSTALL_PROGRAM="${INSTALL_PROGRAM} ${NO_STRIP_BIN}"

AC_SUBST(CCXPG2)
AC_SUBST(CCOBJ)
AC_SUBST(AFSD_LIBS)
AC_SUBST(AFSD_LDFLAGS)
AC_SUBST(AIX32)
AC_SUBST(AIX64)
AC_SUBST(AR)
AC_SUBST(AS)
AC_SUBST(CP)
AC_SUBST(DBG)
AC_SUBST(FSINCLUDES)
AC_SUBST(KERN_DBG)
AC_SUBST(KERN_OPTMZ)
AC_SUBST(LD)
AC_SUBST(LEX)
AC_SUBST(LWP_DBG)
AC_SUBST(LWP_OPTMZ)
AC_SUBST(MT_CC)
AC_SUBST(MT_CFLAGS)
AC_SUBST(MT_LIBS)
AC_SUBST(MV)
AC_SUBST(NO_STRIP_BIN)
AC_SUBST(OPTMZ)
AC_SUBST(PAM_CFLAGS)
AC_SUBST(PAM_LIBS)
AC_SUBST(PAM_DBG)
AC_SUBST(PAM_OPTMZ)
AC_SUBST(RANLIB)
AC_SUBST(REGEX_OBJ)
AC_SUBST(RM)
AC_SUBST(RXDEBUG)
AC_SUBST(SHLIB_CFLAGS)
AC_SUBST(SHLIB_LDFLAGS)
AC_SUBST(SHLIB_LINKER)
AC_SUBST(SHLIB_SUFFIX)
AC_SUBST(TXLIBS)
AC_SUBST(VFSCK_CFLAGS)
AC_SUBST(XCFLAGS)
AC_SUBST(CFLAGS_NOERROR)
AC_SUBST(CFLAGS_NOSTRICT)
AC_SUBST(CFLAGS_NOUNUSED)
AC_SUBST(XCFLAGS64)
AC_SUBST(XLDFLAGS)
AC_SUBST(XLDFLAGS64)
AC_SUBST(XLIBELFA)
AC_SUBST(XLIBKVM)
AC_SUBST(XLIBS)
AC_SUBST(YACC)


])
