AC_DEFUN([LINUX_EXPORTS_TASKLIST_LOCK], [
  AC_CHECK_LINUX_BUILD([for exported tasklist_lock],
		       [ac_cv_linux_exports_tasklist_lock],
[#include <linux/sched.h>],
[
extern rwlock_t tasklist_lock __attribute__((weak)); 
read_lock(&tasklist_lock);
],
		       [EXPORTED_TASKLIST_LOCK],
		       [define if tasklist_lock exported])
])

AC_DEFUN([LINUX_COMPLETION_H_EXISTS], [
  AC_CHECK_LINUX_BUILD([for linux/completion.h],
		       [ac_cv_linux_completion_h_exists],
[#include <linux/version.h>
#include <linux/completion.h>],
[struct completion _c;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,4,8)
lose
#endif],
		       [HAVE_LINUX_COMPLETION_H]
		       [Define if your kernel has a usable linux/completion.h])
])


AC_DEFUN([LINUX_EXPORTS_INIT_MM], [
  AC_CHECK_LINUX_BUILD([for exported init_mm],
		       [ac_cv_linux_exports_init_mm],
		       [extern struct mm_struct init_mm;],
		       [void *address = &init_mm; printk("%p\n", address);],
		       [EXPORTED_INIT_MM],
		       [define if your kernel exports init_mm])
  ])


AC_DEFUN([LINUX_EXPORTS_KALLSYMS_ADDRESS], [
  AC_CHECK_LINUX_BUILD([for exported kallsyms_address_to_symbol],
		       [ac_cv_linux_exports_kallsyms_address],
		       [#include <linux/modversions.h>],
[#ifndef __ver_kallsyms_address_to_symbol
#error kallsyms_address_to_symbol not exported
#endif],
		       [EXPORTED_KALLSYMS_ADDRESS],
		       [define if your linux kernel exports kallsyms address])
])


AC_DEFUN([LINUX_EXPORTS_KALLSYMS_SYMBOL], [
  AC_CHECK_LINUX_BUILD([for exported kallsyms_symbol_to_address],
		       [ac_cv_linux_exports_kallsyms_symbol],
		       [#include <linux/modversions.h>],
[#ifndef __ver_kallsyms_symbol_to_address
#error kallsyms_symbol_to_address not exported
#endif],
		       [EXPORTED_KALLSYMS_SYMBOL],
		       [define if your linux kernel exports kallsyms])
])


AC_DEFUN([LINUX_EXPORTS_SYS_CALL_TABLE], [
  AC_CHECK_LINUX_BUILD([for exported sys_call_table],
		       [ac_cv_linux_exports_sys_call_table],
		       [#include <linux/modversions.h>],
[#ifndef __ver_sys_call_table
#error sys_call_table not exported
#endif],
		       [EXPORTED_SYS_CALL_TABLE],
		       [define if your linux kernel exports sys_call_table])
])


AC_DEFUN([LINUX_EXPORTS_IA32_SYS_CALL_TABLE], [
  AC_CHECK_LINUX_BUILD([for exported ia32_sys_call_table],
		       [ac_cv_linux_exports_ia32_sys_call_table],
		       [#include <linux/modversions.h>],
[#ifndef __ver_ia32_sys_call_table
#error ia32_sys_call_table not exported
#endif],
		       [EXPORTED_IA32_SYS_CALL_TABLE],
		       [define if your linux kernel exports ia32_sys_call_table])
])


AC_DEFUN([LINUX_EXPORTS_SYS_CHDIR], [
  AC_CHECK_LINUX_BUILD([for exported sys_chdir],
		       [ac_cv_linux_exports_sys_chdir],
		       [extern asmlinkage long sys_chdir(void) __attribute__((weak));],
		       [void *address = &sys_chdir; printk("%p\n", address);],
		       [EXPORTED_SYS_CHDIR],
		       [define if your linux kernel exports sys_chdir])
])


AC_DEFUN([LINUX_EXPORTS_SYS_OPEN], [
  AC_CHECK_LINUX_BUILD([for exported sys_open],
		       [ac_cv_linux_exports_sys_open],
		       [extern asmlinkage long sys_open(void) __attribute__((weak));],
		       [void *address = &sys_open; printk("%p\n", address);],
		       [EXPORTED_SYS_OPEN],
		       [define if your linux kernel exports sys_open])
])


AC_DEFUN([LINUX_RECALC_SIGPENDING_ARG_TYPE], [
  AC_CHECK_LINUX_BUILD([for recalc_sigpending arg type],
		       [ac_cv_linux_func_recalc_sigpending_takes_void],
		       [#include <linux/sched.h>],
		       [recalc_sigpending();],
		       [RECALC_SIGPENDING_TAKES_VOID],
		       [define if your recalc_sigpending takes void])
])


AC_DEFUN([LINUX_SCHED_STRUCT_TASK_STRUCT_HAS_SIGNAL_RLIM], [
  AC_CHECK_LINUX_BUILD([for signal->rlim in struct task_struct],
		       [ac_cv_linux_sched_struct_task_struct_has_signal_rlim],
		       [#include <linux/sched.h>],
		       [struct task_struct _tsk; printk("%d\n", _tsk.signal->rlim);],
		       [STRUCT_TASK_STRUCT_HAS_SIGNAL_RLIM],
		       [define if your struct task_struct has signal->rlim])
])


AC_DEFUN([LINUX_KERNEL_POSIX_LOCK_FILE_WAIT_ARG], [
  AC_CHECK_LINUX_BUILD([for 3rd argument in posix_lock_file found in new kernels],
		       [ac_cv_linux_kernel_posix_lock_file_wait_arg],
		       [#include <linux/fs.h>],
		       [posix_lock_file(0,0,0);],
		       [POSIX_LOCK_FILE_WAIT_ARG],
		       [define if your kernel uses 3 arguments for posix_lock_file])
])

AC_DEFUN([LINUX_KERNEL_SOCK_CREATE], [
  AC_CHECK_LINUX_BUILD([for 5th argument in sock_create found in some SELinux kernels],
		       [ac_cv_linux_kernel_sock_create_v],
		       [#include <linux/net.h>],
		       [sock_create(0,0,0,0,0);],
		       [LINUX_KERNEL_SOCK_CREATE_V],
		       [define if your linux kernel uses 5 arguments for sock_create])
])


AC_DEFUN([LINUX_INODE_SETATTR_RETURN_TYPE], [
  AC_CHECK_LINUX_BUILD([for inode_setattr return type],
		       [ac_cv_linux_func_inode_setattr_returns_int],
		       [#include <linux/fs.h>],
		       [struct inode _inode;
			struct iattr _iattr;
			int i;
			i = inode_setattr(&_inode, &_iattr);],
		       [INODE_SETATTR_NOT_VOID],
		       [define if your setattr return return non-void])
])



AC_DEFUN([LINUX_AOP_WRITEBACK_CONTROL], [
  AC_CHECK_LINUX_BUILD([whether aop.writepage takes a writeback_control],
		       [ac_cv_linux_func_a_writepage_takes_writeback_control],
[#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/writeback.h>],
[struct address_space_operations _aops;
struct page _page;
struct writeback_control _writeback_control;
(void)_aops.writepage(&_page, &_writeback_control);],
		       [AOP_WRITEPAGE_TAKES_WRITEBACK_CONTROL],
		       [define if aops.writepage takes a struct writeback_control])
])


AC_DEFUN([LINUX_REFRIGERATOR], [
  AC_CHECK_LINUX_BUILD([whether refrigerator takes PF_FREEZE],
		       [ac_cv_linux_func_refrigerator_takes_pf_freeze],
[#include <linux/sched.h>
#ifdef HAVE_LINUX_FREEZER_H
#include <linux/freezer.h>
#endif],
		       [refrigerator(PF_FREEZE);],
		       [LINUX_REFRIGERATOR_TAKES_PF_FREEZE],
		       [define if your refrigerator takes PF_FREEZE])
])


AC_DEFUN([LINUX_IOP_I_CREATE_TAKES_NAMEIDATA], [
  AC_CHECK_LINUX_BUILD([whether inode_operations.create takes a nameidata],
		       [ac_cv_linux_func_i_create_takes_nameidata],
[#include <linux/fs.h>
#include <linux/namei.h>],
[struct inode _inode;
struct dentry _dentry;
struct nameidata _nameidata;
(void)_inode.i_op->create(&_inode, &_dentry, 0, &_nameidata);],

		       [IOP_CREATE_TAKES_NAMEIDATA],
		       [define if your iops.create takes a nameidata argument])
])


AC_DEFUN([LINUX_IOP_I_LOOKUP_TAKES_NAMEIDATA], [
  AC_CHECK_LINUX_BUILD([whether inode_operations.lookup takes a nameidata],
		       [ac_cv_linux_func_i_lookup_takes_nameidata],
[#include <linux/fs.h>
#include <linux/namei.h>],
[struct inode _inode;
struct dentry _dentry;
struct nameidata _nameidata;
(void)_inode.i_op->lookup(&_inode, &_dentry, &_nameidata);],
		       [IOP_LOOKUP_TAKES_NAMEIDATA],
		       [define if your iops.lookup takes a nameidata argument])
])


AC_DEFUN([LINUX_IOP_I_PERMISSION_TAKES_NAMEIDATA], [
  AC_CHECK_LINUX_BUILD([whether inode_operations.permission takes a nameidata],
		       [ac_cv_linux_func_i_permission_takes_nameidata],
[#include <linux/fs.h>
#include <linux/namei.h>],
[struct inode _inode;
struct dentry _dentry;
struct nameidata _nameidata;
(void)_inode.i_op->permission(&_inode, 0, &_nameidata);],
		       [IOP_PERMISSION_TAKES_NAMEIDATA],
		       [define if your iops.permission takes a nameidata argument])
])


AC_DEFUN([LINUX_IOP_I_PUT_LINK_TAKES_COOKIE], [
  AC_CHECK_LINUX_BUILD([whether inode_operations.put_link takes an opaque cookie],
		       [ac_cv_linux_func_i_put_link_takes_cookie],
[#include <linux/fs.h>
#include <linux/namei.h>],
[struct inode _inode;
struct dentry _dentry;
struct nameidata _nameidata;
void *cookie;
(void)_inode.i_op->put_link(&_dentry, &_nameidata, cookie);],
		       [IOP_PUT_LINK_TAKES_COOKIE],
		       [define if your iops.put_link takes a cookie])
])


AC_DEFUN([LINUX_DOP_D_REVALIDATE_TAKES_NAMEIDATA], [
  AC_CHECK_LINUX_BUILD([whether dentry_operations.d_revalidate takes a nameidata],
		       [ac_cv_linux_func_d_revalidate_takes_nameidata],
[#include <linux/fs.h>
#include <linux/namei.h>],
[struct dentry _dentry;
struct nameidata _nameidata;
(void)_dentry.d_op->d_revalidate(&_dentry, &_nameidata);],
		       [DOP_REVALIDATE_TAKES_NAMEIDATA],
		       [define if your dops.d_revalidate takes a nameidata argument])
])


AC_DEFUN([LINUX_GET_SB_HAS_STRUCT_VFSMOUNT], [
  AC_CHECK_LINUX_BUILD([for struct vfsmount * in get_sb_nodev()],
		       [ac_cv_linux_get_sb_has_struct_vfsmount],
		       [#include <linux/fs.h>],
		       [get_sb_nodev(0,0,0,0,0);],
		       [GET_SB_HAS_STRUCT_VFSMOUNT],
		       [define if your get_sb_nodev needs a struct vfsmount argument])
])


AC_DEFUN([LINUX_STATFS_TAKES_DENTRY], [
  AC_CHECK_LINUX_BUILD([for dentry in statfs],
		       [ac_cv_linux_statfs_takes_dentry],
[#include <linux/fs.h>
#include <linux/statfs.h>],
[struct super_block _sb;
struct dentry _dentry;
struct kstatfs _kstatfs;
(void)_sb.s_op->statfs(&_dentry, &_kstatfs);],
		       [STATFS_TAKES_DENTRY],
		       [define if your statfs takes a dentry argument])
])


AC_DEFUN([LINUX_LINUX_KEYRING_SUPPORT], [
  AC_CHECK_LINUX_BUILD([for linux kernel keyring support],
		       [ac_cv_linux_keyring_support],
[#include <linux/rwsem.h>
#ifdef HAVE_LINUX_KEY_TYPE_H
#include <linux/key-type.h>
#endif
#include <linux/key.h>
#include <linux/keyctl.h>],
[#ifdef CONFIG_KEYS
request_key(NULL, NULL, NULL);
#if !defined(KEY_POS_VIEW) || !defined(KEY_POS_SEARCH) || !defined(KEY_POS_SETATTR) 
#error "Your linux/key.h does not contain KEY_POS_VIEW or KEY_POS_SEARCH or KEY_POS_SETATTR"
#endif
#else
#error rebuild your kernel with CONFIG_KEYS
#endif],
		       [LINUX_KEYRING_SUPPORT],
		       [define if your kernel has keyring support])
])


AC_DEFUN([LINUX_KEY_ALLOC_NEEDS_STRUCT_TASK], [
  AC_CACHE_CHECK([if key_alloc() takes a struct task *],
		 [ac_cv_key_alloc_needs_struct_task],
[
    save_CPPFLAGS="$CPPFLAGS"
    CPPFLAGS="$CPPFLAGS -Werror -Wno-pointer-arith"
    AC_TRY_KBUILD(
[#include <linux/rwsem.h>
#include <linux/key.h>
],
[struct task_struct *t=NULL;
(void) key_alloc(NULL, NULL, 0, 0, t, 0, 0);],
      ac_cv_key_alloc_needs_struct_task=yes,
      ac_cv_key_alloc_needs_struct_task=no)
    CPPFLAGS="$save_CPPFLAGS"])
  AS_IF([test "x$ac_cv_key_alloc_needs_struct_task" = "xyes"],
	[AC_DEFINE([KEY_ALLOC_NEEDS_STRUCT_TASK], 1,
		   [define if key_alloc takes a struct task *])])
])


AC_DEFUN([LINUX_KEY_ALLOC_NEEDS_CRED], [
  AC_CACHE_CHECK([if key_alloc() takes credentials],
		  [ac_cv_key_alloc_needs_cred],
[
    save_CPPFLAGS="$CPPFLAGS"
    CPPFLAGS="$CPPFLAGS -Werror -Wno-pointer-arith"
    AC_TRY_KBUILD(
[#include <linux/rwsem.h>
#include <linux/key.h>],
[struct cred *c = NULL;
(void) key_alloc(NULL, NULL, 0, 0, c, 0, 0);],
      ac_cv_key_alloc_needs_cred=yes,
      ac_cv_key_alloc_needs_cred=no)
    CPPFLAGS="$save_CPPFLAGS"])
  AS_IF([test "x$ac_cv_key_alloc_needs_cred" = "xyes"],
	[AC_DEFINE([KEY_ALLOC_NEEDS_CRED], 1,
		   [define if key_alloc takes credentials])])
])


AC_DEFUN([LINUX_INIT_WORK_HAS_DATA], [
  AC_CHECK_LINUX_BUILD([whether INIT_WORK has a _data argument],
		       [ac_cv_linux_init_work_has_data],
[#include <linux/kernel.h>
#include <linux/workqueue.h>],
[ 
void f(struct work_struct *w) {}
struct work_struct *w;
int *i;
INIT_WORK(w,f,i);],
		       [INIT_WORK_HAS_DATA],
		       [define if INIT_WORK takes a data (3rd) argument])
])


AC_DEFUN([LINUX_REGISTER_SYSCTL_TABLE_NOFLAG], [
  AC_CHECK_LINUX_BUILD([whether register_sysctl_table has an insert_at_head argument],
		       [ac_cv_linux_register_sysctl_table_noflag],
		       [#include <linux/sysctl.h>],
		       [ctl_table *t; register_sysctl_table (t);],
		       [REGISTER_SYSCTL_TABLE_NOFLAG],
		       [define if register_sysctl_table has no insert_at head flag])
])


AC_DEFUN([LINUX_FOP_F_FLUSH_TAKES_FL_OWNER_T], [
  AC_CHECK_LINUX_BUILD([whether file_operations.flush takes a fl_owner_t],
		       [ac_cv_linux_func_f_flush_takes_fl_owner_t],
		       [#include <linux/fs.h>],
[struct inode _inode;
struct file _file;
fl_owner_t id;
(void)_inode.i_fop->flush(&_file, &id);],
		       [FOP_FLUSH_TAKES_FL_OWNER_T],
		       [define if your fops.flush takes an fl_owner_t argument])
])


AC_DEFUN([LINUX_FOP_F_FSYNC_TAKES_DENTRY], [
  AC_CHECK_LINUX_BUILD([whether file_operations.fsync takes a dentry argument],
		       [ac_cv_linux_func_f_fsync_takes_dentry],
		       [#include <linux/fs.h>],
[struct inode _inode;
struct file _file;
struct dentry _d;
(void)_inode.i_fop->fsync(&_file, &_d, 0);],
		       [FOP_FSYNC_TAKES_DENTRY],
		       [define if your fops.fsync takes an dentry argument])
])


AC_DEFUN([LINUX_HAVE_KMEM_CACHE_T], [
  AC_CHECK_LINUX_BUILD([whether kmem_cache_t exists],
		       [ac_cv_linux_have_kmem_cache_t],
		       [#include <linux/slab.h>],
		       [kmem_cache_t *k;],
		       [HAVE_KMEM_CACHE_T],
		       [define if kmem_cache_t exists])
])


AC_DEFUN([LINUX_KMEM_CACHE_CREATE_TAKES_DTOR], [
  AC_CHECK_LINUX_BUILD([whether kmem_cache_create takes a destructor argument],
		       [ac_cv_linux_kmem_cache_create_takes_dtor],
		       [#include <linux/slab.h>],
		       [kmem_cache_create(NULL, 0, 0, 0, NULL, NULL);],
		       [KMEM_CACHE_TAKES_DTOR],
		       [define if kmem_cache_create takes a destructor argument])
])


AC_DEFUN([LINUX_KMEM_CACHE_CREATE_CTOR_TAKES_VOID],[
  AC_CACHE_CHECK([whether kmem_cache_create constructor takes a void pointer],
		 [ac_cv_linux_kmem_cache_create_ctor_takes_void], [
    save_CPPFLAGS="$CPPFLAGS"
    CPPFLAGS="$CPPFLAGS -Werror"
    AC_TRY_KBUILD([#include <linux/slab.h>],
		  [void _ctor(void *v) { }; kmem_cache_create(NULL, 0, 0, 0, _ctor);],
		  ac_cv_linux_kmem_cache_create_ctor_takes_void=yes,
		  ac_cv_linux_kmem_cache_create_ctor_takes_void=no)
    CPPFLAGS="$save_CPPFLAGS"
  ])
  AS_IF([test "x$ac_cv_linux_kmem_cache_create_ctor_takes_void" = "xyes"],
        [AC_DEFINE([KMEM_CACHE_CTOR_TAKES_VOID], 1,
		   [define if kmem_cache_create constructor takes a single void ptr])])
])


dnl This function checks not just the existence of the splice functions,
dnl but also that the signature matches (they gained an extra argument
dnl around 2.6.17)
AC_DEFUN([LINUX_FS_STRUCT_FOP_HAS_SPLICE], [
  AC_CHECK_LINUX_BUILD([for splice_write and splice_read in struct file_operations],
		       [ac_cv_linux_fs_struct_fop_has_splice],
		       [#include <linux/fs.h>],
		       [struct file_operations _fop;
			_fop.splice_write(NULL, NULL, NULL, 0, 0);
			_fop.splice_read(NULL, NULL, NULL, 0, 0);],
		       [STRUCT_FILE_OPERATIONS_HAS_SPLICE],
		       [define if struct file_operations has splice functions])
])


AC_DEFUN([LINUX_KMEM_CACHE_INIT], [
  AC_CHECK_LINUX_BUILD([for new kmem_cache init function parameters],
		       [ac_cv_linux_kmem_cache_init],
		       [#include <linux/slab.h>],
		       [extern struct kmem_cache *
			kmem_cache_create(const char *, size_t, size_t,
					  unsigned long,
					  void (*)(struct kmem_cache *, void *));
			return;],
		       [KMEM_CACHE_INIT],
		       [define for new kmem_cache init function parameters])
])


AC_DEFUN([LINUX_EXPORTS_PROC_ROOT_FS], [
  AC_CHECK_LINUX_BUILD([if proc_root_fs is defined and exported],
		       [ac_cv_linux_exports_proc_root_fs],
		       [#include <linux/proc_fs.h>],
		       [struct proc_dir_entry *p = proc_root_fs;],
		       [EXPORTED_PROC_ROOT_FS],
		       [define if proc_root_fs is exported])
])


AC_DEFUN([LINUX_D_PATH_TAKES_STRUCT_PATH], [
  AC_CHECK_LINUX_BUILD([if d_path() takes a struct path argument],
		       [ac_cv_linux_d_path_takes_struct_path],
		       [#include <linux/dcache.h>],
		       [struct path *p; d_path(p, NULL, 0);],
		       [D_PATH_TAKES_STRUCT_PATH],
		       [define if d_path() takes a struct path argument])
])


AC_DEFUN([LINUX_NEW_EXPORT_OPS], [
  AC_CHECK_LINUX_BUILD([if kernel uses new export ops],
		       [ac_cv_linux_new_export_ops],
		       [#include <linux/exportfs.h>],
		       [struct export_operations _eops;
			_eops.fh_to_parent(NULL, NULL, 0, 0);],
		       [NEW_EXPORT_OPS],
		       [define if kernel uses new export ops])
])


AC_DEFUN([LINUX_POSIX_TEST_LOCK_RETURNS_CONFLICT], [
  AC_CHECK_LINUX_BUILD([if posix_test_lock returns a struct file_lock],
		       [ac_cv_linux_posix_test_lock_returns_conflict],
		       [#include <linux/fs.h>],
		       [struct file_lock *lock;
			struct file * file;
			lock = posix_test_lock(file, lock);],
		       [POSIX_TEST_LOCK_RETURNS_CONFLICT],
		       [define if posix_test_lock returns the conflicting lock])
])


AC_DEFUN([LINUX_POSIX_TEST_LOCK_CONFLICT_ARG], [
  AC_CHECK_LINUX_BUILD([if posix_test_lock takes a conflict argument],
		       [ac_cv_linux_posix_test_lock_conflict_arg],
		       [#include <linux/fs.h>],
		       [struct file_lock *lock;
			struct file *file;
			posix_test_lock(file, lock, lock);],
		       [POSIX_TEST_LOCK_CONFLICT_ARG],
		       [define if posix_test_lock takes a conflict argument])
])


AC_DEFUN([LINUX_EXPORTS_KEY_TYPE_KEYRING], [
  AC_CHECK_LINUX_BUILD([for exported key_type_keyring],
		       [ac_cv_linux_exports_key_type_keyring],
[
#ifdef HAVE_LINUX_KEY_TYPE_H
#include <linux/key-type.h>
#endif
#include <linux/key.h>
],
		       [printk("%s", key_type_keyring.name);],
		       [EXPORTED_KEY_TYPE_KEYRING],
		       [define if key_type_keyring is exported])
])


AC_DEFUN([LINUX_KEYS_HAVE_SESSION_TO_PARENT], [
  AC_CHECK_LINUX_BUILD([for KEYCTL_SESSION_TO_PARENT],
		       [ac_cv_linux_have_session_to_parent],
		       [#include <linux/keyctl.h>],
		       [int i = KEYCTL_SESSION_TO_PARENT;],
		       [HAVE_SESSION_TO_PARENT],
		       [define if keyctl has the KEYCTL_SESSION_TO_PARENT function])
])


AC_DEFUN([LINUX_HAVE_TRY_TO_FREEZE], [
  AC_CHECK_LINUX_BUILD([for try_to_freeze],
		       [ac_cv_linux_have_try_to_freeze],
[#include <linux/sched.h>
#ifdef HAVE_LINUX_FREEZER_H
#include <linux/freezer.h>
#endif],
[#ifdef LINUX_REFRIGERATOR_TAKES_PF_FREEZE
   try_to_freeze(PF_FREEZE);
#else
   try_to_freeze();
#endif],
		       [HAVE_TRY_TO_FREEZE],
                       [define if your kernel has the try_to_freeze function])
])

