#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x1ecfbc75, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0xc6fa97a1, __VMLINUX_SYMBOL_STR(d_path) },
	{ 0x2e48c332, __VMLINUX_SYMBOL_STR(kmem_cache_destroy) },
	{ 0x3356b90b, __VMLINUX_SYMBOL_STR(cpu_tss) },
	{ 0x52dae182, __VMLINUX_SYMBOL_STR(iget_failed) },
	{ 0x81bb7027, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0xd2b09ce5, __VMLINUX_SYMBOL_STR(__kmalloc) },
	{ 0x405c1144, __VMLINUX_SYMBOL_STR(get_seconds) },
	{ 0x4551320b, __VMLINUX_SYMBOL_STR(drop_nlink) },
	{ 0xdcded42b, __VMLINUX_SYMBOL_STR(make_bad_inode) },
	{ 0x8d92af0e, __VMLINUX_SYMBOL_STR(generic_file_llseek) },
	{ 0x6bf1c17f, __VMLINUX_SYMBOL_STR(pv_lock_ops) },
	{ 0x2f9b9bdb, __VMLINUX_SYMBOL_STR(single_open) },
	{ 0xbb155188, __VMLINUX_SYMBOL_STR(mntget) },
	{ 0xb1333933, __VMLINUX_SYMBOL_STR(param_ops_int) },
	{ 0x754d539c, __VMLINUX_SYMBOL_STR(strlen) },
	{ 0x60a13e90, __VMLINUX_SYMBOL_STR(rcu_barrier) },
	{ 0x815b5dd4, __VMLINUX_SYMBOL_STR(match_octal) },
	{ 0x2c5058bc, __VMLINUX_SYMBOL_STR(dax_pfn_mkwrite) },
	{ 0xa1fb36f2, __VMLINUX_SYMBOL_STR(generic_fh_to_parent) },
	{ 0xc4f331c6, __VMLINUX_SYMBOL_STR(cpu_online_mask) },
	{ 0x1db7706b, __VMLINUX_SYMBOL_STR(__copy_user_nocache) },
	{ 0x79aa04a2, __VMLINUX_SYMBOL_STR(get_random_bytes) },
	{ 0x3fae276, __VMLINUX_SYMBOL_STR(single_release) },
	{ 0x5624fead, __VMLINUX_SYMBOL_STR(seq_puts) },
	{ 0x7f456e46, __VMLINUX_SYMBOL_STR(is_bad_inode) },
	{ 0xd30d1a0c, __VMLINUX_SYMBOL_STR(generic_file_open) },
	{ 0x8e082688, __VMLINUX_SYMBOL_STR(_raw_read_lock) },
	{ 0xc38d6a5f, __VMLINUX_SYMBOL_STR(touch_atime) },
	{ 0xc0a3d105, __VMLINUX_SYMBOL_STR(find_next_bit) },
	{ 0x555f6938, __VMLINUX_SYMBOL_STR(lockref_get) },
	{ 0x56d4ca56, __VMLINUX_SYMBOL_STR(seq_printf) },
	{ 0x3ee111c7, __VMLINUX_SYMBOL_STR(remove_proc_entry) },
	{ 0x6729d3df, __VMLINUX_SYMBOL_STR(__get_user_4) },
	{ 0x44e9a829, __VMLINUX_SYMBOL_STR(match_token) },
	{ 0x74c8bfdb, __VMLINUX_SYMBOL_STR(inc_nlink) },
	{ 0x51ab9d31, __VMLINUX_SYMBOL_STR(d_find_alias) },
	{ 0x46382695, __VMLINUX_SYMBOL_STR(init_user_ns) },
	{ 0xa2ce08c3, __VMLINUX_SYMBOL_STR(mutex_unlock) },
	{ 0x84db4d71, __VMLINUX_SYMBOL_STR(mount_bdev) },
	{ 0x85df9b6c, __VMLINUX_SYMBOL_STR(strsep) },
	{ 0x2e06a20a, __VMLINUX_SYMBOL_STR(generic_read_dir) },
	{ 0x999e8297, __VMLINUX_SYMBOL_STR(vfree) },
	{ 0x7a2af7b4, __VMLINUX_SYMBOL_STR(cpu_number) },
	{ 0x26948d96, __VMLINUX_SYMBOL_STR(copy_user_enhanced_fast_string) },
	{ 0xf2028c05, __VMLINUX_SYMBOL_STR(seq_read) },
	{ 0x5a677a1f, __VMLINUX_SYMBOL_STR(kthread_create_on_node) },
	{ 0xe2d5255a, __VMLINUX_SYMBOL_STR(strcmp) },
	{ 0xc6b2adc5, __VMLINUX_SYMBOL_STR(kthread_bind) },
	{ 0xece784c2, __VMLINUX_SYMBOL_STR(rb_first) },
	{ 0xe1da2635, __VMLINUX_SYMBOL_STR(make_kgid) },
	{ 0x9e88526, __VMLINUX_SYMBOL_STR(__init_waitqueue_head) },
	{ 0x36537480, __VMLINUX_SYMBOL_STR(PDE_DATA) },
	{ 0xfe7c4287, __VMLINUX_SYMBOL_STR(nr_cpu_ids) },
	{ 0xe8ef0ff0, __VMLINUX_SYMBOL_STR(current_kernel_time64) },
	{ 0xb6c5f26a, __VMLINUX_SYMBOL_STR(inode_owner_or_capable) },
	{ 0xfb578fc5, __VMLINUX_SYMBOL_STR(memset) },
	{ 0xafcbb988, __VMLINUX_SYMBOL_STR(from_kuid) },
	{ 0xe028b046, __VMLINUX_SYMBOL_STR(proc_mkdir) },
	{ 0xd315aef7, __VMLINUX_SYMBOL_STR(current_task) },
	{ 0xb43c92a7, __VMLINUX_SYMBOL_STR(__mutex_init) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0xd56b3dc0, __VMLINUX_SYMBOL_STR(kthread_stop) },
	{ 0x4c77f560, __VMLINUX_SYMBOL_STR(d_obtain_alias) },
	{ 0xafb8c6ff, __VMLINUX_SYMBOL_STR(copy_user_generic_string) },
	{ 0x7c1372e8, __VMLINUX_SYMBOL_STR(panic) },
	{ 0x686ce552, __VMLINUX_SYMBOL_STR(file_remove_privs) },
	{ 0x479c3c86, __VMLINUX_SYMBOL_STR(find_next_zero_bit) },
	{ 0xa1c76e0a, __VMLINUX_SYMBOL_STR(_cond_resched) },
	{ 0x4d9b652b, __VMLINUX_SYMBOL_STR(rb_erase) },
	{ 0xf3341268, __VMLINUX_SYMBOL_STR(__clear_user) },
	{ 0x74b96fd1, __VMLINUX_SYMBOL_STR(from_kgid) },
	{ 0xa4511467, __VMLINUX_SYMBOL_STR(crc16) },
	{ 0xbf8ba54a, __VMLINUX_SYMBOL_STR(vprintk) },
	{ 0x8e1b70ce, __VMLINUX_SYMBOL_STR(kmem_cache_free) },
	{ 0x65fb04fa, __VMLINUX_SYMBOL_STR(mutex_lock) },
	{ 0xd759656d, __VMLINUX_SYMBOL_STR(set_nlink) },
	{ 0x460f082d, __VMLINUX_SYMBOL_STR(setattr_copy) },
	{ 0xf0a8237a, __VMLINUX_SYMBOL_STR(radix_tree_gang_lookup_tag) },
	{ 0x95ff76b1, __VMLINUX_SYMBOL_STR(insert_inode_locked) },
	{ 0x19f12bc7, __VMLINUX_SYMBOL_STR(truncate_pagecache) },
	{ 0x4e3567f7, __VMLINUX_SYMBOL_STR(match_int) },
	{ 0xd8abc43c, __VMLINUX_SYMBOL_STR(generic_file_read_iter) },
	{ 0x952664c5, __VMLINUX_SYMBOL_STR(do_exit) },
	{ 0x3c483012, __VMLINUX_SYMBOL_STR(radix_tree_delete) },
	{ 0x813c15dd, __VMLINUX_SYMBOL_STR(dax_fault) },
	{ 0x61651be, __VMLINUX_SYMBOL_STR(strcat) },
	{ 0x5b86cc71, __VMLINUX_SYMBOL_STR(dax_do_io) },
	{ 0x5e15eb3e, __VMLINUX_SYMBOL_STR(inode_init_once) },
	{ 0xd21140ad, __VMLINUX_SYMBOL_STR(mntput) },
	{ 0x72a98fdb, __VMLINUX_SYMBOL_STR(copy_user_generic_unrolled) },
	{ 0xf906ddf7, __VMLINUX_SYMBOL_STR(mnt_drop_write_file) },
	{ 0xc6cbbc89, __VMLINUX_SYMBOL_STR(capable) },
	{ 0x9f984513, __VMLINUX_SYMBOL_STR(strrchr) },
	{ 0x40a9b349, __VMLINUX_SYMBOL_STR(vzalloc) },
	{ 0xe20372ae, __VMLINUX_SYMBOL_STR(radix_tree_gang_lookup) },
	{ 0xaed5a83f, __VMLINUX_SYMBOL_STR(kmem_cache_alloc) },
	{ 0x78764f4e, __VMLINUX_SYMBOL_STR(pv_irq_ops) },
	{ 0xb2fd5ceb, __VMLINUX_SYMBOL_STR(__put_user_4) },
	{ 0x7985d043, __VMLINUX_SYMBOL_STR(radix_tree_tag_set) },
	{ 0xca0f4667, __VMLINUX_SYMBOL_STR(readlink_copy) },
	{ 0xf2d8af10, __VMLINUX_SYMBOL_STR(make_kuid) },
	{ 0xc6772da2, __VMLINUX_SYMBOL_STR(radix_tree_lookup_slot) },
	{ 0xf82ec573, __VMLINUX_SYMBOL_STR(rb_prev) },
	{ 0xdb7305a1, __VMLINUX_SYMBOL_STR(__stack_chk_fail) },
	{ 0xb152d87d, __VMLINUX_SYMBOL_STR(cpu_possible_mask) },
	{ 0xd62c833f, __VMLINUX_SYMBOL_STR(schedule_timeout) },
	{ 0x8efcb3fe, __VMLINUX_SYMBOL_STR(unlock_new_inode) },
	{ 0xbda5a438, __VMLINUX_SYMBOL_STR(mnt_want_write_file) },
	{ 0x566579de, __VMLINUX_SYMBOL_STR(kill_block_super) },
	{ 0xa2f9d8f3, __VMLINUX_SYMBOL_STR(pv_cpu_ops) },
	{ 0xbeed9b3f, __VMLINUX_SYMBOL_STR(wake_up_process) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
	{ 0x64f389ee, __VMLINUX_SYMBOL_STR(inode_change_ok) },
	{ 0x123f82f3, __VMLINUX_SYMBOL_STR(getrawmonotonic64) },
	{ 0xa0408575, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0xe259ae9e, __VMLINUX_SYMBOL_STR(_raw_spin_lock) },
	{ 0x5ecfeec6, __VMLINUX_SYMBOL_STR(__per_cpu_offset) },
	{ 0xa5526619, __VMLINUX_SYMBOL_STR(rb_insert_color) },
	{ 0x8ad4ba67, __VMLINUX_SYMBOL_STR(kmem_cache_create) },
	{ 0xa9d0e1bd, __VMLINUX_SYMBOL_STR(register_filesystem) },
	{ 0xa6bbd805, __VMLINUX_SYMBOL_STR(__wake_up) },
	{ 0x722dc6a2, __VMLINUX_SYMBOL_STR(generic_file_write_iter) },
	{ 0xb3f7646e, __VMLINUX_SYMBOL_STR(kthread_should_stop) },
	{ 0x2207a57f, __VMLINUX_SYMBOL_STR(prepare_to_wait_event) },
	{ 0x2e641f74, __VMLINUX_SYMBOL_STR(proc_create_data) },
	{ 0xa3f2afa5, __VMLINUX_SYMBOL_STR(seq_lseek) },
	{ 0x15b1cf2a, __VMLINUX_SYMBOL_STR(iput) },
	{ 0x9c55cec, __VMLINUX_SYMBOL_STR(schedule_timeout_interruptible) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0x18353fca, __VMLINUX_SYMBOL_STR(inode_dio_wait) },
	{ 0xad393fe7, __VMLINUX_SYMBOL_STR(ihold) },
	{ 0x69acdf38, __VMLINUX_SYMBOL_STR(memcpy) },
	{ 0x27df546d, __VMLINUX_SYMBOL_STR(__sb_end_write) },
	{ 0xa75312bc, __VMLINUX_SYMBOL_STR(call_rcu_sched) },
	{ 0x54c8c67e, __VMLINUX_SYMBOL_STR(d_splice_alias) },
	{ 0xa34c586c, __VMLINUX_SYMBOL_STR(__sb_start_write) },
	{ 0x4bc3bb0f, __VMLINUX_SYMBOL_STR(d_make_root) },
	{ 0xf08242c2, __VMLINUX_SYMBOL_STR(finish_wait) },
	{ 0x844e3767, __VMLINUX_SYMBOL_STR(radix_tree_lookup) },
	{ 0x63c4d61f, __VMLINUX_SYMBOL_STR(__bitmap_weight) },
	{ 0xca9360b5, __VMLINUX_SYMBOL_STR(rb_next) },
	{ 0xacc81355, __VMLINUX_SYMBOL_STR(unregister_filesystem) },
	{ 0x9e68ab6f, __VMLINUX_SYMBOL_STR(init_special_inode) },
	{ 0xd9e29712, __VMLINUX_SYMBOL_STR(new_inode) },
	{ 0x1b384c2a, __VMLINUX_SYMBOL_STR(noop_fsync) },
	{ 0x19d4ecb, __VMLINUX_SYMBOL_STR(generic_fh_to_dentry) },
	{ 0x614bb773, __VMLINUX_SYMBOL_STR(radix_tree_insert) },
	{ 0xf3fda6e9, __VMLINUX_SYMBOL_STR(clear_inode) },
	{ 0xcc1de95b, __VMLINUX_SYMBOL_STR(dax_pmd_fault) },
	{ 0xdd6c1685, __VMLINUX_SYMBOL_STR(d_instantiate) },
	{ 0x20dc3285, __VMLINUX_SYMBOL_STR(clear_nlink) },
	{ 0x48ae02b8, __VMLINUX_SYMBOL_STR(iget_locked) },
	{ 0x6f66bf, __VMLINUX_SYMBOL_STR(generic_fillattr) },
	{ 0xdd2dffb9, __VMLINUX_SYMBOL_STR(inode_init_owner) },
	{ 0xe914e41e, __VMLINUX_SYMBOL_STR(strcpy) },
	{ 0xa91ae250, __VMLINUX_SYMBOL_STR(truncate_inode_pages) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "A846C97C302B9313AE71E60");
