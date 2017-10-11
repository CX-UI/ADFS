/*************************************************************************
	> File Name: dafs_namei.c
	> Author:CX
	> Mail: tianfangmmr@126.com
	> Created Time: 2017年10月09日 星期一 14时46分02秒
 ************************************************************************/

#include <linux/fs.h>
#include <linux/pagemap.h>
#include "nova.h"
#include "zone.h"

static int dafs_create(struct inode *dir, struct dentry *dentry, umode_t mode, bool excl)
{
    struct inode *inode = NULL;
    int err = PTR_ERR(inode);
    struct super_block *sb = dir->i_sb;
    struct nova_inode *pidir, *pi;
    u64 pi_addr = 0;
    u64 tail = 0;
    u64 ino;
    timing_t create_time;

    NOVA_START_TIMING(create_t, create_time);

    pidir = nova_get_inode(sb ,dir);
    if(!pidir)
        goto out_err;
    /*在used list上面分配节点号*/
    ino = nova_new_nova_inode(sb, &pi_addr);
    if(ino == 0)
        goto out_err;

    err = dafs_add_dentry(dentry, ino, 0);
    if(err)
        goto out_err;
    
	nova_dbgv("%s: %s\n", __func__, dentry->d_name.name);
	nova_dbgv("%s: inode %llu, dir %lu\n", __func__, ino, dir->i_ino);
	inode = nova_new_vfs_inode(TYPE_CREATE, dir, pi_addr, ino, mode,
					0, 0, &dentry->d_name);

	if (IS_ERR(inode))
		goto out_err;

	d_instantiate(dentry, inode);
	unlock_new_inode(inode);

    pi = nova_get_block(sb ,pi_addr);
    //not decided 需要重新考量关于tail的所有的操作
	nova_lite_transaction_for_new_inode(sb, pi, pidir, tail);
	NOVA_END_TIMING(create_t, create_time);
	return err;
out_err:
    nova_err(sb, "%s return %d\n", __func__, err);
	NOVA_END_TIMING(create_t, create_time);
	return err;

}


const struct inode_operations dafs_dir_inode_operations = {
    .create     = dafs_create,
    .lookup     = dafs_lookup,
    .link       = dafs_link,
    .unlink     = dafs_unlink,
    .symlink    = dafs_symlink,
    .mkdir      = dafs_mkdir,
    .rmdir      = dafs_rmdir,
    .mknod      = dafs_mknod,
    .rename     = dafs_rename,
    .setattr    = dafs_notify_change,
    .get_acl    = NULL,
};

const struct inode_operations dafs_special_inode_operations = {
    .setattr    = dafs_notify_change,
    .get_acl    = NULL,
};
