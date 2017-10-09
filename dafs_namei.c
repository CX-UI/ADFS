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

    err = dafs_add_dentry(dentry, ino);

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
