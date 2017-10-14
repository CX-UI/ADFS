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

    /*文件所在的目录的inode*/
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
    //这个是目录于新建的文件之间的关系，not decided
	nova_lite_transaction_for_new_inode(sb, pi, pidir, tail);
	NOVA_END_TIMING(create_t, create_time);
	return err;

out_err:
    nova_err(sb, "%s return %d\n", __func__, err);
	NOVA_END_TIMING(create_t, create_time);
	return err;

}

/*dentry to get path name and dzt_ei*/
static ino_t dafs_inode_by_name(struct inode *dir, const struct dentry *dentry,\
        struct dafs_dentry **res_entry)
{
    struct super_block *sb = dir->i_sb;
    struct dafs_dentry *direntry;
    
    direntry = dafs_find_direntry(sb, dentry);
    if(direntry == NULL)
        return 0;
    
    *res_entry = direntry;
    return direntry->ino;
}

static struct dentry *dafs_lookup(struct inode *dir, struct dentry *dentry,\
        unsigned int flags)
{
    struct inode *inode = NULL;
    struct dafs_dentry *de;
    ino_t ino;
    timing_t look_up_time;
    
	NOVA_START_TIMING(lookup_t, lookup_time);
	if (dentry->d_name.len > NOVA_NAME_LEN) {
		nova_dbg("%s: namelen %u exceeds limit\n",
			__func__, dentry->d_name.len);
		return ERR_PTR(-ENAMETOOLONG);
	}

	nova_dbg_verbose("%s: %s\n", __func__, dentry->d_name.name);
    ino = dafs_inode_by_name(dir, dentry, &de);
	nova_dbg_verbose("%s: ino %lu\n", __func__, ino);
	if (ino) {
        //根据ino得到整个inode的数据结构
		inode = nova_iget(dir->i_sb, ino);
		if (inode == ERR_PTR(-ESTALE) || inode == ERR_PTR(-ENOMEM)
				|| inode == ERR_PTR(-EACCES)) {
			nova_err(dir->i_sb,
				  "%s: get inode failed: %lu\n",
				  __func__, (unsigned long)ino);
			return ERR_PTR(-EIO);
		}
	}

	NOVA_END_TIMING(lookup_t, lookup_time);
	return d_splice_alias(inode, dentry);
}

/* Returns new tail after append 
 * 这个没有改动*/
int dafs_append_link_change_entry(struct super_block *sb,
	struct nova_inode *pi, struct inode *inode, u64 tail, u64 *new_tail)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_link_change_entry *entry;
	u64 curr_p;
	int extended = 0;
	size_t size = sizeof(struct nova_link_change_entry);
	timing_t append_time;

	NOVA_START_TIMING(append_link_change_t, append_time);
	nova_dbg_verbose("%s: inode %lu attr change\n",
				__func__, inode->i_ino);

	curr_p = nova_get_append_head(sb, pi, sih, tail, size, &extended);
	if (curr_p == 0)
		return -ENOMEM;

	entry = (struct nova_link_change_entry *)nova_get_block(sb, curr_p);
	entry->entry_type = LINK_CHANGE;
	entry->links = cpu_to_le16(inode->i_nlink);
	entry->ctime = cpu_to_le32(inode->i_ctime.tv_sec);
	entry->flags = cpu_to_le32(inode->i_flags);
	entry->generation = cpu_to_le32(inode->i_generation);
	nova_flush_buffer(entry, size, 0);
	*new_tail = curr_p + size;
	sih->last_link_change = curr_p;

	NOVA_END_TIMING(append_link_change_t, append_time);
	return 0;
}

/*没改*/
static void dafs_lite_transaction_for_time_and_link(struct super_block *sb,
	struct nova_inode *pi, struct nova_inode *pidir, u64 pi_tail,
	u64 pidir_tail, int invalidate)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_lite_journal_entry entry;
	u64 journal_tail;
	int cpu;
	timing_t trans_time;

	NOVA_START_TIMING(link_trans_t, trans_time);

	/* Commit a lite transaction */
	memset(&entry, 0, sizeof(struct nova_lite_journal_entry));
	entry.addrs[0] = (u64)nova_get_addr_off(sbi, &pi->log_tail);
	entry.addrs[0] |= (u64)8 << 56;
	entry.values[0] = pi->log_tail;

	entry.addrs[1] = (u64)nova_get_addr_off(sbi, &pidir->log_tail);
	entry.addrs[1] |= (u64)8 << 56;
	entry.values[1] = pidir->log_tail;

	if (invalidate) {
		entry.addrs[2] = (u64)nova_get_addr_off(sbi, &pi->valid);
		entry.addrs[2] |= (u64)1 << 56;
		entry.values[2] = pi->valid;
	}

	cpu = smp_processor_id();
	spin_lock(&sbi->journal_locks[cpu]);
	journal_tail = nova_create_lite_transaction(sb, &entry, NULL, 1, cpu);

	pi->log_tail = pi_tail;
	nova_flush_buffer(&pi->log_tail, CACHELINE_SIZE, 0);
	pidir->log_tail = pidir_tail;
	nova_flush_buffer(&pidir->log_tail, CACHELINE_SIZE, 0);
	if (invalidate) {
		pi->valid = 0;
		nova_flush_buffer(&pi->valid, CACHELINE_SIZE, 0);
	}
	PERSISTENT_BARRIER();

	nova_commit_lite_transaction(sb, journal_tail, cpu);
	spin_unlock(&sbi->journal_locks[cpu]);
	NOVA_END_TIMING(link_trans_t, trans_time);
}

static int dafs_link(struct dentry *dest_dentry, struct inode *dir, struct dentry *dentry)
{
    struct super_block *sb = dir->i_sb;
    struct inode *inode = dest_dentry->d_inode;
    struct nova_inode *pi = nova_get_inode(sb, inode);
    struct nova_inode *pidir;
    u64 pidir_tail = 0, pi_tail = 0;
    int err = -ENOMEM;
    time_t link_time;

    NOVA_START_TIMING(link_t, link_time);
    
	if (inode->i_nlink >= NOVA_LINK_MAX) {
		err = -EMLINK;
		goto out;
	}

	pidir = nova_get_inode(sb, dir);
	if (!pidir) {
		err = -EINVAL;
		goto out;
	}

	ihold(inode);
	nova_dbgv("%s: name %s, dest %s\n", __func__,
			dentry->d_name.name, dest_dentry->d_name.name);
	nova_dbgv("%s: inode %lu, dir %lu\n", __func__,
			inode->i_ino, dir->i_ino);
    /*增加一条硬链接就是新建了一个direntry但是inode早已存在的故事
     * tail应该增加修改 not decided*/
    err = dafs_add_dentry(dentry, inode->i_no, 0);
	if (err) {
		iput(inode);
		goto out;
	}

	inode->i_ctime = CURRENT_TIME_SEC;
	inc_nlink(inode);

	err = dafs_append_link_change_entry(sb, pi, inode, 0, &pi_tail);
	if (err) {
		iput(inode);
		goto out;
	}

	d_instantiate(dentry, inode);
	dafs_lite_transaction_for_time_and_link(sb, pi, pidir,
						pi_tail, pidir_tail, 0);

out:
	NOVA_END_TIMING(link_t, link_time);
	return err;

}

static int dafs_unlink(struct inode *dir, struct dentry *dentry)
{
    struct inode *inode = dentry->d_inode;
    struct super_block *sb = dir->i_sb;
    int retval = -ENOMEM;
    struct nova_inode *pi = nova_get_inode(sb, inode);
    struct nova_inode *pidir;
    u64 pidir_tail = 0, pi_tail = 0;
    int invalidate = 0;
    timing_t unlink_time;

	NOVA_START_TIMING(unlink_t, unlink_time);

	pidir = nova_get_inode(sb, dir);
	if (!pidir)
		goto out;

	nova_dbgv("%s: %s\n", __func__, dentry->d_name.name);
	nova_dbgv("%s: inode %lu, dir %lu\n", __func__,
				inode->i_ino, dir->i_ino);
    //注意更改tail
    retval = dafs_remove_dentry(dentry);

	if (retval)
		goto out;

	inode->i_ctime = dir->i_ctime;

	if (inode->i_nlink == 1)
		invalidate = 1;

	if (inode->i_nlink) {
		drop_nlink(inode);
	}

    /*not decided 返回值没有弄好*/
    retval = nova_append_link_change_entry(sb, pi, inode, 0, &pi_tail);
	if (retval)
		goto out;

	nova_lite_transaction_for_time_and_link(sb, pi, pidir,
					pi_tail, pidir_tail, invalidate);

	NOVA_END_TIMING(unlink_t, unlink_time);
	return 0;

out:
	nova_err(sb, "%s return %d\n", __func__, retval);
	NOVA_END_TIMING(unlink_t, unlink_time);
	return retval;
}

static int dafs_symlink(struct inode *dir, struct dentry *dentry, const char *symname)
{
    struct super_block *sb = dir->i_sb;
    int err = -ENAMETOOLONG;
    unsigned len = strlen(symname);
    struct inode *inode;
    u64 pi_addr = 0;
    struct nova_inode *pidir, *pi;
    u64 log_back = 0;
    unsigned long name_blocknr = 0;
    int allocated;
    u64 tail = 0;
    u64 ino;
    timing_t symlink_time;
    
	NOVA_START_TIMING(symlink_t, symlink_time);
	if (len + 1 > sb->s_blocksize)
		goto out;

	pidir = nova_get_inode(sb, dir);
	if (!pidir)
		goto out_fail1;
 
	ino = nova_new_nova_inode(sb, &pi_addr);
	if (ino == 0)
		goto out_fail1;

	nova_dbgv("%s: name %s, symname %s\n", __func__,
				dentry->d_name.name, symname);
	nova_dbgv("%s: inode %llu, dir %lu\n", __func__, ino, dir->i_ino);
    err = dafs_add_dentry(dentry, ino ,0);

	if (err)
		goto out_fail1;

	inode = nova_new_vfs_inode(TYPE_SYMLINK, dir, pi_addr, ino,
					S_IFLNK|S_IRWXUGO, len, 0,
					&dentry->d_name);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_fail1;
	}

	pi = nova_get_inode(sb, inode);
	allocated = nova_allocate_inode_log_pages(sb, pi,
						1, &log_block);
	if (allocated != 1 || log_block == 0) {
		err = allocated;
		goto out_fail1;
	}

	allocated = nova_new_data_blocks(sb, pi, &name_blocknr,
					1, 0, 1, 0);
	if (allocated != 1 || name_blocknr == 0) {
		err = allocated;
		goto out_fail2;
	}

	pi->i_blocks = 2;
	nova_block_symlink(sb, pi, inode, log_block, name_blocknr,
				symname, len);
	d_instantiate(dentry, inode);
	unlock_new_inode(inode);

	nova_lite_transaction_for_new_inode(sb, pi, pidir, tail);
out:
	NOVA_END_TIMING(symlink_t, symlink_time);
	return err;

out_fail2:
	nova_free_log_blocks(sb, pi, log_block >> PAGE_SHIFT, 1);
out_fail1:
	nova_err(sb, "%s return %d\n", __func__, err);
	goto out;
}

static int dafs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
    struct super_block *sb = dir->i_sb;
    struct inode *inode;
    struct nova_inode *pidir, *pi;
    //struct nova_inode_info *si;
    //struct nova_inode_info_header *sih = NULL;
    u64 pi_addr = 0;
    u64 tail = 0;
    u64 ino;
    int err = -EMLINK;
    timing_t mkdir_time;
    
    NOVA_START_TIMING(mkdir_t, mkdir_time);
    if(dir->i_nlink >= NOVA_LINK_MAX)
        goto out;
    
    ino = nova_new_nova_inode(sb, &pi_addr);
	if (ino == 0)
		goto out_err;

	nova_dbgv("%s: name %s\n", __func__, dentry->d_name.name);
	nova_dbgv("%s: inode %llu, dir %lu, link %d\n", __func__,
				ino, dir->i_ino, dir->i_nlink);

    /*.文件指向目录项*/
    err = dafs_add_dentry(dentry, ino, 1);
	if (err) {
		nova_dbg("failed to add dir entry\n");
		goto out_err;
	}

	inode = nova_new_vfs_inode(TYPE_MKDIR, dir, pi_addr, ino,
					S_IFDIR | mode, sb->s_blocksize,
					0, &dentry->d_name);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_err;
	}

	pi = nova_get_inode(sb, inode);
    dafs_append_dir_init_entries(sb, pi, inode->i, dir->i_ino);
   
    //dafs不需要rebuild dir tree

	pidir = nova_get_inode(sb, dir);
	dir->i_blocks = pidir->i_blocks;
	inc_nlink(dir);
	d_instantiate(dentry, inode);
	unlock_new_inode(inode);

	nova_lite_transaction_for_new_inode(sb, pi, pidir, tail);
out:
	NOVA_END_TIMING(mkdir_t, mkdir_time);
	return err;

out_err:
//	clear_nlink(inode);
	nova_err(sb, "%s return %d\n", __func__, err);
	goto out;
}


static int dafs_rmdir(struct inode *dir, struct dentry *dentry)
{
    struct inode *inode = dentry->d_inode;
    struct dafs_dentry *de;
    struct super_block *sb;
    struct nova_inode *pi = nova_get_inode(sb, inode), *pidir;
    u64 pidir_tail = 0, pi_tail = 0;
    struct nova_inode_info *si = NOVA_I(inode);
    struct nova_inode_info_header *sih = &si->header;
    int err = -ENOTEMPTY;
    timing_t rmdir_time;

	NOVA_START_TIMING(rmdir_t, rmdir_time);
	if (!inode)
		return -ENOENT;

	nova_dbgv("%s: name %s\n", __func__, dentry->d_name.name);
	pidir = nova_get_inode(sb, dir);
	if (!pidir)
		return -EINVAL;

    if(dafs_inode_by_name(dir, dentry, &de) == 0)
        return -ENOENT;

    if(!dafs_empty_dir(inode, dentry))
        return err;
    
	nova_dbgv("%s: inode %lu, dir %lu, link %d\n", __func__,
				inode->i_ino, dir->i_ino, dir->i_nlink);

	if (inode->i_nlink != 2)
		nova_dbg("empty directory %lu has nlink!=2 (%d), dir %lu",
				inode->i_ino, inode->i_nlink, dir->i_ino);
    
    err = dafs_remove_dentry(dentry);

	if (err)
		goto end_rmdir;

	/*inode->i_version++; */
	clear_nlink(inode);
	inode->i_ctime = dir->i_ctime;

	if (dir->i_nlink)
		drop_nlink(dir);
	
    err = dafs_append_link_change_entry(sb, pi, inode, 0, &pi_tail);
	if (err)
		goto end_rmdir;

	nova_lite_transaction_for_time_and_link(sb, pi, pidir,
						pi_tail, pidir_tail, 1);

	NOVA_END_TIMING(rmdir_t, rmdir_time);
	return err;

end_rmdir:
	nova_err(sb, "%s return %d\n", __func__, err);
	NOVA_END_TIMING(rmdir_t, rmdir_time);
	return err;
}

static int dafs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,\ 
        dev_t rdev)
{
    struct inode *inode = NULL;
    int err = PTR_ERR(inode);
    struct super_block *sb = dir->i_sb;
    u64 pi_addr = 0;
    struct nova_inode *pidir, *pi;
    u64 tail = 0;
    u64 ino;
    timing_t mknod_time;
    
	NOVA_START_TIMING(mknod_t, mknod_time);

	pidir = nova_get_inode(sb, dir);
	if (!pidir)
		goto out_err;

	ino = nova_new_nova_inode(sb, &pi_addr);
	if (ino == 0)
		goto out_err;

	nova_dbgv("%s: %s\n", __func__, dentry->d_name.name);
	nova_dbgv("%s: inode %llu, dir %lu\n", __func__, ino, dir->i_ino);

    err = dafs_add_dentry(dentry, ino, 0);

	inode = nova_new_vfs_inode(TYPE_MKNOD, dir, pi_addr, ino, mode,
					0, rdev, &dentry->d_name);
	if (IS_ERR(inode))
		goto out_err;

	d_instantiate(dentry, inode);
	unlock_new_inode(inode);

	pi = nova_get_block(sb, pi_addr);
	nova_lite_transaction_for_new_inode(sb, pi, pidir, tail);
	NOVA_END_TIMING(mknod_t, mknod_time);
	return err;
out_err:
	nova_err(sb, "%s return %d\n", __func__, err);
	NOVA_END_TIMING(mknod_t, mknod_time);
	return err;
}

static int dafs_rename(struct inode *old_dir, struct dentry *old_dentry,\ 
        struct inode *new_dir, struct dentry *new_dentry)
{
    struct inode *old_inode = old_dentry->d_inode;
    struct inode *new_inode = new_dentry->d_inode;
    struct super_block *sb = old_inode->i_sb;
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct nova_inode *old_pi = NULL, *new_pi = NULL;
    struct nova_inode *new_pidir = NULL, *old_pidir = NULL;
    struct nova_lite_journal_entry entry, entry1;
    struct nova_dentry *father_entry = NULL;
    char *head_addr = NULL;
    u64 old_tail = 0, new_tail = 0, new_pi_tail = 0, old_pi_tail = 0;
    int err = -ENOMEM;
    int entries = 0;
    int cpu;
    int change_parent = 0;
    u64 journal_tail;
    timeing_t rename_time;

    
	nova_dbgv("%s: rename %s to %s,\n", __func__,
			old_dentry->d_name.name, new_dentry->d_name.name);
	nova_dbgv("%s: %s inode %lu, old dir %lu, new dir %lu, new inode %lu\n",
			__func__, S_ISDIR(old_inode->i_mode) ? "dir" : "normal",
			old_inode->i_ino, old_dir->i_ino, new_dir->i_ino,
			new_inode ? new_inode->i_ino : 0);
	NOVA_START_TIMING(rename_t, rename_time);

    /*检查rename的情况*/
    if(new_inode){
        err = -ENOMEM;
        if(S_ISDIR(old_inode->i_mode) && !dafs_empty_dir(new_inode))
            goto out;
    } else {
        if(S_ISDIR(old_inode->i_mode)){
            err = -EMLINK;
            if(new_dir->i_nlink >= NOVA_LINK_MAX)
                goto out;
        }
    }

    if(S_ISDIR(old_inode->i_mode)){
        dec_link = -1;
        if(!new_inode)
            inc_link = 1;
    }

    /*change inode link entry*/
	new_pidir = nova_get_inode(sb, new_dir);
	old_pidir = nova_get_inode(sb, old_dir);

	old_pi = nova_get_inode(sb, old_inode);
	old_inode->i_ctime = CURRENT_TIME;
	err = dafs_append_link_change_entry(sb, old_pi,
						old_inode, 0, &old_pi_tail);
    if(err)
        goto out;

    if(S_ISDIR(old_inode->i_mode) && old_dir != new_dir){
        __rename_dir_direntry(old_dentry, new_dentry, old_inode, new_inode, 0); 
    }

    if(new_inode){
        /*first remove the old entry in the new directory*/
        err = dafs_remove_dentry(new_dentry);
        if (err)
            goto out;
    }

    /*link into the new directory*/
    err = dafs_add_dentry(new_dentry, old_inode->i_ino, inc_link);

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
