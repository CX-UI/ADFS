/*************************************************************************
	> File Name: dafs_dir.c
	> Author:CX
	> Mail: tianfangmmr@126.com
	> Created Time: 2017年10月09日 星期一 15时49分06秒
 ************************************************************************/

#include<linux/fs.h>
#include<linux/pagemap.h>
#include<linux/path.h>
#include<linux/string.h>
#include "nova.h"
#include "zone.h"

/*get dentry path except filename*/
static inline char* get_dentry_path(struct dentry *dentry)
{
    char *ph="", *buf=NULL;
    struct vfsmount *p, *root;
    struct fs_struct *fs = current->fs;
    struct vfsmount *vfsmnt = NULL;
    struct path path;

    buf = kmalloc(DAFS_PATH_LEN,GFP_KERNEL);
    if(!buf)
        goto ERR;

    read_lock(&fs->lock);
    vfsmnt = mntget(fs->root.mnt);
    read_unlock(&fs->lock);
    
    ph={
        .mnt = vfsmnt;
        .dentry = dentry; 
    }
    ph = d_path(&path, buf, DAFS_PATH_LEN);
    mntput(vfsmnt);

    kfree(buf);
ERR:
    return ph;
}

/* find currect zone*/
static inline struct dzt_entry_info *find_dzt(struct super_block *sb, char *phname)
{
    struct dzt_entry_info *dzt_ei, *dzt_ei_tem;
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dzt_manager dzt_m = sbi->dzt_m_info;
    u64 hashname;
    u64 phlen;
    u64 dzt_eno;
    char *token, *tem, *rph="/";
    char delim[] = "/";

    hashname = BRDEHash(rph, 1);
    dzt_ei = radix_tree_lookup(&dzt_m->dzt_root,hashname);
    for(token = strsep(&phname, delim);token != NULL; token= strsep(&phname, delim) ){
        if(!token){
            strcat(tem, "/");
            strcat(tem, token);
            phlen = strlen(tem);
            hashname = BKDRHash(tem, phlen);
            dzt_ei_tem = radix_tree_lookup(&dzt_m->dzt_root, hashname);
            if(!dzt_ei_tem)
                goto END;
            dzt_ei = dzt_ei_tem;
        }
    }

END:
    return dzt_ei;
}
/*dafs add dentry in the zone*/
int dafs_add_dentry(struct dentry *dentry, u64 ino, int inc_link)
{
    struct inode *dir = dentry->d_parent->d_inode;
    struct super_block *sb = dir->i_sb;
    const char *name = dentry->d_name.name;
    int namelen = dentry->d_name.len;
    struct dafs_dentry *direntry;
    char *phname = NULL;
    unsigned short loglen;
    int ret;
    timing_t add_dentry_time;

    
	nova_dbg_verbose("%s: dir %lu new inode %llu\n",
				__func__, dir->i_ino, ino);
	nova_dbg_verbose("%s: %s %d\n", __func__, name, namelen);

	NOVA_START_TIMING(add_dentry_t, add_dentry_time);
	if (namelen == 0)
		return -EINVAL;
    

}


const struct file_operations dafs_dir_operations = {
    .llseek      = generic_file_llseek,
    .read        = generic_read_dir,
    .iterate     = dafs_readdir,
    .fsync       = noop_fsync,
    .unlocked_ioctl = dafs_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl   = dafs_compat_ioctl,
#endif
};
