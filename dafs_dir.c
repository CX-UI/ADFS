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
static inline struct dzt_entry_info *find_dzt(struct super_block *sb, char *phstr)
{
    struct dzt_entry_info *dzt_ei, *dzt_ei_tem;
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dzt_manager dzt_m = sbi->dzt_m_info;
    u64 hashname;
    u64 phlen;
    u64 dzt_eno;
    char *token, *tem, *ph, *rph="/";
    char *phname = kstrdup(pthstr,GFP_KERNEL);
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
            /*返回剩余的文件名*/
            strcpy(phstr, phname);
        }
    }

END:
    return dzt_ei;
}

/* set dentry pos in hash table*/
int set_pos_htable()
{
    int ret;
    return ret;
}

/*dafs add dentry in the zone
* and initialize direntry without name*/
int dafs_add_dentry(struct dentry *dentry, u64 ino, int inc_link)
{
    struct inode *dir = dentry->d_parent->d_inode;
    struct super_block *sb = dir->i_sb;
    struct nova_inode *pidir;
    const char *name = dentry->d_name.name;
    int namelen = dentry->d_name.len;
    struct dafs_dentry *direntry;
    struct dzt_entry_info *dzt_ei;
    struct dafs_zone_entry *dafs_ze;
    struct zone_ptr *zone_p;
    struct dafs_dentry *dafs_de;
    char *phname = NULL;
    unsigned long phlen;
    unsigned short delen;
    unsigned short links_count;
    unsigned long bitpos = 0, cur_pos = 0;
    int ret = 0;
    timing_t add_dentry_time;

    
	nova_dbg_verbose("%s: dir %lu new inode %llu\n",
				__func__, dir->i_ino, ino);
	nova_dbg_verbose("%s: %s %d\n", __func__, name, namelen);

	NOVA_START_TIMING(add_dentry_t, add_dentry_time);
	if (namelen == 0)
		return -EINVAL;
    
    phname = get_dentry_path(dentry);
    dzt_ei = find_dzt(sb, &phname);
    dafs_ze = cpu_to_le64(dzt_ei->dz_addr);
    make_zone_ptr(zone_p, dafs_ze);
    while(bitpos<zone_p->zone_max){
        if(test_bit_le(bitpos, zone_p->statemap)||test_bit_le(bitpos+1, zone_p->statemap)){
            bitpos+=2;
            cur_pos++;
        }else{
            break;
        }
    }

    phlen = strlen(phname);
    pidir = nova_get_inode(sb, dir);
    dir->i_mtime = dir->i_ctime = CURRENT_TIME_SEC;
    delen = DAFS_DIR_LEN(namelen + phlen); //not decided 

    /*get dentry on nvm*/
    dafs_de = dafs_ze->dentry[cur_pos];
    memset(dafs_de, 0, sizeof(dafs_de));
    
    dafs_de->entry_type = DAFS_DIR_ENTRY;
    dafs_de->name_len = dentry->d_name.len;
    dafs_de->file_type = 0;       //file_type是啥？ not decided

    links_count = cpu_to_le16(dir->i_nlink);    
	if (links_count == 0 && inc_link == -1)
		links_count = 0;
	else
		links_count += inc_link;
	dafs_de->links_count = cpu_to_le16(links_count);

    dafs_de->de_len = cpu_to_le16(delen);  
    dafs_de->mtime = cpu_to_le32(dir->i_mtime.tv_sec);
    /*not root at first*/
    dafs_de->vroot = 0;
    //dafs_de->path_len =
    dafs_de->ino = cpu_to_le64(ino);
    //需要printk
    dafs_de->par_ino = cpu_to_le64(dentry->d_parent->d_inode->ino);
    
    nova_dbg_verbose("dir ino 0x%llu is subfile of parent ino 0x%llu ", dafs_de->ino, dafs_de->par_ino);
    
    dafs_de->size = cpu_to_le64(dir->i_size);
    dafs_de->zone_no = cpu_to_le64(dzt_ei->dzt_eno);
    dafs_de->prio = LEVEL_0;
    dafs_de->d_f = 0;
    dafs_de->sub_s = 0;
    dafs_de->f_s = 0;
    dafs_de->sub_num = 0;
    dafs_de->sub_pos[NR_DENTRY_IN_ZONE] = {0};
    /*不存储名字字符在初始化的时候*/
    dafs_de->name[dentry->d_name.len] = '\0';
    dafs_de->ful_name->f_namelen = cpu_to_le64(phlen);
    /*那路径名称呢*/
    dafs_de->ful_name->f_name = phname;
    /*not decided是不是每次写到nvm都需要这个接口*/ 
    nova_flush_buffer(dafs_de, de_len, 0);
    
    /*make valid*/
    bitpos++;
    test_and_set_bit_le(bitpos, zone_p->statemap);
    
    dir->i_blocks = pidir->i_blocks;

    /*set pos in hash table for each zone*/
    ret = set_pos_htable(phname ,phlen);

    NOVA_END_TIMING(add_dentry_t, add_entry_time);
    return ret;
}

/*look for dentry for each zone in its hash table*/
unsigned long de_pos *lookup_in_hashtable()
{
    struct dafs_dentry *dafs_de;
    return dafs_de;
}

struct dafs_dentry *dafs_find_direntry(struct super_block *sb, struct dentry *dentry)
{
    struct dafs_dentry *direntry;
    struct dzt_entry_info *dzt_ei;
    struct dafs_zone_entry *dafs_ze;
    unsigned long phlen;
    unsigned long dzt_eno;
    u64 ph_hash;
    unsigned long de_pos;
    char *phname = NULL;

    phname = get_dentry_path(dentry);
    dzt_ei = find_dzt(sb, &phname);
    dafs_ze = cpu_to_le64(dzt_ei->dz_addr);
    phlen = strlen(phname);
    dzt_eno = dzt_ei->dzt_eno;
    ph_hash = BKDRHash(phname, phlen);

    /*lookup in hash table, not decided*/
    de_pos = lookup_in_hashtable(ph_hash, phlen, dzt_eno);
    direntry = dafs_ze->dentry[de_pos];

    return direntry;
}


/* removes a directory entry pointing to the inode. assumes the inode has
 * already been logged for consistency
 * 只是先将对应的状态表显示无效
 */
int dafs_remove_dentry(struct dentry *dentry)
{
    struct inode *dir = dentry->d_parent->d_inode;
    struct super_block *sb = dir->i_sb;
    //struct nova_inode_info *si = NOVA_I(dir);
    //struct nova_inode_info_header *sih = &si->header;
    //struct nova_inode *pidir;
    //struct qstr *entry = &dentry->d_name;
    struct dafs_dentry *dafs_de;
    struct dzt_entry_info *dzt_ei;
    struct dafs_zone_entry *dafs_ze;
    struct zone_ptr *z_p;
    unsigned long phlen;
    unsigned long dzt_eno;
    unsigned long de_pos, bitpos;
    u64 ph_hash;
    char *phname = NULL;
    //unsigned short loglen;
	//u64 curr_tail, curr_entry;
	timing_t remove_dentry_time;

	NOVA_START_TIMING(remove_dentry_t, remove_dentry_time);

	if (!dentry->d_name.len)
		return -EINVAL;

	pidir = nova_get_inode(sb, dir);

	dir->i_mtime = dir->i_ctime = CURRENT_TIME_SEC;

    /*直接rm direntry就可以
    * 先找到相应的dir*/    
    phname = get_dentry_path(dentry);
    dzt_ei = find_dzt(sb, &phname);
    dafs_ze = cpu_to_le64(dzt_ei->dz_addr);
    phlen = strlen(phname);
    dzt_eno = dzt_ei->dzt_eno;
    ph_hash = BKDRHash(phname, phlen);

    /*lookup in hash table, not decided*/
    de_pos = lookup_in_hashtable(ph_hash, phlen, dzt_eno);
    bitpos = de_pos * 2;
    /*not decided z_p是不是需要取地址*/
    make_zone_ptr(z_p, dafs_ze);
    test_and_clear_bit_le(bitpos, zone_p->statemap);
	bitpos++;
    test_and_clear_bit_le(bitpos, zone_p->statemap);
    
    NOVA_END_TIMING(remove_dentry_t, remove_dentry_time);
	return 0;
}

/*append . and .. entries*/
int dafs_append_dir_init_entries(struct super_block *sb, struct nova_inode *pi,\ 
                                u64 self_ino, u64 parent_ino)
{
    int allocated;
    u64 new_block;
    u64 curr_p;
    u64 phhash;
    char *phname;
    unsigned long phlen;
    unsigned long bitpos ,depos;
    unsigned short delen;
    struct dafs_zone_entry *dafs_ze;
    struct dzt_entry_info *dafs_ei;
    struct zone_ptr *zone_p;
    struct dafs_dentry *dafs_de, *dafs_rde;
	
    if (pi->log_head) {
		nova_dbg("%s: log head exists @ 0x%llx!\n",
				__func__, pi->log_head);
		return - EINVAL;
	}
    allocated = nova_allocate_inode_log_pages(sb, pi, 1, &new_block);
	if (allocated != 1) {
		nova_err(sb, "ERROR: no inode log page available\n");
		return - ENOMEM;
	}
    /*虽然不需要将dentry加到log里面去但是还是要初始化一下log_h和log_t*/
	pi->log_tail = pi->log_head = new_block;
	pi->i_blocks = 1;
	nova_flush_buffer(&pi->log_head, CACHELINE_SIZE, 0);

    /*创建. ..并添加到父目录*/
    /*find parent directory*/
    phname = get_dentry_path(dentry);
    phlen = strlen(phname);
    dzt_ei = find_dzt(sb, &phname);
    dafs_ze = cpu_to_le64(dzt_ei->dz_addr);
    phhash = BKDRHash(phname, phlen);
    //not decided
    depos = lookup_in_hashtable(phhash, phlen, dzt_ei->dzt_eno);
    dafs_rde = dafs_ze->dentry[depos];

    make_zone_ptr(zone_p, dafs_ze);
    while(bitpos<zone_p->zone_max){
        if(test_bit_le(bitpos, zone_p->statemap)||test_bit_le(bitpos+1, zone_p->statemap)){
            bitpos+=2;
            cur_pos++;
        }else{
            break;
        }
    }
    delen = DAFS_DIR_LEN(1+phlen+2);
    dafs_de = dafs_ze->dentry[cur_pos];
    dafs_de->entry_type = DAFS_DIR_ENTRY;
    /*标示. ..文件*/
    dafs_de->file_type = FIXED_FILE;
    dafs_de->name_len = 1;
    dafs_de->links_count = 1;
    dafs_de->de_len = cpu_to_le16(delen);
    dafs_de->mtime = CURRENT_TIME_SEC.tv_sec;
    //dafs_de->size = sb->s_blocksize;
    dafs_de->vroot = 0;
    dafs_de->ino = cpu_to_le64(self_ino);
    /*dir ino*/
    dafs_de->parent_ino = cpu_to_le64(self_ino);
    dafs_de->size = sb->s_blocksize;
    dafs_de->zone_no = cpu_to_le64(dzt_ei->dzt_eno);
    strncpy(dafs_de->name, ".\0", 2);
    dafs_de->ful_name->f_namelen = cpu_to_le64(phlen + 2);
    strcpy(dafs_de->ful_name->f_name, phname);
    strcat(dafs_de->ful_name->f_name, "/.");
    
    nova_flush_buffer(dafs_de, delen, 0);
    
    /*change in dir*/
    dafs_rde->sub_num +=1;
    dafs_rde->sub_pos[0] = cpu_to_le64(cur_pos);
    
    /*make valid*/
    bitpos++;
    test_and_set_bit_le(bitpos, zone_p->statemap);
    bitpos++;
    cur_pos++;

    /*set hash table with its position*/
    set_pos_htable(dafs_de->ful_name->f_name,dafs_de->ful_name->f_namelen);

    while(bitpos<zone_p->zone_max){
        if(test_bit_le(bitpos, zone_p->statemap)||test_bit_le(bitpos+1, zone_p->statemap)){
            bitpos+=2;
            cur_pos++;
        }else{
            break;
        }
    }
    delen = DAFS_DIR_LEN(2+phlen+3);
    dafs_de = dafs_ze->dentry[cur_pos];
    dafs_de->entry_type = DAFS_DIR_ENTRY;
    /*标示. ..文件*/
    dafs_de->file_type = FIXED_FILE;
    dafs_de->name_len = 2;
    dafs_de->links_count = 2;
    dafs_de->de_len = cpu_to_le16(delen);
    dafs_de->mtime = CURRENT_TIME_SEC.tv_sec;
    //dafs_de->size = sb->s_blocksize;
    dafs_de->vroot = 0;
    dafs_de->ino = cpu_to_le64(parent_ino);
    /*dir ino*/
    dafs_de->parent_ino = cpu_to_le64(self_ino);
    dafs_de->size = sb->s_blocksize;
    dafs_de->zone_no = cpu_to_le64(dzt_ei->dzt_eno);
    strncpy(dafs_de->name, "..\0", 2);
    dafs_de->ful_name->f_namelen = cpu_to_le64(phlen + 3);
    strcpy(dafs_de->ful_name->f_name, phname);
    strcat(dafs_de->ful_name->f_name, "/..");
    
    nova_flush_buffer(dafs_de, delen, 0);
    
    dafs_rde->sub_num +=1;
    dafs_rde->sub_pos[1] = cpu_to_le64(cur_pos);
    
    /*make valid*/
    bitpos++;
    test_and_set_bit_le(bitpos, zone_p->statemap);

    /*set hash table with its position*/
    set_pos_htable(dafs_de->ful_name->f_name,dafs_de->ful_name->f_namelen);
    //不需要update tail
    
    return 0;
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
