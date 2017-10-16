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
            /*避免zone的根目录被查到*/
            if(!strcat(tem, phstr))
                goto END;
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
    nova_flush_buffer(dafs_de, delen, 0);
    
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

/**递归删除dentry*/
static void __remove_direntry(struct super_block *sb, struct dafs_dentry *dafs_de,\
                              struct dafs_zone_entry *dafs_ze, unsigned long de_pos)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dafs_dentry *dafs_de, *pde, *sde;
    struct dzt_entry_info *dzt_ei;
    struct dafs_zone_entry *dafs_ze;
    struct zone_ptr *z_p;
    struct dzt_ptr *dzt_p;
    struct dzt_manager *dzt_m = sbi->dzt_m_info;
    unsigned long phlen;
    unsigned long dzt_eno, dzt_rno;
    unsigned long bitpos, par_id, par_pos, sub_p, sub_id, i;
    char *tem;
    u64 hashname;

    strcat(tem, dafs_ze->root_path);
    if(dafs_de->file_type == ROOT_DIRECTORY){

        /*delete dir*/
        bitpos = de_pos * 2;
        /*not decided z_p是不是需要取地址*/
        make_zone_ptr(z_p, dafs_ze);
        test_and_clear_bit_le(bitpos, zone_p->statemap);
	    bitpos++;
        test_and_clear_bit_le(bitpos, zone_p->statemap);

        dzt_rno = le64_to_cpu(dafs_de->dz_no);
        strcat(tem, dafs_de->ful_name->f_name);
        hashname = BKDRHash(tem, strlen(tem));

        /*delete dzt on dram and nvm*/
        radix_tree_delete(&dzt_m->dzt_root, hashname);
        make_dzt_ptr(sbi, dzt_p);
        test_and_clear_bit_le(dzt_rno, dzt_p->bitmap);

        /*delete in par sub_pos*/
        par_pos = 0;
        for(par_id =0; par_id<NR_DENTRY_IN_ZONE; par_id++){
            if(test_bit_le(par_pos, z_p->statemap)||test_bit_le(par_pos+1, z_p->statemap)){
                pde = dafs_ze->dentry[par_id];
                if(dafs_de->par_ino == pde->ino){
                    /*not decided*/
                    change_sub_pos();
                    break;
                }
                par_pos += 2;
            }else{
                par_pos += 2;
            }
        }
    }else if(dafs_de->file_type == NORMAL_DIRECTORY){
        /*delete sub file*/
        for(i=0;i<dafs_de->sub_num;i++){
            sub_id = dafs_de->sub_pos[i];
            sde = dafs_ze->dentry[sub_id];
            __remove_direntry(sde, dafs_ze, sub_id);
        }

        /*delete dir itself*/
        bitpos = de_pos * 2;
        /*not decided z_p是不是需要取地址*/
        make_zone_ptr(z_p, dafs_ze);
        test_and_clear_bit_le(bitpos, zone_p->statemap);
	    bitpos++;
        test_and_clear_bit_le(bitpos, zone_p->statemap);
        
        /*delete in par sub_pos*/
        par_pos = 0;
        for(par_id =0; par_id<NR_DENTRY_IN_ZONE; par_id++){
            if(test_bit_le(par_pos, z_p->statemap)||test_bit_le(par_pos+1, z_p->statemap)){
                pde = dafs_ze->dentry[par_id];
                if(dafs_de->par_ino == pde->ino){
                    /*not decided*/
                    change_sub_pos();
                    break;
                }
                par_pos += 2;
            }else{
                par_pos += 2;
            }
        }
    }else{
        
        /*delete dir itself*/
        bitpos = de_pos * 2;
        /*not decided z_p是不是需要取地址*/
        make_zone_ptr(z_p, dafs_ze);
        test_and_clear_bit_le(bitpos, zone_p->statemap);
	    bitpos++;
        test_and_clear_bit_le(bitpos, zone_p->statemap);

        /*delete in par sub_pos*/
        par_pos = 0;
        for(par_id =0; par_id<NR_DENTRY_IN_ZONE; par_id++){
            if(test_bit_le(par_pos, z_p->statemap)||test_bit_le(par_pos+1, z_p->statemap)){
                pde = dafs_ze->dentry[par_id];
                if(dafs_de->par_ino == pde->ino){
                    /*not decided*/
                    change_sub_pos();
                    break;
                }
                par_pos += 2;
            }else{
                par_pos += 2;
            }
        }
    }
}

/* removes a directory entry pointing to the inode. assumes the inode has
 * already been logged for consistency
 * 只是先将对应的状态表显示无效
 * 检查是不是根节点
 * 并不含有link的变化
 */
int dafs_remove_dentry(struct dentry *dentry)
{
    struct inode *dir = dentry->d_parent->d_inode;
    struct super_block *sb = dir->i_sb;
    //struct nova_inode_info *si = NOVA_I(dir);
    //struct nova_inode_info_header *sih = &si->header;
    //struct nova_inode *pidir;
    //struct qstr *entry = &dentry->d_name;
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dafs_dentry *dafs_de;
    struct dzt_entry_info *dzt_ei;
    struct dafs_zone_entry *dafs_ze;
    struct zone_ptr *z_p;
    unsigned long phlen;
    unsigned long dzt_eno;
    unsigned long de_pos;
    unsigned short links_count;
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

    dafs_de = dafs_ze->dentry[de_pos];

    __remove_direntry(dafs_de, dafs_ze, de_pos);
    
    
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

/*bug 应该检验一下状态图是否有效*/
static int dafs_empty_dir(struct inode *inode, struct dentry *dentry)
{
    struct super_block *sb = inode->i_sb;
    struct dafs_dentry *direntry, *denties[4];
    struct dzt_entry_info *dzt_ei;
    struct dafs_zone_entry *dafs_ze;
    unsigned long phlen;
    unsigned long dzt_eno;
    u64 ph_hash;
    unsigned long de_pos;
    char *phname = NULL;
    unsigned long nr_de;
    int i;

    phname = get_dentry_path(dentry);
    dzt_ei = find_dzt(sb, &phname);
    dafs_ze = cpu_to_le64(dzt_ei->dz_addr);
    phlen = strlen(phname);
    dzt_eno = dzt_ei->dzt_eno;
    ph_hash = BKDRHash(phname, phlen);

    /*lookup in hash table, not decided*/
    de_pos = lookup_in_hashtable(ph_hash, phlen, dzt_eno);

    direntry = dafs_ze->dentry[de_pos];
    
    nr_de = direntry->sub_num;
    if(nr_de > 2)
        return 0;

    for(i = 0; i < nr_de, i++){
        de_pos = direntry->sub_pos[i];
        denties[i] = dafs_ze->dentry[de_pos];
        if(!is_dir_init_entry(sb, denties[i]))
            return 0;
    }

    return 1;

}

/*add rename zone root dentry
 * dentry 是新的dentry*/
int add_rename_zone_dir(struct dentry *dentry, struct dafs_dentry *old_de)
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
    unsigned long bitpos = 0, cur_pos = 0;
    int ret = 0;
    timing_t add_dentry_time;

    
	/*nova_dbg_verbose("%s: dir %lu new inode %llu\n",
				__func__, dir->i_ino, ino);
	nova_dbg_verbose("%s: %s %d\n", __func__, name, namelen);*/

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
    dafs_de->file_type = ROOT_DIRECTORY;       //file_type是啥？ not decided

	dafs_de->links_count = old_de->links_count;

    dafs_de->de_len = cpu_to_le16(delen);  
    dafs_de->mtime = cpu_to_le32(dir->i_mtime.tv_sec);
    /*not root at first*/
    dafs_de->vroot = 1;
    //dafs_de->path_len =
    dafs_de->ino = old_de->ino;
    //需要printk
    dafs_de->par_ino = cpu_to_le64(dentry->d_parent->d_inode->ino);
    
    nova_dbg_verbose("dir ino 0x%llu is subfile of parent ino 0x%llu ", dafs_de->ino, dafs_de->par_ino);
    
    dafs_de->size = cpu_to_le64(dir->i_size);
    dafs_de->zone_no = old_de->dz_no;
    dafs_de->prio = old_de->prio;
    dafs_de->d_f = old_de->d_f;
    dafs_de->sub_s = old_de->sub_s;
    dafs_de->f_s = old_de->f_s;
    dafs_de->sub_num = old->sub_num;
    dafs_de->sub_pos[NR_DENTRY_IN_ZONE] = {0};
    /*不存储名字字符在初始化的时候*/
    dafs_de->name[dentry->d_name.len] = '\0';
    dafs_de->ful_name->f_namelen = cpu_to_le64(phlen);
    /*那路径名称呢*/
    dafs_de->ful_name->f_name = phname;
    /*not decided是不是每次写到nvm都需要这个接口*/ 
    nova_flush_buffer(dafs_de, delen, 0);
    
    /*make valid*/
    bitpos++;
    test_and_set_bit_le(bitpos, zone_p->statemap);
    
    dir->i_blocks = pidir->i_blocks;

    /*set pos in hash table for each zone*/
    ret = set_pos_htable(phname ,phlen);

    NOVA_END_TIMING(add_dentry_t, add_entry_time);
    return ret;
}

/*rename code recursive
 * n_ze是new_dentry所在的zone
 * path是新的目录的字符串
 * name纯的文件名*/
int __rename_dir(struct dafs_dentry *src_de, struct dafs_zone_entry *ze, char *path,\ 
         char *name)
{
    struct zone_ptr *z_p;
    struct dafs_dentry *new_de, *sub_de, *sub_nde;
    unsigned long sub_num;
    unsigned long bitpos = 0, dir_pos = 0, s_pos;
    unsigned short delen;
    int i, ret=0;
    char *new_ph=NULL, *s_name;
    u64 phlen,src_len;

    make_zone_ptr(z_p, ze);

    sub_num = le64_to_cpu(src_de->sub_num);

    //src_ph = src_de->ful_name->f_name;
    //s_ph = src_de->name;
    /*含有'/'*/
    //phlen = strlen(src_ph)-strlen(o_name);
    //memcpy(new_ph, src_ph, phlen);
    //strcat(new_ph, n_name);
    memcpy(new_ph, path, sizeof(path));
    delen = DAFS_DIR_LEN(strlen(name)+strlen(new_ph));
    
    /*set dir entry*/
    while(bitpos<z_p->zone_max){
        if(test_bit_le(bitpos, z_p->statemap)||test_bit_le(bitpos+1, z_p->statemap)){
            bitpos+=2;
            dir_pos++;
        }else{
            break;
        }
    }
    new_de = ze->dentry[dir_pos]; 
    memset(new_de, 0, sizeof(new_de));    
    new_de->entry_type = src_de->entry_type;
    new_de->name_len = strlen(name);
    new_de->file_type = src_de->file_type;       //file_type是啥？ not decided
	new_de->links_count = src_de->links_count;
    new_de->de_len = cpu_to_le16(delen);  
    new_de->mtime = cpu_to_le32(CURRENT_TIME_SEC);
    new_de->vroot = src_de->vroot;
    new_de->ino = src_de->ino;
    //需要printk
    new_de->par_ino = src_de->par_ino;
    
    nova_dbg_verbose("dir ino 0x%llu is subfile of parent ino 0x%llu ", new_de->ino, new_de->par_ino);
    
    new_de->size = src_de->size;
    new_de->zone_no = ze->dz_no;
    new_de->prio = src_de->prio;
    new_de->d_f = src_de->d_f + 1;
    new_de->sub_s = src_de->sub_s;
    new_de->f_s = DENTRY_FREQUENCY_WRITE;
    new_de->sub_num = src_de->sub_num;
    new_de->sub_pos[NR_DENTRY_IN_ZONE] = {0};
    /*不存储名字字符在初始化的时候*/
    new_de->name[str(name)] = name;
    new_de->ful_name->f_namelen = cpu_to_le64(strlen(new_ph));
    /*那路径名称呢*/
    new_de->ful_name->f_name = new_ph;

    nova_flush_buffer(new_de, delen, 0);
    
    /*make valid*/
    bitpos++;
    test_and_set_bit_le(bitpos, z_p->statemap);
    bitpos++;
    dir_pos++;
    ret = set_pos_htable(new_ph, strlen(new_ph));

    /*rename 子文件*/
    for(i = 0; i<sub_num; i++) {
        s_pos = src_de->sub_pos[i];
        sub_de = ze->dentry[s_pos];
        s_name = sub_de->name;
        //strcat(o_name, "/");
        //strcat(o_name, s_name);
        //src_len = strlen(o_name)+1;
        //memcpy(s_ph, name, sizeof(name));
        //strcat(s_ph, s_name);
        strcat(new_ph, "/");
        strcat(new_ph, s_name);

        if(sub_de->file_type == NORMAL_DIRECTORY){
            ret = __rename_dir_direntry(sub_de, ze, new_ph, s_name);

        } else {
            delen = DAFS_DIR_LEN(str(s_name)+str(new_ph));
            /*set dir entry*/
            while(bitpos<z_p->zone_max){
                if(test_bit_le(bitpos, z_p->statemap)||test_bit_le(bitpos+1, z_p->statemap)){
                    bitpos+=2;
                    dir_pos++;
                }else{
                    break;
                }
            }
            new_de = ze->dentry[dir_pos]; 
            memset(new_de, 0, sizeof(new_de));    
            new_de->entry_type = sub_de->entry_type;
            new_de->name_len = sub_de->name;
            new_de->file_type = sub_de->file_type;       //file_type是啥？ not decided
	        new_de->links_count = sub_de->links_count;
            new_de->de_len = cpu_to_le16(delen);  
            new_de->mtime = cpu_to_le32(CURRENT_TIME_SEC);
            new_de->vroot = sub_de->vroot;
            new_de->ino = sub_de->ino;
            //需要printk
            new_de->par_ino = sub_de->par_ino;
                
            nova_dbg_verbose("dir ino 0x%llu is subfile of parent ino 0x%llu ", new_de->ino, new_de->par_ino);
              
            new_de->size = sub_de->size;
            new_de->zone_no = ze->dz_no;
            new_de->prio = sub_de->prio;
            new_de->d_f = sub_de->d_f + 1;
            new_de->sub_s = sub_de->sub_s;
            new_de->f_s = DENTRY_FREQUENCY_WRITE;
            new_de->sub_num = sub_de->sub_num;
            new_de->sub_pos[NR_DENTRY_IN_ZONE] = {0};
            /*不存储名字字符在初始化的时候*/
            new_de->name[strlen(s_name)] = sub_de->name;
            new_de->ful_name->f_namelen = cpu_to_le64(strlen(new_ph));
            /*那路径名称呢*/
            new_de->ful_name->f_name = new_ph;
            
            nova_flush_buffer(new_de, delen, 0);
             
            /*make valid*/
            bitpos++;
            test_and_set_bit_le(bitpos, z_p->statemap);
            ret = set_pos_htable(new_ph, strlen(new_ph));
            bitpos++;
            dir_pos++;

        }
    }

    return ret;

}

/*rename directories*/
int add_rename_dir(struct dentry *o_dentry, struct dentry *n_dentry, struct dafs_dentry *old_de)
{
    struct dafs_dentry *new_de;
    struct dzt_entry_info *o_ei, *n_ei;
    struct dafs_zone_entry *o_ze, *n_ze;
    char *o_phname=NULL, n_name, n_phname=NULL, npath;
    unsigned long bitpos, cur_pos;
    int i;
    int ret= 0;

    //not decided
    o_phname = get_dentry_path(o_dentry);
    o_ei = find_dzt(sb, &o_phname);
    o_ze = cpu_to_le64(o_ei->dz_addr);
    
    n_phname = get_dentry_path(n_dentry);
    npath = n_phname;
    n_ei = find_dzt(sb, &o_phname);
    n_ze = cpu_to_le64(n_ei->dz_addr);

    n_name = n_dentry->d_name.name;

    ret = __rename_dir(old_de, n_ze, npath, n_name);
    
    return ret;
}

/*rename_s 是父文件夹是否变化的标志
 * 0不变化父文件夹
 * ch_link inc or dec links
 * not decided 标记log*/
int __rename_dir_direntry(struct dentry *old_dentry, struct dentry *new_dentry)
{ 
    struct super_block *sb = old_dentry->d_sb;
    struct dafs_dentry *old_de, *new_de;
    struct dafs_zone_entry *ze;
    struct zone_ptr *z_p;
    struct inode *new_inode = new_dentry->d_inode;
    struct inode *old_inode = old_dentry->d_inode;
    u64 dz_no;
    int err = -ENOENT;

    old_de = dafs_find_direntry(sb, old_dentry);
    //dz_no = le64_to_cpu(old_de->zone_no);
    if(old_de->file_type == ROOT_DIRECTORY){
        err = add_rename_zone_dir(new_dentry, old_de);
        /*防止zone被删除*/
        if(err)
            return err;
        old_de->file_type = NORMAL_FILE;
        err = dafs_remove_dentry(old_dentry);

    } else {
        
        err = add_rename_dir(old_dentry, new_dentry, old_de); 
        if(err)
            return err;
        err = dafs_remove_dentry(old_dentry);
    }
   return err;
}

int __rename_file_dentry(struct dentry *old_dentry, struct dentry *new_dentry)
{
    struct super_block *sb = old_dentry->d_sb;
    struct dafs_dentry *dafs_de, *o_de;
    struct dafs_zone_entry *n_ze, *o_ze;
    struct dzt_entry_info *n_ei;
    struct zone_ptr *z_p;
    char *n_phname, *name=new_dentry->d_name.name;
    unsigned long bitpos=0, cur_pos=0;
    int namelen = new_dentry->d_name.len;
    unsigned short de_len;
    unsigned long phlen;

    o_de = dafs_find_direntry(sb, o_de);

    n_phname = get_dentry_path(new_dentry);
    n_ei = find_dzt(sb, &n_phname);
    n_ze = cpu_to_le64(n_ei->dz_addr);
    phlen = strlen(n_phname);
    make_zone_ptr(z_p, n_ze);
    while(bitpos<z_p->zone_max){
        if(test_bit_le(bitpos, z_p->statemap)||test_bit_le(bitpos+1, z_p->statemap)){
            bitpos+=2;
            cur_pos++;
        }else{
            break;
        }
    }

    phlen = strlen(n_phname);
    pidir = nova_get_inode(sb, dir);
    dir->i_mtime = dir->i_ctime = CURRENT_TIME_SEC;
    de_len = DAFS_DIR_LEN(namelen + phlen); //not decided 

    /*get dentry on nvm*/
    dafs_de = n_ze->dentry[cur_pos];
    memset(dafs_de, 0, sizeof(dafs_de));
    
    dafs_de->entry_type = DAFS_DIR_ENTRY;
    dafs_de->name_len = dentry->d_name.len;
    dafs_de->file_type = o_de->file_type;       //file_type是啥？ not decided

	dafs_de->links_count = o_de->links_count;

    dafs_de->de_len = cpu_to_le16(de_len);  
    dafs_de->mtime = cpu_to_le32(CURRENT_TIME_SEC);
    /*not root at first*/
    dafs_de->vroot = 0;
    //dafs_de->path_len =
    dafs_de->ino = o_de->ino;
    //需要printk
    dafs_de->par_ino = o_de->par_ino;
    
    nova_dbg_verbose("dir ino 0x%llu is subfile of parent ino 0x%llu ", dafs_de->ino, dafs_de->par_ino);
    
    dafs_de->size = o_de->size;
    dafs_de->zone_no = n_ze->dz_no;
    dafs_de->prio = o_de->prio;
    dafs_de->d_f = o_de->d_f;
    dafs_de->sub_s = o_de->sub_s;
    dafs_de->f_s = DENTRY_FREQUENCY_WRITE;
    dafs_de->sub_num = 0;
    dafs_de->sub_pos[NR_DENTRY_IN_ZONE] = {0};
    /*不存储名字字符在初始化的时候*/
    dafs_de->name[namelen] = name;
    dafs_de->ful_name->f_namelen = cpu_to_le64(phlen);
    /*那路径名称呢*/
    dafs_de->ful_name->f_name = n_phname;
    /*not decided是不是每次写到nvm都需要这个接口*/ 
    nova_flush_buffer(dafs_de, de_len, 0);
    
    /*make valid*/
    bitpos++;
    test_and_set_bit_le(bitpos, z_p->statemap);
    
    dir->i_blocks = pidir->i_blocks;

    /*set pos in hash table for each zone*/
    ret = set_pos_htable(n_phname ,phlen);

    NOVA_END_TIMING(add_dentry_t, add_entry_time);

    return ret;
    
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
