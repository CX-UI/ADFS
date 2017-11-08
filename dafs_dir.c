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

#define DT2IF(dt) (((dt) << 12) & S_IFMT)
#define IF2DT(sif) (((sif) & S_IFMT) >> 12)

/*delete rf tree*/
int delete_rf_tree(struct dzt_entry_info *ei)
{
    struct rf_entry *rf_e;
    struct rf_entry *entries[NR_DENTRY_IN_ZONE];
    u64 key;
    int nr, i;
    void *ret;

    nr = radix_tree_gang_lookup(&ei->rf_root, (void **)entries, 0, NR_DENTRY_IN_ZONE);
    for(i=0; i<nr; i++) {
        rf_e = entries[i];
        key = rf_e->hash_name;
        ret = radix_tree_delete(&ei->rf_root, key);
        if(!ret)
            nova_dbg("ret is NULL\n");
        kfree(rf_e);
    }
    return 0;
}

/*delete rf_entry*/
int delete_rf_entry(struct dzt_entry_info *ei, u64 hash_name)
{
    struct rf_entry *old_rf;

    old_rf = radix_tree_delete(&ei->rf_root, hash_name);
    kfree(old_rf);
    return 0;

}

/*add rf_entry in rf_tree*/
struct rf_entry *add_rf_entry(struct dzt_entry_info *ei, u64 hash_name)
{
    struct rf_entry *new_rf;

    new_rf = kzalloc(sizeof(struct rf_entry), GFP_KERNEL);
    new_rf->r_f = 0;
    new_rf->sub_s = 0;
    new_rf->f_s = 0;
    new_rf->prio = LEVEL_0;
    new_rf->hash_name = hash_name;
    radix_tree_insert(&ei->rf_root, hash_name);
    return new_rf;
}

/*update read frequency when read happens*/
int update_read_hot(struct dzt_entry_info *dzt_ei, u64 sub_hash)
{
    struct rf_entry *sub_rf;
    sub_rf = radix_tree_lookup(&dzt_ei->rf_root, sub_hash);
    if(!sub_rf)
        return -EINVAL;
    sub_rf->r_f++;

    return 0;
}

/*update write frequency when rename happens */
int update_rename_hot(struct dzt_entry_info *dzt_ei, u64 sub_hash)
{
    struct rf_entry *sub_rf;
    sub_rf = radix_tree_lookup(&dzt_ei->rf_root, sub_hash);
    if(!sub_rf)
        return -EINVAL;
    sub_rf->f_s = DENTRY_FREQUENCY_WRITE; 
    return 0;
}

/*copy rf_entry
int cpy_rf_entry(struct dzt_entry_info *src_ei, struct dzt_entry_info *des_ei,\
        u64 new_hn, u64 old_hn)
{
    struct rf_entry *new_rf, *old_rf;
    new_rf =(struct rf_entry *)kzalloc(sizeof(struct rf_entry),GFP_KERNEL);
    old_rf = radix_tree_lookup(*src_ei->rf_root, old_hn);
    new_rf->r_f = old_rf->r_f;
}*/

/*update sub files numbers*/

/*get zone path through root dentry
 * we get charpath when use this function*/
int get_zone_path(struct super_block *sb, struct dzt_entry_info *ei, char *pname, const char *dename)
{
    struct dafs_zone_entry *ze;
    struct dafs_dentry *de;
    u64 num = ei->dzt_eno;
    u64 de_pos, phlen;
    phlen = (u64)ei->root_len;
    char *path = kzalloc((sizeof(char *)*phlen), GFP_KERNEL);
    char *name = kzalloc((sizeof(char*)*phlen), GFP_KERNEL);
    while(num!=1){
        ze = (struct dafs_zone_entry *)nova_get_block(sb, ei->pdz_addr);
        de_pos = ei->rden_pos;
        de = ze->dentry[de_pos];
        //memset(name, 0, strlen(name));
        memcpy(name, de->ful_name->f_name,de->ful_name->f_namelen+1);
        strcat(name,path);
        //memset(path,0,strlen(path));
        memcpy(path, name, strlen(name)+1);
        num = le64_to_cpu(ze->dz_no);
    }
    strcat(path, dename);
    memcpy(pname, path, strlen(path)+1);
    kfree(path);
    kfree(name);
    return 0;

}

/*record dir operation in logs*/
void record_dir_log(struct super_block *sb, struct dentry *src, struct dentry *des, int type)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dafs_dzt_block *dzt_blk;
    struct dzt_ptr *dzt_p;
    struct direntry_log *dlog;
    //struct dafs_dentry *src_de, *des_de;
    struct dzt_entry_info *dzt_ei, *src_ei;
    u64 src_dz, des_dz, src_hn, des_hn;
    unsigned long bitpos = 0;
    char *name, *phname, *src_pn, *ph, *phn;

    src_pn = get_dentry_path(src);
    phname = kzalloc(sizeof(char)*strlen(src_pn), GFP_KERNEL);
    phn = kzalloc(sizeof(char)*strlen(src_pn), GFP_KERNEL);
    memcpy(phname, src_pn, strlen(src_pn));
    src_ei = find_dzt(sb, phname, phn);
    //src_de = dafs_find_direntry(sb, src, 0);
    //name = kzalloc(sizeof(char)*strlen(src_pn),GFP_KERNEL);
    //name = src_de->ful_name->f_name;
    src_hn = BKDRHash(phn, strlen(phn));
    src_dz = src_ei->dzt_eno;

    if(!des) {
        src_hn = 0;
        src_dz = 0;
    }
    else {
        ph = get_dentry_path(des);
        //memset(phname, 0, strlen(phname));
        //memset(phn, 0, strlen(phn));
        memcpy(phname, ph, strlen(ph)+1);
        dzt_ei = find_dzt(sb, phname, phn);
        des_dz = dzt_ei->dzt_eno;
        //des_de = dafs_find_direntry(des);
        //des_name = des->ful_name->f_name;
        des_hn = BKDRHash(phn, strlen(phn)+1);

    }

    dzt_blk = dafs_get_dzt_block(sbi);
    make_dzt_ptr(sbi, &dzt_p);
    test_and_set_bit_le(bitpos, dzt->bitmap);

    /*not decided*/
    dlog->type_d =  type;
    dlog->src_dz_no = cpu_to_le64(src_dz);
    dlog->src_hashname = cpu_to_le64(src_hn);
    dlog->des_dz_no = cpu_to_le64(des_dz);
    dlog->des_hashname = cpu_to_le64(des_hn);

    kfree(phname);
    kfree(ph);
}

/*delete dir operation log*/
void delete_dir_log(struct super_block *sb)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dzt_ptr *dzt_p;
    unsigned long bitpos = 0;

    make_zone_ptr(sbi, &dzt_p);
    test_and_clear_bit_le(bitpos, dzt_p->bitmap);
}

/*get dentry path except filename*/
static inline char* get_dentry_path(struct dentry *dentry)
{
    char *ph="", *buf=NULL;
    struct vfsmount *p, *root;
    struct fs_struct *fs = current->fs;
    struct vfsmount *vfsmnt = NULL;
    struct path path;

    buf = kzalloc(DAFS_PATH_LEN,GFP_KERNEL);
    if(!buf)
        goto ERR;

    read_lock(&fs->lock);
    vfsmnt = mntget(fs->root.mnt);
    read_unlock(&fs->lock);
    
    path ={
        .mnt = vfsmnt;
        .dentry = dentry; 
    }
    ph = d_path(&path, buf, DAFS_PATH_LEN);
    mntput(vfsmnt);

    kfree(buf);
ERR:
    return ph;
}

/* find currect zone
 * ph record file ful name
 * 反向查找
 * 可以用多线程*/
static inline struct dzt_entry_info *find_dzt(struct super_block *sb, const char *phstr, char *ph)
{
    struct dzt_entry_info *dzt_ei, *dzt_ei_tem;
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dzt_manager dzt_m = sbi->dzt_m_info;
    u64 hashname;
    u64 phlen;
    u64 dzt_eno;
    char *tem;

    //ph = kzalloc(DAFS_PATH_LEN*(char *), GFP_KERNEL);
    memcpy(ph, phstr, strlen(phstr)+1);
    while(1){
        tem = strrchr(phstr, "/");
        phlen = strlen(ph)-strlen(tem);
        if(phlen==0)
            break;
        //memset(ph, 0, strlen(ph));
        memcpy(ph,phstr,phlen);
        memcpy(ph+phlen, "\0", 1);
        hashname = BKDRHash(ph,phlen);
        dzt_ei = radix_tree_lookup(&dzt_m->dzt_root, hashname);
        if(dzt_ei)
            goto END;
    }

    /*root dir*/
    //memset(ph, 0, strlen(ph));
    memcpy(ph, "/", 2);
    hashname = BKDRHash(ph ,1);
    dzt_ei = radix_tree_lookup(,&dzt_m->dzt_root,hashname);

END:
    return dzt_ei;
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
    char *phname, *ph, *phn;
    unsigned long phlen;
    unsigned short delen;
    unsigned short links_count;
    unsigned long bitpos = 0, cur_pos = 0;
    int ret = 0;
    u64 hashname, ht_addr;
    timing_t add_dentry_time;

    
	nova_dbg_verbose("%s: dir %lu new inode %llu\n",
				__func__, dir->i_ino, ino);
	nova_dbg_verbose("%s: %s %d\n", __func__, name, namelen);

	NOVA_START_TIMING(add_dentry_t, add_dentry_time);
	if (namelen == 0)
		return -EINVAL;
    ph = get_dentry_path(dentry);
    phname = kzalloc(sizeof(char)*strlen(ph), GFP_KERNEL);
    phn = kzalloc(sizeof(char)*strlen(ph), GFP_KERNEL);
    memcpy(phname, ph, strlen(ph)+1);
    dzt_ei = find_dzt(sb, phname, phn);
    dafs_ze = (struct dafs_zone_entry *)nova_get_block(sb,dzt_ei->dz_addr);
    make_zone_ptr(&zone_p, dafs_ze);
    while(bitpos<zone_p->zone_max){
        if(test_bit_le(bitpos, zone_p->statemap)||test_bit_le(bitpos+1, zone_p->statemap)){
            bitpos+=2;
            cur_pos++;
        }else{
            break;
        }
    }

    phlen = strlen(phn);
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
    //dafs_de->prio = LEVEL_0;
    //dafs_de->d_f = 0;
    //dafs_de->sub_s = 0;
    //dafs_de->f_s = 0;
    dafs_de->sub_num = 0;
    dafs_de->sub_pos[NR_DENTRY_IN_ZONE] = {0};
    /*不存储名字字符在初始化的时候*/
    dafs_de->name[dentry->d_name.len] = '\0';
    dafs_de->ful_name->f_namelen = cpu_to_le64(phlen);
    /*那路径名称呢*/
    memcpy(dafs->ful_name->f_name, phn, phlen+1);
    /*not decided是不是每次写到nvm都需要这个接口*/ 
    nova_flush_buffer(dafs_de, delen, 0);
    
    /*make valid*/
    bitpos++;
    test_and_set_bit_le(bitpos, zone_p->statemap);
    
    dir->i_blocks = pidir->i_blocks;

    /*set pos in hash table for each zone*/
    hashname = BKDRHash(phname, phlen);
    ht_addr = dzt_ei->ht_head;
    ret = record_pos_htable(sb, ht_addr, hashname, phlen, cur_pos, 1);

    /*new rf_entry*/
    add_rf_entry(dzt_ei, hashname);

    NOVA_END_TIMING(add_dentry_t, add_entry_time);
    kfree(phname);
    kfree(ph);
    return ret;
}

/*look for dentry for each zone in its hash table
 * add read frequency*/


struct dafs_dentry *dafs_find_direntry(struct super_block *sb, struct dentry *dentry, int update_flag)
{
    struct dafs_dentry *direntry;
    struct dzt_entry_info *dzt_ei;
    struct dafs_zone_entry *dafs_ze;
    unsigned long phlen;
    unsigned long dzt_eno;
    u64 ph_hash, ht_addr, par_hash;
    unsigned long de_pos;
    char *phname, *ph, *phn;
    int ret;

    ph = get_dentry_path(dentry);
    phname = kzalloc(sizeof(char)*strlen(ph), GFP_KERNEL);
    phn = kzalloc(sizeof(char)*strlen(ph), GFP_KERNEL);
    memcupdate write frequency when rename happens py(phname, ph, strlen(ph));
    dzt_ei = find_dzt(sb, phname, phn);
    dafs_ze = (struct dafs_zone_entry *)nova_get_block(sb, dzt_ei->dz_addr);
    phlen = strlen(phn);
    dzt_eno = dzt_ei->dzt_eno;
    ph_hash = BKDRHash(phn, phlen);


    /*lookup in hash table, not decided*/
    ht_addr = dzt_ei->ht_head;
    ret = lookup_in_hashtable(ht_addr, ph_hash, phlen, 1, &de_pos);
    if(!ret)
        return -EINVAL;
    direntry = dafs_ze->dentry[de_pos];
    
    if(update_flag &&(direntry->file_type!=ROOT_DIRECTORY))
        update_read_hot(dzt_ei, ph_hash);

    kfree(phname);
    kfree(ph);
    return direntry;
}


/**递归删除dentry*/
static int __remove_direntry(struct super_block *sb, struct dafs_dentry *dafs_de,\
        struct dafs_zone_entry *dafs_ze, struct dzt_entry_info *dzt_ei, unsigned long de_pos)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dafs_dentry *dafs_de, *pde, *sde;
    /*ei need deleting*/
    struct dzt_entry_info *ei;
    struct dafs_zone_entry *dafs_ze;
    struct zone_ptr *z_p;
    struct dzt_ptr *dzt_p;
    struct dzt_manager *dzt_m = sbi->dzt_m_info;
    struct hash_table *ht;
    unsigned long phlen;
    unsigned long dzt_eno, dzt_rno;
    unsigned long bitpos, par_id, par_pos, sub_p, sub_id, i, j, k;
    //char *tem;
    u64 hashname, d_hn, d_hlen, tail, tem;
    int ret;

    //strcat(tem, dafs_ze->root_path);
    if(dafs_de->file_type == ROOT_DIRECTORY){

        /*delete dir*/
        d_hlen = le64_to_cpu(dafs_de->ful_name->f_namelen);
        d_hn = BKDRHash(dafs_de->ful_name->f_name,d_hlen);
        bitpos = de_pos * 2;
        /*not decided z_p是不是需要取地址*/
        make_zone_ptr(&z_p, dafs_ze);
        test_and_clear_bit_le(bitpos, zone_p->statemap);
	    bitpos++;
        test_and_clear_bit_le(bitpos, zone_p->statemap);
        ret = make_invalid_htable(dzt_ei->ht_head, d_hn, d_hlen, 1);
        /*free rf_entry*/
        delete_rf_entry(dzt_ei, d_hn);
        if(!ret)
            return -EINVAL;

        //dzt_rno = le64_to_cpu(dafs_de->dz_no);
        //strcat(tem, dafs_de->ful_name->f_name);
        //hashname = BKDRHash(tem, strlen(tem));
        //hashname = le64_to_cpu(dafs_de->hash_name);

        /*delete dzt on dram and nvm
         * ei free zone
         * free hash table
         * free zone
         * free ei
         * free rf_tree*/
        hashname = le64_to_cpu(dafs_de->hash_name);
        ei = radix_tree_delete(&dzt_m->dzt_root, hashname);
        dzt_rno = ei->dzt_eno;
        tail = le64_to_cpu(ei->ht_head);
        while(tail){
            ht = (struct hash_table *)nova_get_block(tail);
            tem = le64_to_cpu(ht->hash_tail);
            dafs_free_htable_blocks(sb, HTABLE_SIZE, tail>>PAGE_SHIFT, 1);
            tail = tem;
        }
        make_dzt_ptr(sbi, &dzt_p);
        test_and_clear_bit_le(dzt_rno, dzt_p->bitmap);
        delete_rf_tree(ei);
        dafs_free_zone_blocks(sb, ei, ei->dz_addr >> PAGE_SHIFT, 1);
        kfree(ei);

        /*delete in par sub_pos*/
        par_pos = 0;
        for(par_id =0; par_id<NR_DENTRY_IN_ZONE; par_id++){
            if(test_bit_le(par_pos, z_p->statemap)||test_bit_le(par_pos+1, z_p->statemap)){
                pde = dafs_ze->dentry[par_id];
                if(dafs_de->par_ino == pde->ino){
                    /*change p_dentry pos*/
                    for(j=0; j<pde->sub_num, j++){
                        if(pde->sub_pos[j] = de_pos){
                            k=j+1;
                            while(k<sub_num) {
                                pde->sub_pos[j] = pde->sub_pos[k];
                                k++;
                                j++;
                            }
                            pde->sub_pos[j] = 0;
                        }
                    }
                    pde->sub_num--;
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
            ret = __remove_direntry(sb, sde, dafs_ze, dzt_ei, sub_id);
        }

        /*delete dir itself*/
        d_hlen = le64_to_cpu(dafs_de->ful_name->f_namelen);
        d_hn = BKDRHash(dafs_de->ful_name->f_name);
        bitpos = de_pos * 2;
        /*not decided z_p是不是需要取地址*/
        make_zone_ptr(&z_p, dafs_ze);
        test_and_clear_bit_le(bitpos, z_p->statemap);
	    bitpos++;
        test_and_clear_bit_le(bitpos, z_p->statemap);
        ret = make_invalid_htable(dzt_ei->ht_head, d_hn, d_hlen, 1);

        /*free rf_entry*/
        delete_rf_entry(dzt_ei, d_hn);
        if(!ret)
            return -EINVAL;
        
        /*delete in par sub_pos*/
        par_pos = 0;
        for(par_id =0; par_id<NR_DENTRY_IN_ZONE; par_id++){
            if(test_bit_le(par_pos, z_p->statemap)||test_bit_le(par_pos+1, z_p->statemap)){
                pde = dafs_ze->dentry[par_id];
                if(dafs_de->par_ino == pde->ino){
                    /*change parent pos*/
                    for(j=0; j<pde->sub_num, j++){
                        if(pde->sub_pos[j] = de_pos){
                            k=j+1;
                            while(k<sub_num) {
                                pde->sub_pos[j] = pde->sub_pos[k];
                                k++;
                                j++;
                            }
                            pde->sub_pos[j] = 0;
                        }
                    }
                    pde->sub_num --;
                    break;
                }
                par_pos += 2;
            }else{
                par_pos += 2;
            }
        }
    }else{
        
        /*delete dir itself*/
        d_hlen = le64_to_cpu(dafs_de->ful_name->f_namelen);
        d_hn = BKDRHash(dafs_de->ful_name->f_name, d_hlen);
        bitpos = de_pos * 2;
        /*not decided z_p是不是需要取地址*/
        make_zone_ptr(&z_p, dafs_ze);
        test_and_clear_bit_le(bitpos, z_p->statemap);
	    bitpos++;
        test_and_clear_bit_le(bitpos, z_p->statemap);
        ret = make_invalid_htable(dzt_ei->ht_head, d_hn, d_hlen, 1);
        /*free rf_entry*/
        delete_rf_entry(dzt_ei, d_hn);
        if(!ret)
            return -EINVAL;

        /*delete in par sub_pos*/
        par_pos = 0;
        for(par_id =0; par_id<NR_DENTRY_IN_ZONE; par_id++){
            if(test_bit_le(par_pos, z_p->statemap)||test_bit_le(par_pos+1, z_p->statemap)){
                pde = dafs_ze->dentry[par_id];
                if(dafs_de->par_ino == pde->ino){
                    /*change parent pos*/
                    for(j=0; j<pde->sub_num, j++){
                        if(pde->sub_pos[j] = de_pos){
                            k=j+1;
                            while(k<sub_num) {
                                pde->sub_pos[j] = pde->sub_pos[k];
                                k++;
                                j++;
                            }
                            pde->sub_num[j] = 0;
                        }
                    }
                    pde->sub_num--;
                    break;
                }
                par_pos += 2;
            }else{
                par_pos += 2;
            }
        }
    }
    return 0;
}


/* removes a directory entry pointing to the inode. assumes the inode has
 * already been logged for consistency
 * 只是先将对应的状态表显示无效
 * 检查是不是根节点
 * 并不含有link的变化
 */
int dafs_rm_dir(struct dentry *dentry)
{
    struct inode *dir = dentry->d_parent->d_inode;
    struct super_block *sb = dir->i_sb;
    //struct nova_inode_info *si = NOVA_I(dir);
    //struct nova_inode_info_header *sih = &si->header;
    //struct nova_inode *pidir;
    //struct qstr *entry = &dentry->d_name;
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dafs_dentry *dafs_de;
    struct dzt_entry_info *dzt_ei, *sub_ei;
    struct dafs_zone_entry *dafs_ze;
    struct zone_ptr *z_p;
    struct dzt_manager *dzt_m = sbi->dzt_m_info;
    unsigned long phlen;
    unsigned long dzt_eno;
    unsigned long de_pos;
    unsigned long bitpos;
    unsigned short links_count;
    u64 ph_hash, de_addr, ei_hash;
    char *phname, *ph, *phn;
    int ret;
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
    ph = get_dentry_path(dentry);
    phname = kzalloc(sizeof(char)*strlen(ph), GFP_KERNEL);
    phn = kzalloc(sizeof(char)*strlen(ph), GFP_KERNEL);
    memcpy(phname, ph, strlen(ph));
    dzt_ei = find_dzt(sb, phname, ph);
    dafs_ze = (struct dafs_zone_entry *)nova_get_block(sb, dzt_ei->dz_addr);
    phlen = strlen(phn);
    dzt_eno = dzt_ei->dzt_eno;
    ph_hash = BKDRHash(phn, phlen);

    /*lookup in hash table*/
    ret = lookup_in_hashtable(dzt_ei->ht_head, ph_hash, phlen, 1, &de_pos);
    if(!ret)
        return -EINVAL;

    dafs_de = dafs_ze->dentry[de_pos];

    if(dafs_de->file_type == ROOT_DIRECTORY) {
        ei_hash = le64_to_cpu(dafs_de->dzt_hn);
        sub_ei = radix_tree_lookup(&dzt_m->dzt_root, ei_hash);
        free_zone_area(sb, sub_ei);
    }
    bitpos = de_pos * 2;
    /*not decided z_p是不是需要取地址*/
    make_zone_ptr(&z_p, dafs_ze);
    test_and_clear_bit_le(bitpos, z_p->statemap);
	bitpos++;
    test_and_clear_bit_le(bitpos, z_p->statemap);
    make_invalid_htable(dzt_ei->ht_head, ph_hash, phlen, 1);
    /*free rf_entry*/
    delete_rf_entry(dzt_ei, ph_hash);
    
    /*
    de_addr = le64_to_cpu(&dafs_de);
    record_dir_log(sb, de_addr, 0, DIR_RMDIR);*/

    
    //ret = __remove_direntry(sb, dafs_de, dafs_ze, dzt_ei, de_pos);

    if(ret)
        return ret;
    kfree(phname);
    kfree(ph);
    
    
    NOVA_END_TIMING(remove_dentry_t, remove_dentry_time);
	return 0;
}

/*remove dir when use rename*/
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
    struct dzt_entry_info *dzt_ei, *sub_ei;
    struct dafs_zone_entry *dafs_ze;
    struct zone_ptr *z_p;
    struct dzt_manager *dzt_m = sbi->dzt_m_info;
    unsigned long phlen;
    unsigned long dzt_eno;
    unsigned long de_pos;
    unsigned long bitpos;
    unsigned short links_count;
    u64 ph_hash, de_addr, ei_hash;
    char *phname, *ph, *phn;
    int ret;
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
    ph = get_dentry_path(dentry);
    phname = kzalloc(sizeof(char)*strlen(ph), GFP_KERNEL);
    phn = kzalloc(sizeof(char)*strlen(ph), GFP_KERNEL);
    memcpy(phname, ph, strlen(ph));
    dzt_ei = find_dzt(sb, phname, ph);
    dafs_ze = (struct dafs_zone_entry *)nova_get_block(sb, dzt_ei->dz_addr);
    phlen = strlen(phn);
    dzt_eno = dzt_ei->dzt_eno;
    ph_hash = BKDRHash(phn, phlen);

    /*lookup in hash table*/
    ret = lookup_in_hashtable(dzt_ei->ht_head, ph_hash, phlen, 1, &de_pos);
    if(!ret)
        return -EINVAL;

    dafs_de = dafs_ze->dentry[de_pos];
    /*
    de_addr = le64_to_cpu(&dafs_de);
    record_dir_log(sb, de_addr, 0, DIR_RMDIR);*/

    
    ret = __remove_direntry(sb, dafs_de, dafs_ze, dzt_ei, de_pos);

    if(ret)
        return ret;
    kfree(phname);
    kfree(ph);
    
    
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
    char *phname, *ph, *phn;
    unsigned long phlen;
    unsigned long bitpos ,depos;
    unsigned short delen;
    struct dafs_zone_entry *dafs_ze;
    struct dzt_entry_info *dafs_ei;
    struct zone_ptr *zone_p;
    struct dafs_dentry *dafs_de, *dafs_rde;
    u64 hashname, h_len;
    int ret;
	
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
    ph = get_dentry_path(dentry);
    phname = kzalloc(sizeof(char)*strlen(ph), GFP_KERNEL);
    phn = kzalloc(sizeof(char)*strlen(ph), GFP_KERNEL);
    memcpy(phname, ph, strlen(ph));
    phlen = strlen(phn);
    dzt_ei = find_dzt(sb, phname, phn);
    dafs_ze = (struct dafs_zone_entry *)nova_get_block(sb, dzt_ei->dz_addr);
    phhash = BKDRHash(phn, phlen);
    //not decided
    ret = lookup_in_hashtable(dzt_ei->ht_head, phhash, phlen, 1, &depos);
    if(!ret)
        return -EINVAL;
    dafs_rde = dafs_ze->dentry[depos];

    /*update read hot*/
    update_read_hot(dzt_ei, phhash);

    make_zone_ptr(&zone_p, dafs_ze);
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
    strcat(phn, "/.");
    memcpy(dafs_de->ful_name->f_name, phn, phlen+3);
    //dafs_de->ful_name->f_name = phn;

    nova_flush_buffer(dafs_de, delen, 0);
    
    /*change in dir*/
    dafs_rde->sub_num +=1;
    dafs_rde->sub_pos[0] = cpu_to_le64(cur_pos);
    
    /*make valid*/
    bitpos++;
    test_and_set_bit_le(bitpos, zone_p->statemap);
    bitpos++;
    h_len = phlen + 2;
    hashname = BKDRHash(phn, h_len);
    record_pos_htable(sb, dzt_ei->ht_head, hashname, h_len, cur_pos, 1);
    cur_pos++;

    /*new rf_entry*/
    add_rf_entry(dzt_ei, hashname);

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
    strncpy(dafs_de->name, "..\0", 3);
    dafs_de->ful_name->f_namelen = cpu_to_le64(phlen + 3);
    strcat(phn, ".");
    memcpy(dafs_de->ful_name->f_name, phn, phlen+4)
    //dafs_de->ful_name->f_name = phn;
    
    nova_flush_buffer(dafs_de, delen, 0);
    
    dafs_rde->sub_num +=1;
    dafs_rde->sub_pos[1] = cpu_to_le64(cur_pos);
    
    /*make valid*/
    bitpos++;
    test_and_set_bit_le(bitpos, zone_p->statemap);
    h_len = phlen + 3;
    hashname = BKDRHash(phn, h_len);
    record_pos_htable(sb, dzt_ei->ht_head, hashname, h_len, cur_pos, 1);

    /*new rf_entry*/
    add_rf_entry(dzt_ei, hashname);
    //不需要update tail
    
    kfree(phname);
    kfree(ph);
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
    char *phname, *ph, phn;
    unsigned long nr_de;
    int i, ret;

    ph = get_dentry_path(dentry);
    phname = kzalloc(sizeof(char)*strlen(ph), GFP_KERNEL);
    phn = kzalloc(sizeof(char)*strlen(ph), GFP_KERNEL);
    memcpy(phname, ph, strlen(ph));
    dzt_ei = find_dzt(sb, phname, phn);
    dafs_ze = (struct dafs_zone_entry *)nova_get_block(sb, dzt_ei->dz_addr);
    phlen = strlen(phn);
    dzt_eno = dzt_ei->dzt_eno;
    ph_hash = BKDRHash(phn, phlen);

    kfree(phname);
    kfree(ph);
    /*lookup in hash table, not decided*/
    ret = lookup_in_hashtable(dzt_ei->ht_head, ph_hash, phlen, 1, &de_pos);
    if(!ret)
        return -EINVAL;

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
int add_rename_zone_dir(struct dentry *dentry, struct dafs_dentry *old_de, u64 *new_hn, u64 *root_len)
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
    char *phname, *new_pn, *ph, *phn;
    unsigned long phlen;
    unsigned short delen;
    unsigned long bitpos = 0, cur_pos = 0;
    u64 hashname, newp_len;
    int ret = 0;
    timing_t add_dentry_time;

    
	/*nova_dbg_verbose("%s: dir %lu new inode %llu\n",
				__func__, dir->i_ino, ino);
	nova_dbg_verbose("%s: %s %d\n", __func__, name, namelen);*/

	NOVA_START_TIMING(add_dentry_t, add_dentry_time);
	if (namelen == 0)
		return -EINVAL;
    
    ph = get_dentry_path(dentry);
    phname = kzalloc(sizeof(char)*strlen(ph), GFP_KERNEL);
    phn = kzalloc(sizeof(char)*strlen(ph), GFP_KERNEL);
    memcpy(phname, ph, strlen(ph));
    dzt_ei = find_dzt(sb, phname, phn);
    dafs_ze = (struct dafs_zone_entry *)nova_get_block(sb, dzt_ei->dz_addr);

    make_zone_ptr(&zone_p, dafs_ze);
    while(bitpos<zone_p->zone_max){
        if(test_bit_le(bitpos, zone_p->statemap)||test_bit_le(bitpos+1, zone_p->statemap)){
            bitpos+=2;
            cur_pos++;
        }else{
            break;
        }
    }

    phlen = strlen(phn);
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
    //dafs_de->zone_no = old_de->dz_no;
    //dafs_de->prio = old_de->prio;
    //dafs_de->d_f = old_de->d_f;
    //dafs_de->sub_s = old_de->sub_s;
    //dafs_de->f_s = old_de->f_s;
    dafs_de->sub_num = old->sub_num;
    dafs_de->sub_pos[NR_DENTRY_IN_ZONE] = {0};
    /*不存储名字字符在初始化的时候*/
    dafs_de->name[dentry->d_name.len] = '\0';
    dafs_de->ful_name->f_namelen = cpu_to_le64(phlen);
    /*那路径名称呢*/
    memcpy(dafs_de->ful_name->f_name, phn, phlen);
    //dafs_de->ful_name->f_name = phn;

    /*get new ei path hashname*/
    if(dzt_ei->eno!=1){
        newp_len =(u64)dzt_ei->root_len + phlen;
        new_pn = kzalloc(sizeof(char)*newp_len, GFP_KERNEL);
        get_zone_path(sb,dzt_ei, new_pn, phn);
        *root_len = newp_len;
        *new_hn = BKDRHash(new_pn, newp_len);
        kfree(new_pn);
    } else {
        newp_len = phlen;
        new_pn = kzalloc(sizeof(char *)*newp_len, GFP_KERNEL);
        memcpy(new_pn, phn);
        *root_len = newp_len;
        *new_hn = BKDRHash(new_pn, newp_len);
        kfree(new_pn);
    }

    dafs_de->dzt_hn = cpu_to_le64(*new_hn);

    /*not decided是不是每次写到nvm都需要这个接口*/ 
    nova_flush_buffer(dafs_de, delen, 0);
    
    /*make valid*/
    bitpos++;
    test_and_set_bit_le(bitpos, zone_p->statemap);
    
    dir->i_blocks = pidir->i_blocks;

    /*set pos in hash table for each zone*/
    hashname = BKDRHash(phn, phlen);
    record_pos_htable(sb, dzt_ei->ht_head, hashname, phlen, cur_pos, 1);

    /*new rf_entry*/
    add_rf_entry(dzt_ei, hashname);

    kfree(phname);
    kfree(ph);
    NOVA_END_TIMING(add_dentry_t, add_entry_time);
    return ret;
}

/*rename code recursive
 * n_ze是new_dentry所在的zone
 * path是新的目录的字符串
 * name纯的文件名*/
int __rename_dir(struct super_block *sb, struct dafs_dentry *src_de, \
        struct dzt_entry_info *dzt_ei, const char *path, char *name)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct zone_ptr *z_p;
    struct dafs_dentry *new_de, *sub_de, *sub_nde;
    struct dafs_zone_entry *ze;
    struct dzt_entry_info *ch_ei;
    struct dzt_manager *dzt_m = sbi->dzt_m_info;
    struct rf_entry *new_rf;
    unsigned long sub_num;
    unsigned long bitpos = 0, dir_pos = 0, s_pos;
    unsigned short delen;
    int i, ret=0;
    char *new_ph, *s_name, *sub_ph, ch_ph;
    u64 phlen,src_len, hashname, dzt_hn, ch_len, sub_len;

    ze = (struct dafs_zone_entry *)nova_get_block(sb, dzt_ei->dz_addr);
    make_zone_ptr(&z_p, ze);

    sub_num = le64_to_cpu(src_de->sub_num);

    //src_ph = src_de->ful_name->f_name;
    //s_ph = src_de->name;
    /*含有'/'*/
    //phlen = strlen(src_ph)-strlen(o_name);
    //memcpy(new_ph, src_ph, phlen);
    //strcat(new_ph, n_name);
    new_ph = kzalloc(sizeof(char )*DAFS_PATH_LEN, GFP_KERNEL);
    memcpy(new_ph, path, strlen(path)+1);
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
    //new_de->zone_no = ze->dz_no;
    //new_de->prio = src_de->prio;
    //new_de->d_f = src_de->d_f + 1;
    //new_de->sub_s = src_de->sub_s;
    //new_de->f_s = DENTRY_FREQUENCY_WRITE;
    new_de->sub_num = src_de->sub_num;
    new_de->sub_pos[NR_DENTRY_IN_ZONE] = {0};
    /*不存储名字字符在初始化的时候*/
    memcpy(new_de->name, name, strlen(name)+1);
    //new_de->name[str(name)] = name;
    new_de->ful_name->f_namelen = cpu_to_le64(strlen(new_ph));
    /*那路径名称呢*/
    memcpy(new_de->ful_name->f_name, new_ph, strlen(new_ph)+1);
    //new_de->ful_name->f_name = new_ph;

    nova_flush_buffer(new_de, delen, 0);
    
    /*make valid*/
    bitpos++;
    test_and_set_bit_le(bitpos, z_p->statemap);
    bitpos++;
    hashname = BKDRHash(new_ph, strlen(new_ph));
    record_pos_htable(sb, dzt_ei->ht_head, hashname, strlen(new_ph), dir_pos, 1);
    dir_pos++;

    /*new rf_entry*/
    new_rf = add_rf_entry(dzt_ei, hashname);
    new_rf->f_s = DENTRY_FREQUENCY_WRITE;
    //ret = update_write_hot(dzt_ei, hashname);
    if(ret)
        return -EINVAL;
    
    /*rename 子文件*/
    for(i = 0; i<sub_num; i++) {
        sub_ph = kzalloc(sizeof(char )*DAFS_PATH_LEN, GFP_KERNEL);
        sub_len = le64_to_cpu(sub_de->name_len);
        s_name = kzalloc(sizeof(char )*(sub_len+1), GFP_KERNEL);
        s_pos = src_de->sub_pos[i];
        sub_de = ze->dentry[s_pos];
        memcpy(s_name, sub_de->name, sub_len+1);
        //s_name = sub_de->name;
        //strcat(o_name, "/");
        //strcat(o_name, s_name);
        //src_len = strlen(o_name)+1;
        //memcpy(s_ph, name, sizeof(name));
        //strcat(s_ph, s_name);
        memcpy(sub_ph, new_ph, sizeof(new_ph));
        strcat(sub_ph, "/");
        strcat(sub_ph, s_name);

        if(sub_de->file_type == NORMAL_DIRECTORY){
            ret = __rename_dir(sb, sub_de, dzt_ei, sub_ph, s_name);

        } else {
            delen = DAFS_DIR_LEN(str(s_name)+str(sub_ph));
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
            new_de->name_len = sub_de->name_len;
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
            //new_de->zone_no = ze->dz_no;
            //new_de->prio = sub_de->prio;
            //new_de->d_f = sub_de->d_f + 1;
            //new_de->sub_s = sub_de->sub_s;
            //new_de->f_s = DENTRY_FREQUENCY_WRITE;
            new_de->sub_num = sub_de->sub_num;
            new_de->sub_pos[NR_DENTRY_IN_ZONE] = {0};
            /*不存储名字字符在初始化的时候*/
            memcpy(new_de->name, sub_de->name, sub_len+1);
            //new_de->name[strlen(s_name)] = sub_de->name;
            new_de->ful_name->f_namelen = cpu_to_le64(strlen(sub_ph));
            /*那路径名称呢*/
            memcpy(new_de->ful_name->f_name, sub_ph, strlen(sub_ph)+1);
            //new_de->ful_name->f_name = sub_ph;
           
            /*ROOT_DIRECTORY update ei*/
            if(new_de->file_type==ROOT_DIRECTORY) {
                dzt_hn = le64_to_cpu(sub_de->dzt_hn);
                ch_ei = radix_tree_delete(&dzt_m->dzt_root, dzt_hn);
                if(dzt_ei->dzt_eno!=1) {
                    ch_len =(u64)dzt_ei->root_len + strlen(sub_ph);
                    ch_ph = kzalloc(sizeof(char *)ch_len, GFP_KERNEL);
                    get_zone_path(sb, dzt_ei, ch_ph, sub_ph);
                } else {
                    ch_len = strlen(sub_ph);
                    ch_ph = kzalloc(sizeof(char *)*ch_len, GFP_KERNEL);
                    memcpy(ch_ph, sub_ph, ch_len+1);
                }
                dzt_hn = BKDRHash(ch_ph, ch_len);
                ch_ei->root_len = (u32)ch_len;
                ch_ei->hash_name = dzt_hn;
                radix_tree_insert(&dzt_m->dzt_root, dzt_hn);
                radix_tree_tag_set(&dzt_m->dzt_root, dzt_hn, 1);
                kfree(ch_ph);
                new_de->dzt_hn = cpu_to_le64(dzt_hn);
            } else {
                new_de->dzt_hn = sub_de->dzt_hn;
            }

            nova_flush_buffer(new_de, delen, 0);
             
            /*make valid*/
            bitpos++;
            test_and_set_bit_le(bitpos, z_p->statemap);
            hashname = BKDRHash(sub_ph, strlen(sub_ph));
            record_pos_htable(sb, dzt_ei->ht_head, hashname, strlen(sub_ph), dir_pos, 1);
            bitpos++;
            dir_pos++;
            
            /*new rf_entry*/
            new_rf = add_rf_entry(dzt_ei, hashname);
            new_rf->f_s = DENTRY_FREQUENCY_WRITE;
            
        }
        kfree(s_name);
        kfree(sub_ph);
    }

    kfree(new_ph);
    return ret;

}

/*rename directories*/
int add_rename_dir(struct dentry *o_dentry, struct dentry *n_dentry, struct dafs_dentry *old_de)
{
    struct super_block *sb = o_dentry->d_sb;
    struct dafs_dentry *new_de;
    struct dzt_entry_info *o_ei, *n_ei;
    struct dafs_zone_entry *o_ze, *n_ze;
    char  *n_name, *n_phname, *ph, *phn;
    unsigned long bitpos, cur_pos;
    int i;
    int ret= 0;

    /*
    //not decided
    o_phname = get_dentry_path(o_dentry);
    o_ei = find_dzt(sb, &o_phname);
    o_ze = cpu_to_le64(o_ei->dz_addr);*/
    
    ph = get_dentry_path(n_dentry);
    n_phname = kzalloc(sizeof(char)*strlen(ph), GFP_KERNEL);
    phn = kzalloc(sizeof(char)*strlen(ph), GFP_KERNEL);
    memcpy(n_phname, ph, strlen(ph)+1);
    n_ei = find_dzt(sb, n_phname, phn);
    n_ze = (struct dafs_zone_entry *)nova_get_block(sb, n_ei->dz_addr);

    n_name = n_dentry->d_name.name;

    ret = __rename_dir(old_de, n_ei, phn, n_name);
    
    kfree(phname);
    kfree(ph);
    return ret;
}

/*rename_s 是父文件夹是否变化的标志
 * 0不变化父文件夹
 * ch_link inc or dec links
 * not decided 标记log*/
int __rename_dir_direntry(struct dentry *old_dentry, struct dentry *new_dentry)
{ 
    struct super_block *sb = old_dentry->d_sb;
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dafs_dentry *old_de, *new_de;
    struct dafs_zone_entry *ze;
    struct zone_ptr *z_p;
    struct inode *new_inode = new_dentry->d_inode;
    struct inode *old_inode = old_dentry->d_inode;
    struct dzt_entry_info *ch_ei;
    struct dzt_manager *dzt_m = sbi->dzt_m_info;
    //char *phname;
    u64 dz_no, old_hn, new_hn, root_len;
    int err = -ENOENT;

    old_de = dafs_find_direntry(sb, old_dentry,0);
    //dz_no = le64_to_cpu(old_de->zone_no);
    if(old_de->file_type == ROOT_DIRECTORY){
        old_hn = le64_to_cpu(old_de->hash_name);
        ch_ei = radix_tree_delete(&dzt_m->dzt_root, old_hn);
        err = add_rename_zone_dir(new_dentry, old_de, &new_hn, &root_len);
        /*防止zone被删除*/
        if(err)
            return err;
        ch_ei->root_len = (u32)root_len;
        ch_ei->hash_name = new_hn;
        /*update ei hashname, root len and set dirty bit*/
        radix_tree_insert(&dzt_m->dzt_root, new_hn);
        radix_tree_tag_set(&dzt_m->dzt_root, new_hn, 1);

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
    struct rf_entry *new_rf;
    char *n_phname, *name=new_dentry->d_name.name, *phname, *ph, *phn;
    unsigned long bitpos=0, cur_pos=0;
    int namelen = new_dentry->d_name.len;
    unsigned short de_len;
    unsigned long phlen;
    u64 hashname;

    o_de = dafs_find_direntry(sb, o_de, 0);

    ph = get_dentry_path(new_dentry);
    phname = kzalloc(sizeof(char)*strlen(ph), GFP_KERNEL);
    phn = kzalloc(sizeof(char)*strlen(ph), GFP_KERNEL);
    memcpy(phname, ph, strlen(ph)+1);
    n_ei = find_dzt(sb, phname, phn);
    n_ze = (struct dafs_zone_entry *)nova_get_block(sb, n_ei->dz_addr);
    phlen = strlen(phn);
    make_zone_ptr(&z_p, n_ze);
    while(bitpos<z_p->zone_max){
        if(test_bit_le(bitpos, z_p->statemap)||test_bit_le(bitpos+1, z_p->statemap)){
            bitpos+=2;
            cur_pos++;
        }else{
            break;
        }
    }

    //phlen = strlen(n_phname);
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
    //dafs_de->prio = o_de->prio;
    //dafs_de->d_f = o_de->d_f;
    //dafs_de->sub_s = o_de->sub_s;
    //dafs_de->f_s = DENTRY_FREQUENCY_WRITE;
    dafs_de->sub_num = 0;
    dafs_de->sub_pos[NR_DENTRY_IN_ZONE] = {0};
    /*不存储名字字符在初始化的时候*/
    memcpy(dafs_de->name, name, (dentry->d_name.len) +1);
    //dafs_de->name[namelen] = name;
    dafs_de->ful_name->f_namelen = cpu_to_le64(phlen);
    /*那路径名称呢*/
    memcpy(dafs_de->ful_name->f_name, phn, phlen+1);
    //dafs_de->ful_name->f_name = phn;
    /*not decided是不是每次写到nvm都需要这个接口*/ 
    nova_flush_buffer(dafs_de, de_len, 0);
    
    /*make valid*/
    bitpos++;
    test_and_set_bit_le(bitpos, z_p->statemap);
   
    dafs_remove_dentry(old_dentry);
    dir->i_blocks = pidir->i_blocks;

    /*set pos in hash table for each zone*/
    hashname = BKDRHash(phn, phlen);
    record_pos_htable(sb, n_ei->ht_addr, hashname, phlen, cur_pos, 1);

    /*new rf_entry*/
    new_rf = add_rf_entry(n_ei, hashname);
    new_rf->f_s = DENTRY_FREQUENCY_WRITE;
    
    kfree(phname);
    kfree(ph);
    NOVA_END_TIMING(add_dentry_t, add_entry_time);

    return ret;
    
}

/*遍历文件夹，dir_emit填充到用户空间*/
static int dafs_readdir(struct file *file, struct dir_context *ctx)
{
    struct inode *inode = file_inode(file);
    struct super_block *sb = inode->i_sb;
    struct nova_inode *pidir;
    struct nova_inode *child_pi;
    struct dentry *dentry = file->f_path.dentry; 
    struct dafs_dentry *de = NULL;
    struct dafs_dentry *f_de = NULL;
    struct dzt_entry_info *ei;
    struct dafs_zone_entry *ze;
    unsigned short de_len;
    u64 pi_addr;
    unsigned long pos = 0, sub_num, n = 0;
    ino_t ino;
    u8 type;
    int ret;
    char *phname, *ph, *phn;
    timing_t readdir_time;

    NOVA_START_TIMING(readdir_t, readdir_time);
    pidir = nova_get_inode(sb ,inode);
    
	nova_dbgv("%s: ino %llu, size %llu, pos 0x%llx\n",
			__func__, (u64)inode->i_ino,
			pidir->i_size, ctx->pos);

    ph = get_dentry_path(dentry);
    phname = kzalloc(sizeof(char)*strlen(ph), GFP_KERNEL);
    phn = kzalloc(sizeof(char)*strlen(ph), GFP_KERNEL);
    memcpy(phname, ph, strlen(ph));
    ei = find_dzt(sb, phname, phn);

    kfree(phname);
    kfree(ph);
    if(!ei){
        nova_err("ei with dentry %lu not exist!\n", dentry->d_inode->i_ino);
        BUG();
        return EINVAL;
    }

    ze = (struct dafs_zone_entry *)nova_get_block(sb, n_ei->dz_addr);
	f_de = dafs_find_direntry(sb, dentry,1);
    
    sub_num = le64_to_cpu(f_de->sub_num);

    pos = ctx->pos;

    if(pos == READDIR_END){
        goto out;
    } 

    while(n < sub_num){
        pos = f_de->sub_pos[n];
        if(!pos){
            ctx->pos = READDIR_END;
            goto out;
        }

        de = ze->dentry[pos];
        type = nova_get_entry_type((void *)de);
        if(type != DAFS_DIR_ENTRY){
            nova_dbg ("unknown type\n");
            BUG();
            return -EINVAL;
        }

		nova_dbgv("pos %lu, type %d, ino %llu, "
			"name %s, namelen %u, rec len %u\n", pos,
			de->entry_type, le64_to_cpu(de->ino),
			de->name, de->name_len,
			le16_to_cpu(de->de_len));

        if(de->ino>0){
            ino = __le64_to_cpu(de->ino);
            ret = nova_get_inode_address(sb, ino, &pi_addr, 0);
            if(ret){
				nova_dbg("%s: get child inode %lu address "
					"failed %d\n", __func__, ino, ret);
				ctx->pos = READDIR_END;
				return ret;
            }

            child_pi = nova_get_block(sb, pi_addr);
			nova_dbgv("ctx: ino %llu, name %s, "
				"name_len %u, de_len %u\n",
				(u64)ino, de->name, de->name_len,
				de->de_len);
			if (!dir_emit(ctx, de->name,
				de->name_len, ino,
				IF2DT(le16_to_cpu(_child_pi->i_mode)))) {
				nova_dbgv("Here: pos %llu\n", ctx->pos);
				return 0;
			}

        }
        ctx->pos = pos;
        n++;

    }
    
out:
	NOVA_END_TIMING(readdir_t, readdir_time);
	nova_dbgv("%s return\n", __func__);
	return 0;

}



const struct file_operations dafs_dir_operations = {
    .llseek      = generic_file_llseek,
    .read        = generic_read_dir,
    .iterate     = dafs_readdir,
    .fsync       = noop_fsync,
    .unlocked_ioctl = nova_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl   = nova_compat_ioctl,
#endif
};
