/*
	> File Name: dafs_dir.c
	> Author:CX
	> Mail: tianfangmmr@126.com
	> Created Time: 2017年10月09日 星期一 15时49分06秒
 ************************************************************************/

#include<linux/fs.h>
#include<linux/pagemap.h>
#include<linux/path.h>
#include<linux/string.h>
#include<linux/mount.h>
#include<linux/path.h>
#include<linux/netdevice.h>
#include<linux/fs_struct.h>
#include<linux/time.h>
#include "nova.h"
//#include "zone.h"

#define DT2IF(dt) (((dt) << 12) & S_IFMT)
#define IF2DT(sif) (((sif) & S_IFMT) >> 12)

//char *fph = (char *)kmalloc(sizeof(char)*DAFS_PATH_LEN,GFP_KERNEL);
//char *phname =(char *)kmalloc(sizeof(char)*DAFS_PATH_LEN, GFP_KERNEL);
//char *phn = (char *)kmalloc(sizeof(char)*DAFS_PATH_LEN, GFP_KERNEL);

void tes_empty_zone(struct super_block *sb, struct zone_ptr *z_p)
{
    u32 pos = 0, epos = 0;
    u32 bitpos = 0;

    while(pos<NR_DENTRY_IN_ZONE){
        if(test_bit_le(bitpos, (void *)z_p->statemap)||test_bit_le(bitpos+1, (void *)z_p->statemap)){
            bitpos+=2;
            pos++;
            //nova_dbg("%s: valid pos %d", __func__, pos);
        } else {
            bitpos+=2;
            pos++;
            epos++;
        }
    }
    //nova_dbg("%s: empty pos num %d",__func__, epos);
}

/*delete dir_info entry*/
int delete_dir_info(struct dzt_entry_info *ei, u64 hashname)
{
    struct dir_info *dir_i;
    struct file_p *o_sf;
    struct list_head *this=NULL, *head=NULL, *next=NULL;

    //nova_dbg("%s start",__func__);
    dir_i = radix_tree_delete(&ei->dir_tree, hashname);
    if(!dir_i){
        //nova_dbg("dir info not found");
        goto OUT;
    }
    //nova_dbg("dir sub num is %llu",dir_i->sub_num);
    head = &dir_i->sub_file;
    list_for_each_safe(this, next, head) {
        o_sf = list_entry(this, struct file_p, list);
        //nova_dbg("list pos %d",o_sf->pos);
        //find bug
        list_del(&o_sf->list);
        kfree(o_sf);
    }

    kfree(dir_i);
OUT:
    //nova_dbg("%s end",__func__);
    return 0;
}

/*delete dir_info tree*/
int delete_dir_tree(struct dzt_entry_info *ei)
{
    struct dir_info *dir_i;
    struct dir_info *entries[FREE_BATCH];
    struct file_p *o_sf;
    struct list_head *head, *this, *next;
    u64 key, dir_index=0;
    int nr, i;
    void *ret;

    do {
        nr = radix_tree_gang_lookup(&ei->dir_tree, (void **)entries, dir_index, FREE_BATCH);
        for(i=0; i<nr; i++) {
            dir_i = entries[i];
            key = dir_i->dir_hash;
            dir_index = dir_i->dir_hash;
            ret = radix_tree_delete(&ei->dir_tree, key);
            head = &dir_i->sub_file;
            list_for_each_safe(this, next, head) {
                o_sf = list_entry(this, struct file_p, list);
                list_del(&o_sf->list);
                kfree(o_sf);
            }
            if(!ret)
                return -EINVAL;
                //nova_dbg("ret is NULL\n");
            kfree(dir_i);
        }
        dir_index ++;
    } while (nr==FREE_BATCH);

    return 0;
}

/*delete rf_entry*/
/*int delete_rf_entry(struct dzt_entry_info *ei, u64 hash_name)
{
    struct rf_entry *old_rf;

    old_rf = radix_tree_delete(&ei->rf_root, hash_name);
    kfree(old_rf);
    return 0;

}*/

/*add dir_info_entry in dir_info_tree*/
struct dir_info *add_dir_info(struct dzt_entry_info *ei, u64 hash_name, u32 pos)
{
    struct dir_info *new_dir;

    //nova_dbg("dafs add dir info in radix tree");
    new_dir = kzalloc(sizeof(struct dir_info), GFP_KERNEL);
    new_dir->r_f = 0;
    new_dir->sub_s = 0;
    new_dir->f_s = 0;
    new_dir->prio = LEVEL_0;
    new_dir->sub_num = 0;
    new_dir->dir_hash = hash_name;
    new_dir->dir_pos = pos;
    //nova_dbg("dir hash name is %llu", hash_name);
    INIT_LIST_HEAD(&new_dir->sub_file);
    radix_tree_insert(&ei->dir_tree, hash_name, new_dir);
    return new_dir;
}

/*update read frequency when read happens*/
int update_read_hot(struct dzt_entry_info *dzt_ei, u64 hn)
{
    struct dir_info *dir_info;
    dir_info = radix_tree_lookup(&dzt_ei->dir_tree, hn);
    if(!dir_info)
        BUG();
    dir_info->r_f++;

    return 0;
}

/*update write frequency when rename happens */
/*int update_rename_hot(struct dzt_entry_info *dzt_ei, u64 sub_hash)
{
    struct rf_entry *sub_rf;
    sub_rf = radix_tree_lookup(&dzt_ei->rf_root, sub_hash);
    if(!sub_rf)
        return -EINVAL;
    sub_rf->f_s = DENTRY_FREQUENCY_WRITE; 
    return 0;
}*/

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
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dzt_manager *dzt_m = sbi->dzt_m_info;
    struct dafs_dzt_block *dzt_blk = dafs_get_dzt_block(sb); 
    u32 num = ei->dzt_eno, slen;
    u32 de_pos;
    u64 phlen=0, hashname;
    char *path, *name;

    //nova_dbg("%s start",__func__);
    phlen = ei->root_len;
    path = kzalloc(sizeof(char )*(phlen+1), GFP_KERNEL);
    name = kzalloc(sizeof(char)*(phlen+1), GFP_KERNEL);
    while(num!=0){
        ze = (struct dafs_zone_entry *)nova_get_block(sb, ei->pdz_addr);
        de_pos = ei->rden_pos;
        de = &ze->dentry[de_pos];
        get_de_name(de, ze, name, 1);
        strcat(name,path);
        slen = strlen(name);
        memcpy(path, name, slen);
        path[slen]='\0';
        num = le64_to_cpu(ze->dz_no);
        hashname = le64_to_cpu(dzt_blk->dzt_entry[num].hash_name);
        ei = radix_tree_lookup(&dzt_m->dzt_root, hashname);
    }
    strcat(path, dename);
    slen = strlen(path);
    memcpy(pname, path, slen);
    pname[slen]= '\0';
    //memcpy(pname+strlen(path),end,1);
    kfree(path);
    kfree(name);
    //nova_dbg("%s end get name %s",__func__,pname);
    return 0;

}

static inline int  find_dentry_path(const struct dentry *dentry, char *ph, u64 ino)
{
    struct inode *dir = dentry->d_parent->d_inode;
    struct super_block *sb = dir->i_sb;
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct path_tree *pt= sbi->pt;
    struct path_entry *pe = NULL;
    u64 i_ino=0;
    u64 phlen=0;
    u32 ret=0;
    timing_t  st;

    //nova_dbg("%s:start %s",__func__,dentry->d_name.name);
    getrawmonotonic(&st); 
    
    if(!ino)
        goto END;

    ph[0]='\0';
    pe = radix_tree_lookup(&pt->de_path, ino);

    if(pe){
        memcpy(ph, pe->path, pe->len);
        ph[pe->len]='\0';
        //nova_dbg("%s name %s",__func__,ph);
        goto END;
    } 

    /*pe is null*/
    /*
    i_ino = dir->i_ino;
    pe = radix_tree_lookup(&pt->de_path, i_ino);
    if(pe){
        strcat(ph, pe->path);
        
        if(strcmp(ph, "/"))
            strcat(ph, "/");

        if(strcmp(dentry->d_name.name, "/"))
            strcat(ph, dentry->d_name.name);
        //nova_dbg("%s name %s",__func__,ph);
        goto END;
    }*/

    ret = 1;

END:
   // print_time(st);
   // nova_dbg("%s", __func__);
    return ret;
}

struct dzt_entry_info *mk_path(const struct dentry *dentry, char *ph, u64 ino)
{

    struct inode *dir = dentry->d_parent->d_inode;
    struct super_block *sb = dir->i_sb;
    struct nova_sb_info *sbi = NOVA_SB(sb);
    char ph_f[DAFS_PATH_LEN], ph_dzt[DAFS_PATH_LEN], ph_name[DAFS_PATH_LEN];
    char *buf = ph_dzt, *tem = ph_name, *ppath;
    //char *buf = NULL, *ppath=NULL, *tem=NULL;
    struct fs_struct *fs = current->fs;
    struct vfsmount *vfsmnt = NULL;
    //struct path path;
    struct dentry *tem_dentry, *p_dentry = dentry->d_parent;
    struct dentry *rd;
    struct path_tree *pt= sbi->pt;
    struct path_entry *pe = NULL;
    u64 i_ino=0;
    u64 phlen=0,tlen=0,plen=0,pplen=0;
    u32 i;
    struct dzt_entry_info *ei=NULL;
    timing_t getpath_time, st, ad;

    //nova_dbg("%s:start %s",__func__,dentry->d_name.name);
    //getrawmonotonic(&st); 
    NOVA_START_TIMING(getpath_t, getpath_time);
    
    if(!ino)
        goto NEXT;

    ph[0]='\0';

    /*pe is null*/
    i_ino = dir->i_ino; 
    pe = radix_tree_lookup(&pt->de_path, i_ino);
    if(pe){
        strcat(ph, pe->path);
        
        if(strcmp(ph, "/"))
            strcat(ph, "/");

        if(strcmp(dentry->d_name.name, "/"))
            strcat(ph, dentry->d_name.name);
        //nova_dbg("%s name %s",__func__,ph);
        //getrawmonotonic(&ad); 
        phlen = strlen(ph);
        pe = kzalloc(sizeof(struct path_entry), GFP_KERNEL);
        pe->ino = ino;
        pe->len = phlen;
        memcpy(pe->path, ph, phlen);
        pe->path[phlen]='\0';
        radix_tree_insert(&pt->de_path, ino, pe);
        //print_time(ad);
        //nova_dbg("%s", __func__);
        goto END;
    }
NEXT:
    read_lock(&fs->lock);
    vfsmnt = mntget(fs->pwd.mnt);
    if(!vfsmnt){
        //nova_dbg("not find mnt");
        goto END;
    }
    rd= vfsmnt->mnt_root;

    read_unlock(&fs->lock);
    tem_dentry = dentry;
    if(strcmp(dentry->d_name.name,"/")){
        memcpy(buf,"/",1);
        buf[1]='\0';
    }else{
        //nova_dbg("%s root dentry",__func__);
        memcpy(ph, "/", 1);
        ph[1]='\0';
        goto END;
    }

    //plen = strlen(buf);

    do{
        strcat(buf, "/");
        strcat(buf, tem_dentry->d_name.name);
        p_dentry = tem_dentry->d_parent;
        tem_dentry = p_dentry;
        if(!strcmp(p_dentry->d_name.name, "/") && p_dentry->d_inode->i_ino == NOVA_ROOT_INO)
            break;
    }while(1);

    //tem[0]='\0';
    tlen = strlen(buf);
    //strcat(tem, buf);
    memcpy(tem, buf, tlen);
    tem[tlen]='\0';
    //nova_dbg("%s buf is %s tem is %s",__func__, buf, tem);
    ph[0]='\0';

    do{
        ppath = strrchr(tem, '/');
        plen = strlen(ppath);
        tlen = tlen - plen;
        phlen += plen;
        //BUG_ON(strlen(tem)==0);
        strcat(ph, ppath);
        memcpy(tem, buf, tlen);
        tem[tlen]='\0';
        if(!strcmp(tem,"/")){
            break;
        }
    }while(1);

    /*
    phlen = strlen(ph);
    ino = dentry->d_inode->i_ino;
    pe = kzalloc(sizeof(struct path_entry), GFP_KERNEL);
    pe->ino = ino;
    pe->len = phlen;
    memcpy(pe->path, ph, phlen);
    pe->path[phlen]='\0';
    radix_tree_insert(&pt->de_path, ino, pe);
    */

    mntput(vfsmnt);
END:
	NOVA_END_TIMING(getpath_t, getpath_time);
    //print_time(st);
    //nova_dbg("%s", __func__);
    return ei;
}

/*get dentry path except filename*/
static inline int  get_dentry_path(const struct dentry *dentry, char *ph, u64 ino)
{
    struct inode *dir = dentry->d_parent->d_inode;
    struct super_block *sb = dir->i_sb;
    struct nova_sb_info *sbi = NOVA_SB(sb);
    char ph_f[DAFS_PATH_LEN], ph_dzt[DAFS_PATH_LEN], ph_name[DAFS_PATH_LEN];
    char *buf = ph_dzt, *tem = ph_name, *ppath;
    //char *buf = NULL, *ppath=NULL, *tem=NULL;
    struct fs_struct *fs = current->fs;
    struct vfsmount *vfsmnt = NULL;
    //struct path path;
    struct dentry *tem_dentry, *p_dentry = dentry->d_parent;
    struct dentry *rd;
    struct path_tree *pt= sbi->pt;
    struct path_entry *pe = NULL;
    u64 i_ino=0, hashname;
    u64 phlen=0,tlen=0,plen=0,pplen=0;
    u32 i;
    timing_t getpath_time, st, ad;

    //nova_dbg("%s:start %s",__func__,dentry->d_name.name);
    //getrawmonotonic(&st); 
    NOVA_START_TIMING(getpath_t, getpath_time);
    
    if(!ino)
        goto NEXT;

    ph[0]='\0';
    //getrawmonotonic(&ad); 
    pe = radix_tree_lookup(&pt->de_path, ino);
    //print_time(ad);
    //nova_dbg("%s", __func__);

    if(pe){
        memcpy(ph, pe->path, pe->len);
        ph[pe->len]='\0';
        //nova_dbg("%s name %s",__func__,ph);
        goto END;
    } 

    /*pe is null*/
    i_ino = dir->i_ino; 
    pe = radix_tree_lookup(&pt->de_path, i_ino);
    if(pe){
        strcat(ph, pe->path);
        
        if(strcmp(ph, "/"))
            strcat(ph, "/");

        if(strcmp(dentry->d_name.name, "/"))
            strcat(ph, dentry->d_name.name);
        //nova_dbg("%s name %s",__func__,ph);
        //getrawmonotonic(&ad); 
        phlen = strlen(ph);
        pe = kzalloc(sizeof(struct path_entry), GFP_KERNEL);
        hashname = BKDRHash(ph, phlen);
        pe->ino = ino;
        pe->len = phlen;
        pe->hn = hashname;
        memcpy(pe->path, ph, phlen);
        pe->path[phlen]='\0';
        radix_tree_insert(&pt->de_path, ino, pe);
        //print_time(ad);
        //nova_dbg("%s", __func__);
        goto END;
    }

NEXT:
    
    read_lock(&fs->lock);
    vfsmnt = mntget(fs->pwd.mnt);
    if(!vfsmnt){
        //nova_dbg("not find mnt");
        goto END;
    }
    rd= vfsmnt->mnt_root;

    read_unlock(&fs->lock);
    tem_dentry = dentry;
    if(strcmp(dentry->d_name.name,"/")){
        memcpy(buf,"/",1);
        buf[1]='\0';
    }else{
        //nova_dbg("%s root dentry",__func__);
        memcpy(ph, "/", 1);
        ph[1]='\0';
        goto END;
    }

    //plen = strlen(buf);

    do{
        strcat(buf, "/");
        strcat(buf, tem_dentry->d_name.name);
        p_dentry = tem_dentry->d_parent;
        tem_dentry = p_dentry;
        if(!strcmp(p_dentry->d_name.name, "/") && p_dentry->d_inode->i_ino == NOVA_ROOT_INO)
            break;
    }while(1);

    //tem[0]='\0';
    tlen = strlen(buf);
    //strcat(tem, buf);
    memcpy(tem, buf, tlen);
    tem[tlen]='\0';
    //nova_dbg("%s buf is %s tem is %s",__func__, buf, tem);
    ph[0]='\0';

    do{
        ppath = strrchr(tem, '/');
        plen = strlen(ppath);
        tlen = tlen - plen;
        phlen += plen;
        //BUG_ON(strlen(tem)==0);
        strcat(ph, ppath);
        memcpy(tem, buf, tlen);
        tem[tlen]='\0';
        if(!strcmp(tem,"/")){
            break;
        }
    }while(1);

    /*
    phlen = strlen(ph);
    ino = dentry->d_inode->i_ino;
    pe = kzalloc(sizeof(struct path_entry), GFP_KERNEL);
    pe->ino = ino;
    pe->len = phlen;
    memcpy(pe->path, ph, phlen);
    pe->path[phlen]='\0';
    radix_tree_insert(&pt->de_path, ino, pe);
    */

    mntput(vfsmnt);
    
END:
	NOVA_END_TIMING(getpath_t, getpath_time);
    //print_time(st);
    //nova_dbg("%s", __func__);
    return 0;
}

/* find currect zone
 * ph record file ful name
 * 反向查找
 * 可以用多线程*/
static inline struct dzt_entry_info *find_dzt(struct super_block *sb, const char *phstr, char *phs)
{
    struct dzt_entry_info *dzt_ei;
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dzt_manager *dzt_m = sbi->dzt_m_info;
    u64 hashname;
    u64 phlen, tlen;
    char *tem;
    timing_t st;

    //nova_dbg("%s start %s",__func__,phstr);
    //getrawmonotonic(&st); 
    tlen = strlen(phstr);
    memcpy(phs, phstr, tlen);
    phs[tlen]='\0';

    /*debug
    do{
        tem = strrchr(phs, '/');
        phlen = tlen -strlen(tem);
        tlen = phlen;
        //bug
        if(phlen==0){
            break;
        }
        memcpy(phs,phstr,tlen);
        phs[tlen]='\0';
        hashname = BKDRHash(phs,tlen);
        //nova_dbg("%s:par path is %s",__func__, phs);
        dzt_ei = radix_tree_lookup(&dzt_m->dzt_root, hashname);
        if(dzt_ei){
            return dzt_ei;
        }
    }while(1);
    */
    /*root dir*/
    memcpy(phs, "/", 1);
    phs[1]='\0';
    hashname = BKDRHash(phs ,1);
    dzt_ei = radix_tree_lookup(&dzt_m->dzt_root,hashname);
    if(!dzt_ei){
        //nova_dbg("dafs not find zone ei");
        BUG();
        return ERR_PTR(-EINVAL);
    }

    //print_time(st);
    //nova_dbg("%s", __func__);
    //nova_dbg("dafs finish finding dzt:%d, zone addr 0x%llu",dzt_ei->dzt_eno, dzt_ei->dz_addr);
    return dzt_ei;
}

void dafs_rebuild_dir_time_and_size(struct super_block *sb,
	struct nova_inode *pi, int link_change, struct inode *dir)
{
    unsigned short links_count;

	if (!pi)
		return;

	pi->i_ctime = CURRENT_TIME_SEC.tv_sec;
	pi->i_mtime = CURRENT_TIME_SEC.tv_sec;
	pi->i_size = DAFS_DEF_DENTRY_SIZE;
    links_count = cpu_to_le16(dir->i_nlink);
    //nova_dbg("%s dir links is %d", __func__, links_count);
	if (links_count == 0 && link_change == -1)
		links_count = 0;
	else
		links_count += link_change;
	pi->i_links_count = links_count;
}

/*record dir operation in logs*/
void record_dir_log(struct super_block *sb, struct dentry *src, struct dentry *des, int type)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dafs_dzt_block *dzt_blk;
    struct dzt_ptr *dzt_p;
    struct direntry_log *dlog;
    struct dzt_entry_info *dzt_ei, *src_ei;
    u64 sdz_hn, des_dz_hn=0;
    u64 src_hn, des_hn=0, phlen, flen;
    u32 bitpos = DAFS_DZT_ENTRIES_IN_BLOCK;
    char ph_f[DAFS_PATH_LEN], ph_dzt[DAFS_PATH_LEN], ph_name[DAFS_PATH_LEN], ph_fn[DAFS_PATH_LEN];
    char *phname = ph_name, *src_pn = ph_f, *ph = ph_fn, *phn = ph_dzt;
    //char *src_pn, *ph;
    int cpu;
    struct ptr_pair *pair;
    u32 i;

    //nova_dbg("record dir log");
//debug
	cpu = smp_processor_id();
	pair = nova_get_journal_pointers(sb, cpu);
    //nova_dbg("journal tail %llu, with head %llu", le64_to_cpu(pair->journal_tail), le64_to_cpu(pair->journal_head));
    get_dentry_path(src, src_pn, src->d_inode->i_ino);
    /*phname = sbi->ph_name;
    phn = sbi->ph_dzt;
    for(i=0;i++;i<DAFS_PATH_LEN){
        sbi->ph_dzt[i]='\0';
    }
    for(i=0;i++;i<DAFS_PATH_LEN){
        sbi->ph_name[i]='\0';
    }*/

    //phname = kzalloc(sizeof(char)*(strlen(src_pn)+1), GFP_KERNEL);
    //phn = kzalloc(sizeof(char)*(strlen(src_pn)+1), GFP_KERNEL);
    src_ei = find_dzt(sb, src_pn, phn);
    phlen = strlen(phn);
    if(phlen==1){
        flen = strlen(src_pn);
        memcpy(phname, src_pn, flen);
        phname[flen]='\0';
    } else {
        flen = strlen(src_pn)-phlen;
        memcpy(phname, src_pn+phlen, flen);
        phname[flen]='\0';
    }
    src_hn = BKDRHash(phname, flen);
    sdz_hn = src_ei->hash_name;

	pair = nova_get_journal_pointers(sb, cpu);
    //nova_dbg("journal tail %llu, with head %llu", le64_to_cpu(pair->journal_tail), le64_to_cpu(pair->journal_head));
    if(!des) {
        des_hn = 0;
        des_dz_hn = 0;
    }
    else {
        get_dentry_path(des, ph, des->d_inode->i_ino);
        //memcpy(phname, ph, strlen(ph)+1);
        dzt_ei = find_dzt(sb, ph, phn);
        des_dz_hn = dzt_ei->hash_name;
        phlen = strlen(phn);
        if(phlen==1){
            flen = strlen(ph);
            memcpy(phname, ph, flen);
            phname[flen]='\0';
        } else {
            flen = strlen(ph)-phlen;
            memcpy(phname, ph+phlen, flen);
            phname[flen]='\0';
        }
        des_hn = BKDRHash(phname, flen);
        //kfree(ph);
    }

	pair = nova_get_journal_pointers(sb, cpu);
    //nova_dbg("journal tail %llu, with head %llu", le64_to_cpu(pair->journal_tail), le64_to_cpu(pair->journal_head));
    dzt_blk = dafs_get_dzt_block(sb);
    make_dzt_ptr(sb, &dzt_p);
    dlog = (struct direntry_log*)&dzt_blk->dzt_entry[DAFS_DZT_ENTRIES_IN_BLOCK];
    test_and_set_bit_le(bitpos, (void *)dzt_p->bitmap);

	pair = nova_get_journal_pointers(sb, cpu);
    //nova_dbg("journal tail %llu, with head %llu", le64_to_cpu(pair->journal_tail), le64_to_cpu(pair->journal_head));
    /*not decided*/
    dlog->type_d = type;
    dlog->src_dz_hn = cpu_to_le64(sdz_hn);
    dlog->src_hashname = cpu_to_le64(src_hn);
    dlog->des_dz_hn = cpu_to_le64(des_dz_hn);
    dlog->des_hashname = cpu_to_le64(des_hn);

    //kfree(src_pn);
    //kfree(phname);
    //kfree(phn);
    kfree(dzt_p);
    //nova_dbg("%s end record log",__func__);
}

/*delete dir operation log*/
void delete_dir_log(struct super_block *sb)
{
    //struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dzt_ptr *dzt_p;
    u32 bitpos = DAFS_DZT_ENTRIES_IN_BLOCK;

    //nova_dbg("%s start",__func__);
    make_dzt_ptr(sb, &dzt_p);
    test_and_clear_bit_le(bitpos, (void *)dzt_p->bitmap);
    kfree(dzt_p);
}

/*
* extend dentry name
* nameflag = 0 => name
* nameflag = 1==> fulname*/
void ext_de_name(struct super_block *sb, struct dzt_entry_info *ei, struct dafs_zone_entry *ze,\
        struct zone_ptr *p, int cur_pos, int name_len, const char *name, int name_flag)

{
    struct dafs_dentry *de;
    struct name_ext *de_ext, *tem_ext;
    //struct dzt_entry_info *ei;
    u64 ext_len;
    u32 bitpos, ext_pos, ext_num;
  
    //nova_dbg("%s start, dentry pos %d",__func__, cur_pos);
    //BUG_ON(ze==NULL);
    de = &ze->dentry[cur_pos];
    cur_pos ++;
    if(name_flag == 0){
        /*judge name len && set dentry name*/
        if(name_len <= LARGE_NAME_LEN){
            //ext_num = 1;
            //de->ext_flag = 0;
            ext_pos = find_invalid_id(sb, ei, p, cur_pos);
            de_ext = (struct name_ext *)&ze->dentry[ext_pos];
            de->next = de_ext;
            memcpy(de_ext->name, name, name_len);
            de_ext->name[name_len]='\0';
            de_ext->ext_pos = cpu_to_le32(ext_pos);
            de_ext->next = NULL;
            bitpos = ext_pos*2+1;
            test_and_set_bit_le(bitpos, (void *)p->statemap);
            nova_flush_buffer(de_ext, DAFS_DEF_DENTRY_SIZE, 0);
        } else {
            //de->ext_flag = 1;
            ext_len = name_len - LARGE_NAME_LEN -1;
            ext_pos = find_invalid_id(sb, ei, p, cur_pos);
            de_ext = (struct name_ext *)&ze->dentry[ext_pos];
            memcpy(de_ext->name, name, LARGE_NAME_LEN);
            de_ext->name[LARGE_NAME_LEN]='\0';
            de_ext->ext_pos = cpu_to_le32(ext_pos);
            bitpos = ext_pos*2+1;
            test_and_set_bit_le(bitpos, (void *)p->statemap);

            //de_ext->name[name_len]="/0";
            /*at most 2 extend dentry*/
            ext_pos = find_invalid_id(sb, ei, p, ext_pos);
            //de_ext->next = cpu_to_le64(ext_pos);
            tem_ext = (struct name_ext *)&ze->dentry[ext_pos];
            de_ext->next = tem_ext;
            memcpy(tem_ext->name, name + LARGE_NAME_LEN, ext_len);
            tem_ext->name[ext_len]='\0';
            tem_ext->next = NULL;
            tem_ext->ext_pos = cpu_to_le32(ext_pos);
            bitpos = ext_pos *2 +1;
            test_and_set_bit_le(bitpos,(void *)p->statemap);
            nova_flush_buffer(de_ext, DAFS_DEF_DENTRY_SIZE, 0);
            nova_flush_buffer(tem_ext, DAFS_DEF_DENTRY_SIZE, 0);
        }
    } else {
        ext_pos = find_invalid_id(sb, ei, p, cur_pos);
        de_ext = (struct name_ext *)&ze->dentry[ext_pos];
        de->ful_name.fn_ext = de_ext;

        if(name_len <= (LARGE_NAME_LEN)){
            memcpy(de_ext->name, name, name_len);
            de_ext->name[name_len]='\0';
            de_ext->ext_pos = cpu_to_le32(ext_pos);
            de_ext->next = NULL;
            bitpos = ext_pos *2+1;
            test_and_set_bit_le(bitpos, (void *)p->statemap);
        }else {
            ext_len = 0;
            ext_num = name_len/(LARGE_NAME_LEN);
            ext_num++;
            //ext_pos = cur_pos;
            //if(name_len%(LARGE_NAME_LEN)>ext_num)
                //ext_num++;
            memcpy(de_ext->name, name, LARGE_NAME_LEN);
            de_ext->name[LARGE_NAME_LEN]='\0';
            de_ext->ext_pos = cpu_to_le32(ext_pos);
            bitpos = ext_pos *2+1;
            test_and_set_bit_le(bitpos, (void *)p->statemap);
            ext_num--;
            ext_len += LARGE_NAME_LEN;
            name_len -= LARGE_NAME_LEN;
            while(ext_num > 1) {
                ext_pos =  find_invalid_id(sb, ei, p, ext_pos);
                tem_ext = (struct name_ext *)&ze->dentry[ext_pos];
                de_ext->next = tem_ext;
                memcpy(tem_ext->name, name + ext_len, LARGE_NAME_LEN);
                tem_ext->name[LARGE_NAME_LEN]='\0';
                tem_ext->ext_pos = cpu_to_le32(ext_pos);
                bitpos = ext_pos *2+1;
                test_and_set_bit_le(bitpos, (void *)p->statemap);
                de_ext = tem_ext;
                name_len -= LARGE_NAME_LEN;
                ext_len += LARGE_NAME_LEN;
                ext_num--;
            }
            ext_pos = find_invalid_id(sb, ei, p, ext_pos);
            tem_ext = (struct name_ext *)&ze->dentry[ext_pos];
            de_ext->next = tem_ext;
            memcpy(tem_ext->name, name+ext_len, name_len);
            tem_ext->ext_pos = cpu_to_le32(ext_pos);
            tem_ext->name[name_len] = '\0';
            tem_ext->next = NULL;
            bitpos = ext_pos *2+1;
            test_and_set_bit_le(bitpos, (void *)p->statemap);
        }
    }
    //nova_dbg("%s end",__func__);
}

/*get ext name
* fulname & name*/
void get_ext_name(struct name_ext *de_ext, char *name)
{
    struct name_ext *tem_ext;
    unsigned short len;
    char tem_f[DAFS_PATH_LEN];
    char *tem = tem_f;

    tem_ext = de_ext;
    do{
        len =strlen(tem_ext->name);
        memcpy(tem, tem_ext->name, len);
        tem[len]='\0';
        strcat(name, tem);
        tem_ext = tem_ext->next; 
    }while(tem_ext);
    
    //strcat(name,"/0");
}

/*get dentry name
 * name_type 0 for name, 1 for fulname*/
void get_de_name(struct dafs_dentry *de, struct dafs_zone_entry *ze, char *name, int name_type)
{
    struct dafs_dentry *par_de;
    unsigned short nlen;
    u64 flen;
    char tem_f[DAFS_PATH_LEN];
    char *tem = tem_f;
    u32 par_pos;

    nlen = de->name_len;
    flen = de->fname_len;

    if(name_type == 0){
        if(de->ext_flag==1){
            get_ext_name(de->next, name);
        } else {
            memcpy(name, de->name, nlen);
            name[nlen]='\0';
        }
    } else {
        if(de->isr_sf==1){
            if(de->ext_flag==0){
                memcpy(name, de->ful_name.f_name, flen);
                name[flen] = '\0';
            } else {
                get_ext_name(de->ful_name.fn_ext, name);
            }
        } else {
            if(de->file_type==NORMAL_FILE){
                /*get name*/
                tem[0]='\0';
                if(de->ext_flag==1){
                    get_ext_name(de->next, tem);
                } else {
                    memcpy(tem, de->name, nlen);
                    tem[nlen]='\0';
                }

                /*get par fulname*/
                par_pos = le32_to_cpu(de->par_pos);
                par_de = &ze->dentry[par_pos];
                get_de_name(par_de, ze, name, 1);

                strcat(name, "/");
                strcat(name, tem);
            } else {
                if(de->ext_flag == 0){
                    memcpy(name, de->ful_name.f_name, flen);
                    name[flen]='\0';
                } else {
                    get_ext_name(de->ful_name.fn_ext, name);
                }
            }
        }
    }

}

/*clear ext bit*/
void clear_ext(struct zone_ptr *p, struct name_ext *de_ext)
{
    u32 ext_pos, bitpos;
    
    //nova_dbg("%s start",__func__);
    ext_pos = le32_to_cpu(de_ext->ext_pos);
    bitpos = ext_pos*2+1;
    test_and_clear_bit_le(bitpos, (void *)p->statemap);
    if(de_ext->next)
        clear_ext(p, de_ext->next);
}

/*test and delete ext name entry*/
int delete_ext(struct zone_ptr *p, struct dafs_dentry *de)
{
    //u32 ext_pos, bitpos;
    unsigned short ext_flag;
    //struct name_ext *de_ext;

    //nova_dbg("%s start %s",__func__, de->name);
    ext_flag = le16_to_cpu(de->ext_flag);
    switch(ext_flag) {
    case 0:
        goto OUT;
    case 1:
        clear_ext(p, de->next);
        clear_ext(p, de->ful_name.fn_ext);
        break;
    case 2:
        clear_ext(p, de->ful_name.fn_ext);
        break;
    }
OUT:
    //nova_dbg("%s end",__func__);
    return 0;
}

/*dafs add dentry in the zone
* and initialize direntry without name*/
int dafs_add_dentry( struct dentry *dentry, u64 ino, int link_change, int file_type, umode_t mode)
{
    struct inode *dir = dentry->d_parent->d_inode;
    struct super_block *sb = dir->i_sb;
    struct nova_inode *pidir;
    struct nova_sb_info *sbi = NOVA_SB(sb);
    unsigned short  namelen = dentry->d_name.len;
    struct dzt_entry_info *dzt_ei;
    struct dafs_zone_entry *dafs_ze;
    struct zone_ptr *zone_p;
    struct dafs_dentry *dafs_de, *par_de;
    struct dir_info *par_dir;
    struct file_p *tem_sf;
    //struct name_ext *de_ext;
    char ph_f[DAFS_PATH_LEN], ph_dzt[DAFS_PATH_LEN], ph_name[DAFS_PATH_LEN], tem_f[DAFS_PATH_LEN];
    char *phname = ph_name, *ph = ph_f, *phn = ph_dzt;
    //char *phf;
    char *tem = tem_f, *te;
    unsigned long phlen, temlen, flen, tm_len;
    unsigned short links_count;
    u32 bitpos = 0, cur_pos = 0, par_pos, tem_pos, i;
    int ret = 0;
    u64 hashname, ht_addr, par_hn;
    struct path_entry *pe;
    struct path_tree *pt = sbi->pt;
    struct dzt_manager *dzt_m = sbi->dzt_m_info;
    struct dir_info *new_dir;
    u64 p_ino = dir->i_ino;
    timing_t add_dentry_time;

    
	/*nova_dbg_verbose("%s: dir %lu new inode %llu\n",
				__func__, dir->i_ino, ino);
	nova_dbg_verbose("%s: %s %d\n", __func__, name, namelen);*/

	NOVA_START_TIMING(add_dentry_t, add_dentry_time);
	if (namelen == 0)
		return -EINVAL;
   // nova_dbg("%s:dafs start to add dentry",__func__);
    //get_dentry_path(dentry, ph, ino);
    if(!ino)
        return -EINVAL;
    ph[0]= '\0';
    pe = radix_tree_lookup(&pt->de_path, p_ino);
    if(!pe)
        return -EINVAL;
    strcat(ph, pe->path);
    if(strcmp(ph, "/"))
        strcat(ph, "/");
    if(strcmp(dentry->d_name.name, "/"))
        strcat(ph, dentry->d_name.name);
    flen = strlen(ph);
    
    memcpy(phn, ph, flen);
    phn[flen]='\0';
    /*
    do{
        te = strrchr(phn, '/');
        phlen = flen -strlen(tem);
        flen = phlen;
        if(phlen==0)
            break;
        memcpy(phn, ph, flen);
        phn[flen]='\0';
        hashname = BKDRHash(phn, flen);
        dzt_ei = radix_tree_lookup(&dzt_m->dzt_root, hashname);
        if(dzt_ei)
            goto NEXT;
    }while(1);*/
    memcpy(phn, "/", 1);
    phn[1] = '\0';
    hashname = BKDRHash(phn, 1);
    dzt_ei = radix_tree_lookup(&dzt_m->dzt_root, hashname);

    //flen = strlen(ph);

    //dzt_ei = find_dzt(sb, ph, phn);
    phlen = strlen(phn); 
    if(phlen==1){
        flen = strlen(ph);
        memcpy(phname, ph, flen);
        phname[flen]='\0';
    } else {
        flen = strlen(ph)-phlen;
        memcpy(phname, ph+phlen, flen);
        phname[flen]='\0';
    }

    hashname = BKDRHash(phname, flen);

NEXT:
    pe = kzalloc(sizeof(struct path_entry), GFP_KERNEL);
    pe->ino = ino;
    pe->len = flen;
    pe->hn = hashname;
    pe->ei = dzt_ei;
    memcpy(pe->path, phname, flen);
    pe->path[flen] = '\0';

    dafs_ze = (struct dafs_zone_entry *)nova_get_block(sb,dzt_ei->dz_addr);
    
    zone_p = dzt_ei->ztr;
    //make_zone_ptr(&zone_p, dafs_ze);
    
    while(cur_pos<NR_DENTRY_IN_ZONE){
        if(test_bit_le(bitpos, (void *)zone_p->statemap)||test_bit_le(bitpos+1, (void *)zone_p->statemap)){
            bitpos+=2;
            cur_pos++;
        }else{
            break;
        }
    }

    /*
    if(cur_pos==NR_DENTRY_IN_ZONE){
        BUG();
        dafs_split_zone(sb, NULL, 0, NEGTIVE_SPLIT);
    }*/

    phlen = strlen(phn); 
    if(phlen==1){
        //flen = strlen(ph);
        memcpy(phname, ph, flen);
        phname[flen]='\0';
    } else {
        flen = strlen(ph)-phlen;
        memcpy(phname, ph+phlen, flen);
        phname[flen]='\0';
    }

    //nova_dbg("%s phname %s",__func__, phname);
    pidir = nova_get_inode(sb, dir);
    dir->i_mtime = dir->i_ctime = CURRENT_TIME_SEC;
    dir->i_blocks = pidir->i_blocks;

    /*get dentry on nvm*/
    dafs_de = &dafs_ze->dentry[cur_pos];
    tem_pos = cur_pos;
    dafs_de->entry_type = DAFS_DIR_ENTRY;
    dafs_de->name_len = dentry->d_name.len;
    dafs_de->mode = cpu_to_le16(mode);
    //dafs_de->file_type = NORMAL_DIRECTORY;       

    links_count = cpu_to_le16(dir->i_nlink);
	if (links_count == 0 && link_change == -1)
		links_count = 0;
	else
		links_count += link_change;
	dafs_de->links_count = cpu_to_le16(links_count);
    dafs_de->mtime = cpu_to_le32(dir->i_mtime.tv_sec);
    dafs_de->ino = cpu_to_le64(ino);
    //dafs_de->size = cpu_to_le64(dir->i_size);

    /*make valid*/
    bitpos++;
    test_and_set_bit_le(bitpos, (void *)zone_p->statemap);
    /*judge name len && set dentry name*/
    if(dentry->d_name.len <= SMALL_NAME_LEN){
        //nova_dbg("dentry not need extension");
        dafs_de->ext_flag = 0;
        memcpy(dafs_de->name,dentry->d_name.name,dentry->d_name.len);
        //nova_dbg("dentry name is %s", dafs_de->name);
        dafs_de->name[dentry->d_name.len] = '\0'; 

    } else {
        //nova_dbg("%s dentry need extend name entry",__func__);
        dafs_de->ext_flag = 1;
        ext_de_name(sb, dzt_ei, dafs_ze, zone_p, tem_pos, dentry->d_name.len, dentry->d_name.name, 0);
    }

    dafs_de->fname_len = cpu_to_le64(flen);
    /*set fulname
    * use temlen to find par de*/
    temlen = flen - dentry->d_name.len;
    tm_len = temlen;
    if(temlen ==1){
        dafs_de->isr_sf = 1;
        //nova_dbg("dentry is root subfile");
        par_pos =0;
        if(dafs_de->ext_flag==0){
            //re_len = SMALL_NAME_LEN - dentry->d_name.len;
            if(flen<SMALL_NAME_LEN){
                memcpy(dafs_de->ful_name.f_name, phname, flen);
                dafs_de->ful_name.f_name[flen]= '\0';
            } else {
                //nova_dbg("%s ful name %s", __func__, phname);
                BUG();
                dafs_de->ext_flag = 2;
                ext_de_name(sb ,dzt_ei, dafs_ze, zone_p, tem_pos, flen, phname, 1);
            }
        } else{
            ext_de_name(sb, dzt_ei, dafs_ze, zone_p, tem_pos,flen, phname, 1);
        }
        dafs_de->par_pos = cpu_to_le32(par_pos);
    } else {
        /*get par de pos*/
        tem[0]='\0';
        temlen--;
        memcpy(tem, phname, temlen);
        tem[temlen]='\0';
        par_hn = BKDRHash(tem, temlen);
        
        //nova_dbg("%s par name %s",__func__,tem);
        dafs_de->isr_sf = 0;
        if(file_type == 1){
           if(dafs_de->ext_flag==0){
                if(flen<=SMALL_NAME_LEN){
                    //nova_dbg("dafs not need extend fulname");
                    memcpy(dafs_de->ful_name.f_name, phname, flen);
                    dafs_de->ful_name.f_name[flen]='\0';
                } else {
                    //nova_dbg("%s extend ful name %s ino %llu", __func__, phname, ino);
                    dafs_de->ext_flag = 2;
                    ext_de_name(sb, dzt_ei, dafs_ze, zone_p, tem_pos, flen, phname, 1);
                }
            } else {
                ext_de_name(sb, dzt_ei, dafs_ze, zone_p, tem_pos, flen, phname, 1);
            }
        } else {
            dafs_de->ful_name.f_name[0]= '\0';
        }
        
        lookup_in_hashtable(sb, dzt_ei->ht_head, par_hn, 1, &par_pos);
        dafs_de->par_pos = cpu_to_le32(par_pos);
    }

    /*debug*/
    par_de = &dafs_ze->dentry[par_pos];
 
    ht_addr = dzt_ei->ht_head;
    ret = record_pos_htable(sb, ht_addr, hashname, tem_pos, 1);
    //nova_dbg("%s hash value is %llu, name is %s",__func__,hashname, phname);
    if(tm_len>1 || dzt_ei->dzt_eno==0){
        if(par_pos==0){
            par_hn = BKDRHash("/",1);
        } else {
            par_de = &dafs_ze->dentry[par_pos];
            par_hn = le64_to_cpu(par_de->hname);
        }
        par_dir = radix_tree_lookup(&dzt_ei->dir_tree, par_hn);
        if(!par_dir){
            BUG();
            goto OUT;
	
        }
        par_dir->sub_num++;
        tem_sf = kzalloc(sizeof(struct file_p), GFP_KERNEL);
        tem_sf->pos = tem_pos;
        list_add_tail(&tem_sf->list, &par_dir->sub_file);
    }

    dafs_de->hname = cpu_to_le64(hashname);
    /*add dir info if dentry is dir*/
    if(file_type==1){
        dafs_de->file_type = NORMAL_DIRECTORY;
        new_dir = add_dir_info(dzt_ei, hashname, tem_pos);
        pe->d_f = new_dir;
        radix_tree_insert(&pt->de_path, ino, pe);
        //dafs_append_dir_init_entries(sb, tem_pos, dzt_ei, ino, dir->i_ino, phname);
    } else {
        dafs_de->file_type = NORMAL_FILE;
        radix_tree_insert(&pt->de_path, ino, pe);
    }

    // nova_flush_buffer(dafs_de, DAFS_DEF_DENTRY_SIZE, 0);

OUT:
    NOVA_END_TIMING(add_dentry_t, add_dentry_time);

    //kfree(zone_p);

    //nova_dbg("%s: finish, ino %llu, parent name %s",
    //     __func__, dafs_de->ino, dentry->d_parent->d_name.name);
    return ret;
}

ino_t dafs_find_ino(struct super_block *sb, const struct dentry *dentry)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct path_tree *pt = sbi->pt;
    struct path_entry *pe = NULL;
    struct dafs_dentry *direntry=NULL;
    struct dzt_entry_info *dzt_ei;
    struct dafs_zone_entry *dafs_ze;
    struct dentry *p_dentry=dentry->d_parent;
    char ph_f[DAFS_PATH_LEN], ph_name[DAFS_PATH_LEN], ph_dzt[DAFS_PATH_LEN];
    char *ph = ph_f, *phname = ph_name, *phn = ph_dzt;
    u64 flen, phlen, ht_addr, ph_hash;
    u32 de_pos;
    ino_t ino = 0, de_id = 0;
    int ret = 0;

    ph[0]='\0';
    if(dentry->d_inode)
        de_id = dentry->d_inode->i_ino;
    if(de_id){
        pe = radix_tree_lookup(&pt->de_path, de_id);
        ino = pe->ino;
        return ino;
    }

    ret = find_dentry_path(p_dentry, ph, p_dentry->d_inode->i_ino);
    if(ret)
        return ino;
    strcat(ph, dentry->d_name.name);
    flen = strlen(ph);
    dzt_ei = find_dzt(sb, ph, phn);
    dafs_ze = (struct dafs_zone_entry *)nova_get_block(sb, dzt_ei->dz_addr);

    phlen = strlen(phn);
    if(phlen==1){
        phname = ph;
        //print_time(ad);
        //nova_dbg("%s memcpy ", __func__);
        //memcpy(phname, ph, flen);
        //phname[flen]='\0';
    } else {
        flen = strlen(ph)-phlen;
        memcpy(phname, ph+phlen, flen);
        phname[flen]='\0';
    }
    ph_hash = BKDRHash(phname, flen);
    ht_addr = dzt_ei->ht_head;
    ret = lookup_in_hashtable(sb, ht_addr, ph_hash, 1, &de_pos);
    if(!ret){
        //nova_dbg("%s not found dentry in hash table value is %llu",__func__, ph_hash);
        return ino;
    }
    direntry = &dafs_ze->dentry[de_pos];
    ino = le64_to_cpu(direntry->ino);

    return ino;

}

/*look for dentry for each zone in its hash table
 * add read frequency
 * phn path name
 * ph strictly ful name
 * phname full name
 * update flag for whether update
 * ISREAD for readdir flag in get path*/
struct dafs_dentry *dafs_find_direntry(struct super_block *sb, const struct dentry *dentry, int update_flag,
        u32 ISREAD)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dafs_dentry *direntry=NULL;
    struct dzt_entry_info *dzt_ei;
    struct dafs_zone_entry *dafs_ze;
    struct dentry *p_dentry=dentry->d_parent;
    unsigned long phlen;
    u32 dzt_eno;
    u64 ph_hash, ht_addr, flen;
    //u64 tes_len;
    u32 de_pos, par_pos, i;
    char ph_f[DAFS_PATH_LEN], ph_dzt[DAFS_PATH_LEN], ph_name[DAFS_PATH_LEN];
    char *ph = ph_f, *dot=".", *pdot = "..";
    char *phname = ph_name, *phn = ph_dzt;
    int ret = 0;
    timing_t st, ad, ht, lt;

    //nova_dbg("%s:dafs start to find direntry",__func__);
   // getrawmonotonic(&st); 
    
    
    ret = find_dentry_path(p_dentry, ph, p_dentry->d_inode->i_ino);
    if(ret)
        goto OUT;
    strcat(ph, dentry->d_name.name);
    flen = strlen(ph);
    

    dzt_ei = find_dzt(sb, ph, phn);
    dafs_ze = (struct dafs_zone_entry *)nova_get_block(sb, dzt_ei->dz_addr);
    
    //getrawmonotonic(&ad); 
    phlen = strlen(phn);
    if(phlen==1){
        phname = ph;
        //print_time(ad);
        //nova_dbg("%s memcpy ", __func__);
        //memcpy(phname, ph, flen);
        //phname[flen]='\0';
    } else {
        flen = strlen(ph)-phlen;
        memcpy(phname, ph+phlen, flen);
        phname[flen]='\0';
    }
    //print_time(ad);
    //nova_dbg("%s memcpy ", __func__);
    
    //getrawmonotonic(&ht); 
    ph_hash = BKDRHash(phname, flen);
    ht_addr = dzt_ei->ht_head;
    //print_time(ht);
    //nova_dbg("%s hash function", __func__);

    //getrawmonotonic(&lt); 
    ret = lookup_in_hashtable(sb, ht_addr, ph_hash, 1, &de_pos);
    //print_time(lt);
    //nova_dbg("%s hash search", __func__);
    if(!ret){
        //nova_dbg("%s not found dentry in hash table value is %llu",__func__, ph_hash);
        goto OUT;
    }
    direntry = &dafs_ze->dentry[de_pos];
    
    //getrawmonotonic(&st); 
    if(update_flag){
        if(direntry->file_type == NORMAL_DIRECTORY)
            update_read_hot(dzt_ei, ph_hash);
        else if(direntry->isr_sf!=1){
            par_pos = le32_to_cpu(direntry->par_pos);
            ph_hash = le64_to_cpu(&dafs_ze->dentry[par_pos].hname);
            update_read_hot(dzt_ei, ph_hash);
        }
    }
    //print_time(st);
    //nova_dbg("%s", __func__);
OUT:
    //nova_dbg("%s:dafs finish find direntry",__func__);
    //print_time(st);
    //nova_dbg("%s", __func__);
    return direntry;
}

int dafs_rebuild_dir_inode_tree(struct super_block *sb, struct nova_inode *pi, u64 pi_addr,
	struct nova_inode_info_header *sih)
{
	//struct nova_dentry *entry = NULL;
	struct nova_setattr_logentry *attr_entry = NULL;
	struct nova_link_change_entry *link_change_entry = NULL;
	//struct nova_inode_log_page *curr_page;
	//u64 ino = pi->nova_ino;
	//unsigned short de_len;
	timing_t rebuild_time;
	void *addr;
	u64 curr_p;
	//u64 next;
	u8 type;
	//int ret;

	NOVA_START_TIMING(rebuild_dir_t, rebuild_time);

	sih->pi_addr = pi_addr;

	curr_p = pi->log_head;
    /*
	if (curr_p == 0) {
		nova_err(sb, "Dir %llu log is NULL!\n", ino);
		BUG();
	}*/

	//nova_dbg("Log head 0x%llx, tail 0x%llx\n",
	//			curr_p, pi->log_tail);

    if(!curr_p){
        sih->log_pages = 0;
        goto DIR_TYPE;
    }

	sih->log_pages = 1;
	//while (curr_p != pi->log_tail) {
		/*if (goto_next_page(sb, curr_p)) {
			sih->log_pages++;
			curr_p = next_log_page(sb, curr_p);
		}*/

        /*
		if (curr_p == 0) {
			nova_err(sb, "Dir %llu log is NULL!\n", ino);
			BUG();
		}*/

	addr = (void *)nova_get_block(sb, curr_p);
    //find bug
    type = nova_get_entry_type(addr);
	switch (type) {
		case SET_ATTR:
            BUG();
			attr_entry =(struct nova_setattr_logentry *)addr;
			nova_apply_setattr_entry(sb, pi, sih,attr_entry);
			sih->last_setattr = curr_p;
			curr_p += sizeof(struct nova_setattr_logentry);
				//continue;
                break;
		case LINK_CHANGE:
            BUG();
			link_change_entry = (struct nova_link_change_entry *)addr;
			dafs_apply_link_change_entry(pi, link_change_entry);
			sih->last_link_change = curr_p;
			curr_p += sizeof(struct nova_link_change_entry);
            break;
				//continue;
			//case DIR_LOG:
				//break;
		default:
            BUG();
			//nova_dbg_verbose("%s: unknown type %d, 0x%llx\n",
			//				__func__, type, curr_p);
				//NOVA_ASSERT(0);
	}
DIR_TYPE:
	sih->i_size = le64_to_cpu(pi->i_size);
	sih->i_mode = le64_to_cpu(pi->i_mode);
    nova_flush_buffer(pi, sizeof(struct nova_inode), 0);

    pi->i_blocks = sih->log_pages;

//	nova_print_dir_tree(sb, sih, ino);
    //dafs_rebuild_dir_time_and_size(sb, pi, entry);
	//nova_dbg("%s:dafs finish rebuild dir inode",__func__);
    NOVA_END_TIMING(rebuild_dir_t, rebuild_time);
    return 0;
}

/**递归删除dentry*/
static int __remove_direntry(struct super_block *sb, struct dafs_dentry *dafs_de,\
        struct dafs_zone_entry *dafs_ze, struct dzt_entry_info *dzt_ei, u32 de_pos)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dafs_dentry *pde, *sde;
    /*ei need deleting*/
    struct dzt_entry_info *ei;
    struct zone_ptr *z_p;
    struct dzt_ptr *dzt_p;
    struct dir_info *old_dir, *par_dir;
    struct list_head *this, *head, *next;
    struct file_p *tem_sf;
    struct dzt_manager *dzt_m = sbi->dzt_m_info;
    u32 dzt_rno;
    u32 bitpos, par_id=0, sub_id;
    //char *par_name, *tem;
    u64 hashname, d_hn, tail, par_hn, plen,ino;
    char pname_f[DAFS_PATH_LEN];
    char *pname = pname_f;
    int ret, isr_sf;
    //u8 hlevel = 1;

    /*get par dentry pos*/
    //nova_dbg("%s start",__func__);
    isr_sf = le64_to_cpu(dafs_de->isr_sf);
    
    if(isr_sf!=1){
        par_id = le64_to_cpu(dafs_de->par_pos);
        pde = &dafs_ze->dentry[par_id];
        par_hn = le64_to_cpu(pde->hname);

        /*delete pos in its pardir*/
        par_dir = radix_tree_lookup(&dzt_ei->dir_tree, par_hn);
        head = &par_dir->sub_file;
        list_for_each_safe(this, next, head) {
            tem_sf = list_entry(this, struct file_p, list);
            if(tem_sf->pos == de_pos){
                list_del(&tem_sf->list);
                kfree(tem_sf);
                par_dir->sub_num--;
                goto NEXT;
            }
        }
        //kfree(par_name);
    }else{
        par_id = le64_to_cpu(dafs_de->par_pos);
        pde = &dafs_ze->dentry[par_id];
        ino = le64_to_cpu(pde->ino);
        if(ino==NOVA_ROOT_INO || par_id!=0){
            par_hn = le64_to_cpu(pde->hname);
            par_dir = radix_tree_lookup(&dzt_ei->dir_tree, par_hn);
            head = &par_dir->sub_file;
            list_for_each_safe(this, next, head) {
                tem_sf = list_entry(this, struct file_p, list);
                if(tem_sf->pos == de_pos){
                    list_del(&tem_sf->list);
                    kfree(tem_sf);
                    par_dir->sub_num--;
                    //nova_dbg("%s par %s subfile num is %d",__func__,pde->name, par_dir->sub_num);
                    goto NEXT;
                }
            }
        }
    }
    head = next = this =NULL;

NEXT:    
    //strcat(tem, dafs_ze->root_path);
    if(dafs_de->file_type == ROOT_DIRECTORY){

        /*delete dir*/
        bitpos = de_pos * 2;

        plen = le64_to_cpu(dafs_de->fname_len);
        //pname = kzalloc(sizeof(char)*(plen+1), GFP_KERNEL);
        pname[0]='\0';
        get_de_name(dafs_de, dafs_ze, pname, 1);
        d_hn = BKDRHash(pname, plen);
        
        make_zone_ptr(&z_p, dafs_ze);
        test_and_clear_bit_le(bitpos, (void *)z_p->statemap);
	    bitpos++;
        test_and_clear_bit_le(bitpos, (void *)z_p->statemap);
        ret = make_invalid_htable(sb, dzt_ei->ht_head, d_hn,  1);
        delete_ext(z_p, dafs_de);
        /*free dir_entry*/
        delete_dir_info(dzt_ei, d_hn);
        
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
         * free ei*/
        hashname = le64_to_cpu(dafs_de->dzt_hn);
        ei = radix_tree_lookup(&dzt_m->dzt_root, hashname);
        dzt_rno = ei->dzt_eno;
        tail = le64_to_cpu(ei->ht_head);
        free_htable(sb, tail, 1);
        make_dzt_ptr(sb, &dzt_p);
        test_and_clear_bit_le(dzt_rno, (void *)dzt_p->bitmap);
        //delete_rf_tree(ei);
        dafs_free_zone_blocks(sb, ei, ei->dz_addr >> PAGE_SHIFT, 1);
        kfree(ei);
        kfree(z_p);
        kfree(dzt_p);
    }else if(dafs_de->file_type == NORMAL_DIRECTORY){

        /* delete sub files*/
        //nova_dbg("%s remove dir",__func__);
        d_hn = le64_to_cpu(dafs_de->hname);
        old_dir = radix_tree_lookup(&dzt_ei->dir_tree, d_hn);
        if(!old_dir){
            //nova_dbg("%s not find dir_info",__func__);
            return -EINVAL;
        }
        head = &old_dir->sub_file;
        list_for_each_safe(this, next, head) {
            tem_sf = list_entry(this, struct file_p, list);
            sub_id = tem_sf->pos;
            sde= &dafs_ze->dentry[sub_id];
            //nova_dbg("%s start to delete de %s",__func__, sde->name);
            ret = __remove_direntry(sb, sde, dafs_ze, dzt_ei, sub_id);
            //list_del(&tem_sf->list); done by recursive
            //old_dir->sub_num--;
            //kfree(tem_sf);
        }

        /*delete dir itself*/
        bitpos = de_pos * 2;
        
        make_zone_ptr(&z_p, dafs_ze);
        test_and_clear_bit_le(bitpos, (void *)z_p->statemap);
	    bitpos++;
        test_and_clear_bit_le(bitpos, (void *)z_p->statemap);
        ret = make_invalid_htable(sb, dzt_ei->ht_head, d_hn, 1);
        delete_ext(z_p, dafs_de);

        if(!ret)
            return -EINVAL;
        
        /*free dir_info_entry*/
        old_dir = radix_tree_lookup(&dzt_ei->dir_tree, d_hn);
        kfree(old_dir);

        if(!ret)
            return -EINVAL;
    
        kfree(z_p);
    }else{
        d_hn = le64_to_cpu(dafs_de->hname);
        
        /*delete dir itself*/
        bitpos = de_pos * 2;
        
        make_zone_ptr(&z_p, dafs_ze);
        test_and_clear_bit_le(bitpos, (void *)z_p->statemap);
	    bitpos++;
        test_and_clear_bit_le(bitpos, (void *)z_p->statemap);
        ret = make_invalid_htable(sb, dzt_ei->ht_head, d_hn, 1);
        delete_ext(z_p, dafs_de);
        /*free rf_entry*/
        //delete_rf_entry(dzt_ei, d_hn);
        if(!ret){
            //nova_dbg("%s make invalid fail",__func__);
            return -EINVAL;
        }
        /*delete in par de*/

        kfree(z_p);
    }
    //nova_dbg("%s end",__func__);
    return 0;
}


/* removes a directory entry pointing to the inode. assumes the inode has
 * already been logged for consistency
 * 只是先将对应的状态表显示无效
 * 检查是不是根节点
 * 并不含有link的变化
 * 1 not rm successful
 */
int dafs_rm_dir(struct dentry *dentry, int link_change)
{
    struct inode *dir = dentry->d_parent->d_inode;
    struct super_block *sb = dir->i_sb;
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dafs_dentry *dafs_de, *par_de,*sub_de;
    struct dzt_entry_info *dzt_ei, *sub_ei;
    struct dafs_zone_entry *dafs_ze;
    struct zone_ptr *z_p;
    struct dzt_manager *dzt_m = sbi->dzt_m_info;
    struct dir_info *rm_dir, *par_dir;
    struct file_p *rm_sf;
    struct list_head *head, *next, *this;
    struct path_tree *pt = sbi->pt;
    struct path_entry *pe;
    u32 phlen, flen;
    u32 ret = 0;
    u32 dzt_eno, i;
    u32 de_pos, sub_pos, par_pos;
    u32 bitpos;
    unsigned short links_count;
    u64 ph_hash, ei_hash, par_hash, sub_hash;
    char ph_f[DAFS_PATH_LEN], ph_dzt[DAFS_PATH_LEN], ph_name[DAFS_PATH_LEN];
    char *phname=ph_name, *ph=ph_f, *phn=ph_dzt;
    //char *ph;
	timing_t remove_dentry_time;

//	NOVA_START_TIMING(remove_dentry_t, remove_dentry_time);

	/*if (!dentry->d_name.len){
        //nova_dbg("%s name is null %s",__func__,dentry->d_name.name);
		return -EINVAL;
    }*/


//	dir->i_mtime = dir->i_ctime = CURRENT_TIME_SEC;
 
    //nova_dbg("%s start",__func__);
    //ret = find_dentry_path(dentry,ph,dentry->d_inode->i_ino);
    pe = radix_tree_delete(&pt->de_path, dentry->d_inode->i_ino);
    /*not exist*/
    if(!pe)
        return 1;
    dzt_ei = pe->ei;
    ph_hash = pe->hn;
    rm_dir = pe->d_f;
    /*not empty*/
    if(rm_dir->sub_num>0)
        return 1;
    //kfree(pe);
    /*if(ret)
        return -EINVAL;
    */
    //flen= strlen(ph);

    //nova_dbg("%s start dentry %s",__func__,pe->path);
    //dzt_ei = find_dzt(sb, ph, phn);
    dafs_ze = (struct dafs_zone_entry *)nova_get_block(sb, dzt_ei->dz_addr);
    /*phlen = strlen(phn);

    if(phlen==1){
        memcpy(phname, ph, flen);
        phname[flen]='\0';
    } else {
        flen = strlen(ph)-phlen;
        memcpy(phname, ph+phlen, flen);
        phname[flen]='\0';
    }

    //dzt_eno = dzt_ei->dzt_eno;
    //nova_dbg("%s start hash name is %s ",__func__, phname);
    ph_hash = BKDRHash(phname, flen);*/

    /*lookup in hash table*/
    ret = lookup_in_hashtable(sb, dzt_ei->ht_head, ph_hash, 1, &de_pos);
    if(!ret){
        //nova_dbg("%s name is %llu ",__func__, ph_hash);
        return -EINVAL;
    }
    dafs_de = &dafs_ze->dentry[de_pos];
    //nova_dbg("%s get rm pos %d",__func__,de_pos);

    /*if(dafs_de->file_type == ROOT_DIRECTORY) {
        nova_dbg("%s dentry is root zone",__func__);
        ei_hash = le64_to_cpu(dafs_de->dzt_hn);
        sub_ei = radix_tree_lookup(&dzt_m->dzt_root, ei_hash);
        free_zone_area(sb, sub_ei);
    }*/

	/*links_count = cpu_to_le16(dir->i_nlink);
	if (links_count == 0 && link_change == -1)
		links_count = 0;
	else
		links_count += link_change;
	dafs_de->links_count = cpu_to_le16(links_count);
*/
    //nova_dbg("%s dafs_de link is: %d",__func__, links_count);
    bitpos = de_pos * 2;
   
    /*remove from par*/
    par_pos = le32_to_cpu(dafs_de->par_pos);
    if(dir->i_ino == NOVA_ROOT_INO || par_pos!=0){
        par_de = &dafs_ze->dentry[par_pos];
        par_hash = le64_to_cpu(par_de->hname);
        par_dir = radix_tree_lookup(&dzt_ei->dir_tree, par_hash);
        //BUG_ON(par_dir==NULL);
        head = &par_dir->sub_file;
        
        list_for_each_safe(this, next, head) {
            rm_sf = list_entry(this, struct file_p, list);
            if(rm_sf->pos == de_pos){
                par_dir->sub_num--;
                list_del(&rm_sf->list);
                kfree(rm_sf);//debug
                goto CONT;
            }
        }
    } 

CONT:
    make_zone_ptr(&z_p, dafs_ze);
    test_and_clear_bit_le(bitpos, (void *)z_p->statemap);
	bitpos++;
    test_and_clear_bit_le(bitpos, (void *)z_p->statemap);
    make_invalid_htable(sb, dzt_ei->ht_head, ph_hash, 1);
    delete_ext(z_p, dafs_de);

    if(dafs_de->file_type == ROOT_DIRECTORY) {
        //nova_dbg("%s dentry is root zone",__func__);
        delete_dir_info(dzt_ei, ph_hash);
        ei_hash = le64_to_cpu(dafs_de->dzt_hn);
        sub_ei = radix_tree_lookup(&dzt_m->dzt_root, ei_hash);
        free_zone_area(sb, sub_ei);
        goto END;
    }
    /*make invalid sub file only for empty dir
     * free dir_tree*/
    //this = NULL;
    //next = NULL;
    rm_dir = radix_tree_delete(&dzt_ei->dir_tree, ph_hash);
    //BUG_ON(rm_dir==NULL);
    /*
    head = &rm_dir->sub_file;
    list_for_each_safe(this, next, head){
        //nova_dbg("%s list sub",__func__);
        rm_sf = list_entry(this, struct file_p, list);
        sub_pos = rm_sf->pos;
        bitpos = sub_pos*2;
        sub_de = &dafs_ze->dentry[sub_pos];
        sub_hash = le64_to_cpu(sub_de->hname);
        test_and_clear_bit_le(bitpos, (void *)z_p->statemap);
	    bitpos++;
        test_and_clear_bit_le(bitpos, (void *)z_p->statemap);
        make_invalid_htable(sb, dzt_ei->ht_head, sub_hash, 1);
        delete_ext(z_p, dafs_de);
        list_del(&rm_sf->list);
        kfree(rm_sf);
    }*/

    if(rm_dir)
        kfree(rm_dir);
    //tes_empty_zone(sb, z_p);

END:
    //kfree(phname);
    //kfree(ph);
    //kfree(phn);
    
    
  //  NOVA_END_TIMING(remove_dentry_t, remove_dentry_time);
    kfree(pe);//debug
    //kfree(z_p);
    //nova_dbg("%s end",__func__);
	return 0;
}

/*remove dir when use rename*/
int dafs_remove_dentry(struct dentry *dentry)
{
    struct inode *dir = dentry->d_parent->d_inode;
    struct super_block *sb = dir->i_sb;
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dafs_dentry *dafs_de;
    struct dzt_entry_info *dzt_ei;
    struct dafs_zone_entry *dafs_ze;
    //struct zone_ptr *z_p;
    //struct dzt_manager *dzt_m = sbi->dzt_m_info;
    struct path_tree *pt = sbi->pt;
    struct path_entry *pe;
    unsigned long phlen, flen;
    u32 dzt_eno, de_pos;
    //unsigned short links_count;
    u64 ph_hash;
    char ph_f[DAFS_PATH_LEN], ph_dzt[DAFS_PATH_LEN], ph_name[DAFS_PATH_LEN];
    char *phname=ph_name, *ph=ph_f, *phn=ph_dzt;
    //char *ph;
    int ret, i;
	timing_t remove_dentry_time;

    //nova_dbg("%s start %s",__func__,dentry->d_name.name);
	NOVA_START_TIMING(remove_dentry_t, remove_dentry_time);

	if (!dentry->d_name.len)
		return -EINVAL;


	dir->i_mtime = dir->i_ctime = CURRENT_TIME_SEC;

    /*直接rm direntry就可以
    * 先找到相应的dir*/    
    get_dentry_path(dentry,ph, dentry->d_inode->i_ino);
    
    //phname = kzalloc(sizeof(char)*(strlen(ph)+1), GFP_KERNEL);
    //phn = kzalloc(sizeof(char)*(strlen(ph)+1), GFP_KERNEL);
    //memcpy(phname, ph, strlen(ph));
    dzt_ei = find_dzt(sb, ph, phn);
    
    pe = radix_tree_delete(&pt->de_path, dentry->d_inode->i_ino);
    if(!pe)
        BUG();
    kfree(pe);
    dafs_ze = (struct dafs_zone_entry *)nova_get_block(sb, dzt_ei->dz_addr);
    phlen = strlen(phn);
    if(phlen==1){
        flen = strlen(ph);
        memcpy(phname, ph, flen);
        phname[flen]='\0';
    } else {
        flen = strlen(ph)-phlen;
        memcpy(phname, ph+phlen, flen);
        phname[flen]='\0';
    }

    dzt_eno = dzt_ei->dzt_eno;
    ph_hash = BKDRHash(phname, flen);

    /*lookup in hash table*/
    //nova_dbg("%s lookup for %s, hash value %llu",__func__,phname, ph_hash);
    ret = lookup_in_hashtable(sb, dzt_ei->ht_head, ph_hash, 1, &de_pos);
    if(!ret){
        //nova_dbg("not find in hashtable");
        return -EINVAL;
    }

    dafs_de = &dafs_ze->dentry[de_pos];
    /*if(dafs_de->file_type==NORMAL_FILE)
        nova_dbg("%s delete normal file ",__func__);*/
    /*
    de_addr = le64_to_cpu(&dafs_de);
    record_dir_log(sb, de_addr, 0, DIR_RMDIR);*/

    
    ret = __remove_direntry(sb, dafs_de, dafs_ze, dzt_ei, de_pos);

    if(ret){
        //nova_dbg("%s remove result is %d",__func__,ret);
        return ret;
    }
    //kfree(phname);
    //kfree(phn);
    //kfree(ph);
    
    
    NOVA_END_TIMING(remove_dentry_t, remove_dentry_time);
    //nova_dbg("%s end", __func__);
	return 0;
}

/*append . and .. entries*/
int dafs_append_dir_init_entries(struct super_block *sb, u32 par_pos, struct dzt_entry_info *dzt_ei,
                                 u64 self_ino, u64 parent_ino, const char *ful_name)
{
    //int allocated;
    //u64 new_block;
    //u64 curr_p;
    //u64 phhash;
    char *phn[DAFS_PATH_LEN];
    char *phn_f = phn;
    //unsigned long phlen;
    u32 bitpos;
    struct dafs_zone_entry *dafs_ze;
    //struct dzt_entry_info *dafs_ei;
    struct zone_ptr *zone_p;
    struct dafs_dentry *dafs_de, *par_de;
    struct dir_info *par_dir;
    struct file_p *new_sf;
    u64 hashname, p_len, par_hn;
    u32 cur_pos = 0;
    //int ret;
	

    //nova_dbg("%s start ino is %llu, par_ino is %llu", __func__, self_ino, parent_ino);
    dafs_ze = (struct dafs_zone_entry *)nova_get_block(sb, dzt_ei->dz_addr);
    //nova_dbg("par ze addr is %llu", dzt_ei->dz_addr);

    make_zone_ptr(&zone_p, dafs_ze);
    bitpos = 0;
    while(cur_pos<NR_DENTRY_IN_ZONE){
        if(test_bit_le(bitpos, (void *)zone_p->statemap)||test_bit_le(bitpos+1, (void *)zone_p->statemap)){
            bitpos+=2;
            cur_pos++;
        }else{
            break;
        }
    }

    /* if not enough entries, negtive split*/
    if(cur_pos == NR_DENTRY_IN_ZONE){
        dafs_split_zone(sb, dzt_ei, 0, NEGTIVE_SPLIT);
    }

    p_len = strlen(ful_name);
    phn_f[0] = '\0';
    //phn_f = kzalloc(sizeof(char)*(p_len+4), GFP_KERNEL);
    memcpy(phn_f, ful_name, p_len);
    phn_f[p_len]='\0';

    dafs_de = &dafs_ze->dentry[cur_pos];
    dafs_de->entry_type = DAFS_DIR_ENTRY;
    /*标示. ..文件*/
    dafs_de->file_type = NORMAL_FILE;
    dafs_de->name_len = 1;
    dafs_de->links_count = 1;
    dafs_de->mtime = CURRENT_TIME_SEC.tv_sec;
    /*if not super root sub init file, then isr_sf = 0*/
    dafs_de->isr_sf = 0;
    dafs_de->ino = cpu_to_le64(self_ino);
    dafs_de->size = sb->s_blocksize;
    dafs_de->par_pos = cpu_to_le32(par_pos);
    
    memcpy(dafs_de->name, ".", 1);
    dafs_de->name[1]='\0';

    /*set ful_name*/
    p_len += 2;
    dafs_de->fname_len = cpu_to_le64(p_len);
    if(p_len == 3)
        strcat(phn_f, ".");
    else
        strcat(phn_f, "/.");
    /*normal file*/
    dafs_de->ful_name.f_name[0]='\0';
    dafs_de->ext_flag=0;
     
    /*make valid*/
    bitpos++;
    test_and_set_bit_le(bitpos, (void *)zone_p->statemap);
    bitpos++;
    //h_len = phlen + 2;
    hashname = BKDRHash(phn_f, p_len);
    //nova_dbg("%s init entry name %s",__func__,phn_f);
    dafs_de->hname = cpu_to_le64(hashname);
    record_pos_htable(sb, dzt_ei->ht_head, hashname, cur_pos, 1);

    par_de = &dafs_ze->dentry[par_pos];
    //nova_dbg("par pos is %d, cur pos is %d", par_pos,cur_pos);
    par_hn = le64_to_cpu(par_de->hname);
    /*bugbugbugbugbug*/
    //nova_dbg("parent hashname is %llu", par_hn);
    /*update dir info entry */
    par_dir = radix_tree_lookup(&dzt_ei->dir_tree, par_hn);
    if(!par_dir){
        //nova_dbg("dafs not find dir entry");
        return -EINVAL;
    }
    par_dir->sub_num++;
    new_sf = kzalloc(sizeof(struct file_p), GFP_KERNEL);
    new_sf->pos = cur_pos;
    list_add_tail(&new_sf->list, &par_dir->sub_file);

    //nova_dbg("%s . pos is %d",__func__,cur_pos);
    nova_flush_buffer(dafs_de, DAFS_DEF_DENTRY_SIZE, 0);
    
    cur_pos++;

    while(cur_pos<NR_DENTRY_IN_ZONE){
        if(test_bit_le(bitpos, (void *)zone_p->statemap)||test_bit_le(bitpos+1, (void *)zone_p->statemap)){
            bitpos+=2;
            cur_pos++;
        }else{
            break;
        }
    }
    dafs_de = &dafs_ze->dentry[cur_pos];
    dafs_de->entry_type = DAFS_DIR_ENTRY;
    /*标示. ..文件*/
    dafs_de->file_type = NORMAL_FILE;
    dafs_de->name_len = 2;
    dafs_de->links_count = 2;
    dafs_de->mtime = CURRENT_TIME_SEC.tv_sec;
    dafs_de->isr_sf = 0;
    dafs_de->ino = cpu_to_le64(parent_ino);
    dafs_de->size = sb->s_blocksize;
    memcpy(dafs_de->name, "..", 2);
    dafs_de->name[2]='\0';
    p_len ++; 
    dafs_de->fname_len = cpu_to_le64(p_len);
    /*normal file*/
    dafs_de->ful_name.f_name[0]='\0';
    dafs_de->ext_flag=0;
    strcat(phn_f, ".");
    
    /*make valid*/
    bitpos++;
    test_and_set_bit_le(bitpos, (void *)zone_p->statemap);
    hashname = BKDRHash(phn_f, p_len);
    dafs_de->hname = cpu_to_le64(hashname);
    record_pos_htable(sb, dzt_ei->ht_head, hashname, cur_pos, 1);
    
    /*update dir info entry */
    par_dir->sub_num++;
    new_sf = kzalloc(sizeof(struct file_p), GFP_KERNEL);
    new_sf->pos = cur_pos;
    list_add_tail(&new_sf->list, &par_dir->sub_file);

    //nova_dbg("%s .. pos is %d",__func__,cur_pos);
    nova_flush_buffer(dafs_de, DAFS_DEF_DENTRY_SIZE, 0);
    //kfree(phname);
    //kfree(phn_f);
    kfree(zone_p);
    //nova_dbg("dafs finish add initial part in dir");
    return 0;
}

/*bug 应该检验一下状态图是否有效*/
int dafs_empty_dir(struct inode *inode, struct dentry *dentry)
{
    struct super_block *sb = inode->i_sb;
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dafs_dentry *denties[4];
    struct dzt_entry_info *dzt_ei;
    struct dafs_zone_entry *dafs_ze;
    struct dir_info *par_dir;
    struct file_p *tem_sf;
    struct list_head *this, *head;
    unsigned long phlen, flen, slen;
    u64 dzt_eno;
    u64 ph_hash;
    u32 de_pos;
    char ph_f[DAFS_PATH_LEN], ph_dzt[DAFS_PATH_LEN], ph_name[DAFS_PATH_LEN];
    char *phname=ph_name, *ph=ph_f, *phn=ph_dzt;
    //char *ph;
    unsigned long nr_de;
    int i, ret;
    struct path_entry *pe;
    struct path_tree *pt = sbi->pt;
    u64 ino = inode->i_ino;

    //nova_dbg("%s dafs start test empty dir",__func__);
    if(!ino)
        return -EINVAL;
    pe = radix_tree_lookup(&pt->de_path, ino);
    if(!pe)
        return -EINVAL;
    dzt_ei = pe->ei;
    par_dir = pe->d_f;
    /*
    get_dentry_path(dentry,ph,inode->i_ino);
    slen = strlen(ph)+1;
        
    //phname = kzalloc(sizeof(char)*slen, GFP_KERNEL);
    //phn = kzalloc(sizeof(char)*slen, GFP_KERNEL);
    dzt_ei = find_dzt(sb, ph, phn);
    
    dafs_ze = (struct dafs_zone_entry *)nova_get_block(sb, dzt_ei->dz_addr);
    phlen = strlen(phn);
    dzt_eno = dzt_ei->dzt_eno;
    if(phlen==1){
        flen = strlen(ph);
        memcpy(phname, ph, flen);
        phname[flen]='\0';
    } else {
        flen = strlen(ph)-phlen;
        memcpy(phname, ph+phlen, flen);
        phname[flen]='\0';
    }*/
    
    //nova_dbg("%s name %s",__func__, phname);
    //ph_hash = BKDRHash(phname, flen);
    //kfree(phname);
    //kfree(ph);
    //kfree(phn);

    /*lookup in hash table, not decided*/
    /*
    ret = lookup_in_hashtable(sb, dzt_ei->ht_head, ph_hash, 1, &de_pos);
    if(!ret)
        return -EINVAL;

    //direntry = &dafs_ze->dentry[de_pos];
    
    par_dir = radix_tree_lookup(&dzt_ei->dir_tree, ph_hash);*/
   /* if(par_dir){
        nova_dbg("%s dafs find par dir, num is %d",__func__,par_dir->sub_num);
    }*/
    nr_de = par_dir->sub_num;
    //nova_dbg("%s sub de is %d",__func__,nr_de);
    if(nr_de > 0)
        return 0;

    /*
    head = &par_dir->sub_file;

    for(i = 0; i < nr_de; i++){
        list_for_each(this, head) {
            tem_sf = list_entry(this, struct file_p, list);
            de_pos = tem_sf->pos;
        }
        denties[i] = &dafs_ze->dentry[de_pos];
        //if(!is_dir_init_entry(sb, denties[i]))
        //    return 0;
    }*/

    
    //nova_dbg("%s dir is empty",__func__);
    return 1;

}

/*add rename zone root dentry
 * dentry 是新的dentry*/
int add_rename_zone_dir(struct dentry *dentry, struct dafs_dentry *old_de, struct dzt_entry_info *old_ei,
        u64 *new_hn, u64 *root_len)
{
    struct inode *dir = dentry->d_parent->d_inode;
    struct super_block *sb = dir->i_sb;
    struct nova_inode *pidir;
    //const char *name = dentry->d_name.name;
    unsigned short namelen = dentry->d_name.len;
    //struct dafs_dentry *direntry;
    struct dzt_entry_info *dzt_ei;
    struct dafs_zone_entry *dafs_ze, *old_ze;
    struct zone_ptr *zone_p;
    struct dafs_dentry *dafs_de;
    struct dir_info *pdir, *new_dir, *old_dir;
    struct file_p *tem_sf, *new_sf;
    struct list_head *this, *head, *next;
    char ph_f[DAFS_PATH_LEN], ph_dzt[DAFS_PATH_LEN], ph_name[DAFS_PATH_LEN];
    char *new_pn, *ph=ph_f, *par_ph, *tname, *phname=ph_name, *phn=ph_dzt;
    unsigned long phlen;
    //unsigned short delen;
    u32 bitpos = 0, cur_pos = 0, par_pos, slen;
    u64 hashname, newp_len, par_hash, temlen, old_hn;
    int ret = 0;
    timing_t add_dentry_time;

    
	/*nova_dbg_verbose("%s: dir %lu new inode %llu\n",
				__func__, dir->i_ino, ino);
	nova_dbg_verbose("%s: %s %d\n", __func__, name, namelen);*/

	NOVA_START_TIMING(add_dentry_t, add_dentry_time);
	if (namelen == 0)
		return -EINVAL;
   
    get_dentry_path(dentry,ph, dentry->d_inode->i_ino);
    
    slen = strlen(ph);
    memcpy(phname, ph, slen);
    phname[slen]='\0';
    dzt_ei = find_dzt(sb, phname, phn);
    dafs_ze = (struct dafs_zone_entry *)nova_get_block(sb, dzt_ei->dz_addr);

    make_zone_ptr(&zone_p, dafs_ze);
    while(cur_pos<NR_DENTRY_IN_ZONE){
        if(test_bit_le(bitpos, (void *)zone_p->statemap)||test_bit_le(bitpos+1, (void *)zone_p->statemap)){
            bitpos+=2;
            cur_pos++;
        }else{
            break;
        }
    }

    phlen = strlen(phn);
    pidir = nova_get_inode(sb, dir);
    dir->i_mtime = dir->i_ctime = CURRENT_TIME_SEC;
    //delen = DAFS_DIR_LEN(namelen + phlen);  

    /*get dentry on nvm*/
    dafs_de = &dafs_ze->dentry[cur_pos];
    //memset(dafs_de, 0, sizeof(dafs_de));
    
    dafs_de->entry_type = DAFS_DIR_ENTRY;
    dafs_de->name_len = dentry->d_name.len;
    dafs_de->file_type = ROOT_DIRECTORY;       //file_type是啥？ not decided

	dafs_de->links_count = old_de->links_count;

    dafs_de->mtime = cpu_to_le32(dir->i_mtime.tv_sec);
    /*not root at first*/
    //dafs_de->isr_sf = old_de->isr_sf;
    dafs_de->ino = old_de->ino;
    dafs_de->size = cpu_to_le64(dir->i_size);
    /*add dentry name*/
    if(dentry->d_name.len <= SMALL_NAME_LEN){
        dafs_de->ext_flag = 0;
        memcpy(dafs_de->name,dentry->d_name.name,dentry->d_name.len);
        dafs_de->name[dentry->d_name.len] = '\0'; 

    } else {
        dafs_de->ext_flag = 1;
        ext_de_name(sb, dzt_ei, dafs_ze, zone_p, cur_pos, dentry->d_name.len, dentry->d_name.name, 0);
    }

    dafs_de->fname_len = cpu_to_le64(phlen);

    /*set isr_sf, fulname*/
    temlen = phlen - dentry->d_name.len;
    if(temlen == 1){
        dafs_de->isr_sf = 1;
        dafs_de->par_pos = 0;
    }else{
        dafs_de->isr_sf = 0;
        /*set par_pos*/
        par_ph = kzalloc(temlen*sizeof(char), GFP_KERNEL);
        temlen--;
        memcpy(par_ph, phn, temlen);
        par_ph[temlen] = '\0';
        par_hash = BKDRHash(par_ph, temlen);
        lookup_in_hashtable(sb, dzt_ei->ht_head, par_hash, 1, &par_pos);
        dafs_de->par_pos = cpu_to_le32(par_pos);

        /*set sub file pos*/
        pdir = radix_tree_lookup(&dzt_ei->dir_tree, par_hash);
        pdir->sub_num++;
        tem_sf = (struct file_p *)kzalloc(sizeof(struct file_p), GFP_KERNEL);
        tem_sf->pos = cur_pos;
        list_add_tail(&tem_sf->list, &pdir->sub_file);
        kfree(par_ph);
        
    }

    /*set root dir fulname*/
    if(dafs_de->ext_flag==0){
        //re_len = SMALL_NAME_LEN - dentry->d_name.len;
        if(phlen<SMALL_NAME_LEN){
            memcpy(dafs_de->ful_name.f_name, phn, phlen);
            dafs_de->ful_name.f_name[phlen]='\0';
        } else {
            dafs_de->ext_flag = 2;
            ext_de_name(sb, dzt_ei, dafs_ze, zone_p, cur_pos, phlen, phn, 1);
        }
    } else
        ext_de_name(sb, dzt_ei, dafs_ze, zone_p, cur_pos, phlen, phn, 1);

    /*get hash value*/
    hashname = BKDRHash(phn, phlen);


    /*get new ei path hashname*/
    if(dzt_ei->dzt_eno!=1){
        newp_len =(u64)dzt_ei->root_len + phlen;
        new_pn = kzalloc(sizeof(char)*(newp_len+1), GFP_KERNEL);
        get_zone_path(sb,dzt_ei, new_pn, phn);
        *root_len = newp_len;
        *new_hn = BKDRHash(new_pn, newp_len);
        kfree(new_pn);
    } else {
        newp_len = phlen;
        new_pn = kzalloc(sizeof(char *)*(newp_len+1), GFP_KERNEL);
        memcpy(new_pn, phn, newp_len);
        new_pn[newp_len]='\0';
        *root_len = newp_len;
        *new_hn = BKDRHash(new_pn, newp_len);
        kfree(new_pn);
    }

    dafs_de->dzt_hn = cpu_to_le64(*new_hn);

    /*not decided是不是每次写到nvm都需要这个接口*/ 
    nova_flush_buffer(dafs_de, DAFS_DEF_DENTRY_SIZE, 0);
    
    /*make valid*/
    bitpos++;
    test_and_set_bit_le(bitpos, (void *)zone_p->statemap);
    
    dir->i_blocks = pidir->i_blocks;

    /*cpy dir_info*/
    new_dir = add_dir_info(dzt_ei, hashname, cur_pos);
    phlen = le64_to_cpu(old_de->fname_len);
    tname = kzalloc(sizeof(char)*phlen,GFP_KERNEL);
    old_ze = (struct dafs_zone_entry *)nova_get_block(sb, old_ei->dz_addr);
    get_de_name(old_de, old_ze, tname, 1);
    old_hn = BKDRHash(tname, phlen); 
    old_dir = radix_tree_delete(&old_ei->dir_tree, phlen);
    head = &old_dir->sub_file;
    list_for_each_safe(this, next, head){
        tem_sf = list_entry(this, struct file_p, list);
        new_sf = kzalloc(sizeof(struct file_p), GFP_KERNEL);
        new_sf->pos = tem_sf->pos;
        list_add_tail(&new_sf->list, &new_dir->sub_file);
        list_del(&tem_sf->list);
        kfree(tem_sf);
    }
    kfree(old_dir);

    /*set pos in hash table for each zone*/
    //hashname = BKDRHash(phn, phlen);
    record_pos_htable(sb, dzt_ei->ht_head, hashname, cur_pos, 1);

    kfree(tname);
    kfree(phname);
    kfree(ph);
    kfree(phn);
    kfree(zone_p);
    NOVA_END_TIMING(add_dentry_t, add_dentry_time);
    return ret;
}

/*rename code recursive
 * n_ze是new_dentry所在的zone
 * path是新的目录的字符串
 * name纯的文件名*/
int __rename_dir(struct super_block *sb, struct dafs_dentry *src_de, \
        struct dzt_entry_info *dzt_ei, struct dzt_entry_info *old_ei, const char *path, char *name)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct zone_ptr *z_p;
    struct dafs_dentry *new_de, *sub_de, *par_de;
    struct dafs_zone_entry *ze, *o_ze;
    struct dzt_entry_info *ch_ei;
    struct dzt_manager *dzt_m = sbi->dzt_m_info;
    struct dir_info *new_dir, *old_dir, *pdir, *nr_dir;
    struct list_head *this, *head, *next;
    struct file_p *tem_sf, *new_sf;
    u32 bitpos = 0, dir_pos = 0, s_pos, par_pos, par_id;
    int ret=0;
    u64 nlen, flen, sub_plen, temlen, ino, slen;
    //u8 isr_sf;
    char *new_ph, *s_name, *sub_ph, *ch_ph, *tem, *r_name;
    u64 hashname, dzt_hn, ch_len, sub_len, old_hn, par_hash, rn_len;

    //nova_dbg("%s start",__func__);
    ze = (struct dafs_zone_entry *)nova_get_block(sb, dzt_ei->dz_addr);
    make_zone_ptr(&z_p, ze);

    nlen = strlen(name);
    flen = strlen(path);
    new_ph = kzalloc(sizeof(char )*(flen+1), GFP_KERNEL);
    memcpy(new_ph, path, flen);
    new_ph[flen]='\0';
    /*set dir entry*/
    while(bitpos<z_p->zone_max){
        if(test_bit_le(bitpos, (void *)z_p->statemap)||test_bit_le(bitpos+1, (void *)z_p->statemap)){
            bitpos+=2;
            dir_pos++;
        }else{
            break;
        }
    }
    new_de = &ze->dentry[dir_pos];
    par_id = dir_pos;
    //memset(new_de, 0, sizeof(new_de));    
    new_de->entry_type = src_de->entry_type;
    new_de->name_len = nlen;
    new_de->file_type = src_de->file_type;       //file_type是啥？ not decided
	new_de->links_count = src_de->links_count;
    //new_de->de_len = cpu_to_le16(delen);  
    new_de->mtime = cpu_to_le32(CURRENT_TIME_SEC.tv_sec);
    //new_de->isr_sf = src_de->isr_sf;
    new_de->ino = src_de->ino;
    
    new_de->size = src_de->size;
    /*set name*/
    if(nlen<=SMALL_NAME_LEN){
        new_de->ext_flag = 0;
        memcpy(new_de->name, name, nlen);
        new_de->name[nlen] = '\0';
    } else {
        new_de->ext_flag = 1;
        ext_de_name(sb, dzt_ei, ze, z_p, dir_pos, nlen, name, 0);
    }
    new_de->fname_len = cpu_to_le64(flen);
    
    /*set dir fulname*/
    if(new_de->ext_flag==0){
        if(flen<SMALL_NAME_LEN){
            memcpy(new_de->ful_name.f_name, new_ph, flen);
            new_de->ful_name.f_name[flen]='\0';
        } else {
            new_de->ext_flag = 2;
            ext_de_name(sb, dzt_ei, ze, z_p, dir_pos, flen, new_ph, 1);
        }
    } else
        ext_de_name(sb, dzt_ei, ze, z_p, dir_pos, flen, new_ph, 1);

    /*set par_pos and subpos in par
     * set isr_sf*/
    temlen = flen - nlen;
    if(temlen == 1){
        new_de->isr_sf = 1;
        new_de->par_pos = 0;
        par_de = &ze->dentry[0];
        ino = le64_to_cpu(par_de->ino);
        if(ino == NOVA_ROOT_INO){
            //nova_dbg("new par is root");
            par_hash = le64_to_cpu(par_de->hname);
            lookup_in_hashtable(sb, dzt_ei->ht_head, par_hash, 1, &par_pos);
            pdir = radix_tree_lookup(&dzt_ei->dir_tree, par_hash);
            tem_sf = kzalloc(sizeof(struct file_p), GFP_KERNEL);
            tem_sf->pos = cpu_to_le32(dir_pos);
            list_add_tail(&tem_sf->list, &pdir->sub_file);
            pdir->sub_num++;
        }
    } else {
        new_de->isr_sf = 0;
        tem = kzalloc(sizeof(char)*temlen, GFP_KERNEL);
        temlen--;
        memcpy(tem, new_ph, temlen);
        tem[temlen]='\0';
        par_hash = BKDRHash(tem, temlen);
        lookup_in_hashtable(sb, dzt_ei->ht_head, par_hash, 1, &par_pos);
        new_de->par_pos = cpu_to_le64(par_pos);

        /*add list entry*/
        pdir = radix_tree_lookup(&dzt_ei->dir_tree, par_hash);
        pdir->sub_num++;
        tem_sf = kzalloc(sizeof(struct file_p), GFP_KERNEL);
        tem_sf->pos = dir_pos;
        list_add_tail(&tem_sf->list, &pdir->sub_file);
        kfree(tem);
    }

    /*make valid*/
    bitpos++;
    test_and_set_bit_le(bitpos, (void *)z_p->statemap);
    bitpos++;
    hashname = BKDRHash(new_ph, strlen(new_ph));
    record_pos_htable(sb, dzt_ei->ht_head, hashname, dir_pos, 1);
    new_de->hname = cpu_to_le64(hashname);

    dir_pos++;

    /*new dir_info_entry*/
    new_dir = add_dir_info(dzt_ei, hashname, dir_pos);
    new_dir->f_s = DENTRY_FREQUENCY_WRITE;
    //ret = update_write_hot(dzt_ei, hashname);
    if(ret)
        return -EINVAL;
    
    nova_flush_buffer(new_de, DAFS_DEF_DENTRY_SIZE, 0);
    
    old_hn = le64_to_cpu(src_de->hname);
    old_dir = radix_tree_lookup(&dzt_ei->dir_tree, old_hn);
    head = &old_dir->sub_file;
    
    /*rename 子文件*/
    list_for_each_safe(this, next, head) {
        tem_sf = list_entry(this, struct file_p, list);
        s_pos = tem_sf->pos;
        sub_de = &ze->dentry[s_pos];
        sub_ph = kzalloc(sizeof(char )*LARGE_NAME_LEN, GFP_KERNEL);
        sub_len = le64_to_cpu(sub_de->name_len);
        s_name = kzalloc(sizeof(char )*(sub_len+1), GFP_KERNEL);
        if(sub_de->ext_flag==1)
            get_ext_name(sub_de->next, s_name);
        else{
            memcpy(s_name, sub_de->name, sub_len);
            s_name[sub_len] = '\0';
        }
        slen = strlen(new_ph);
        memcpy(sub_ph, new_ph, slen);
        sub_ph[slen] = '\0';
        strcat(sub_ph, "/");
        strcat(sub_ph, s_name);

        if(sub_de->file_type == NORMAL_DIRECTORY){
            ret = __rename_dir(sb, sub_de, dzt_ei,old_ei, sub_ph, s_name);

        } else {
            //delen = DAFS_DIR_LEN(str(s_name)+str(sub_ph));
            /*set dir entry*/
            while(bitpos<z_p->zone_max){
                if(test_bit_le(bitpos, (void *)z_p->statemap)||test_bit_le(bitpos+1, (void *)z_p->statemap)){
                    bitpos+=2;
                    dir_pos++;
                }else{
                    break;
                }
            }
            new_de = &ze->dentry[dir_pos]; 
            //memset(new_de, 0, sizeof(new_de));    
            new_de->entry_type = sub_de->entry_type;
            new_de->name_len = sub_de->name_len;
            new_de->file_type = sub_de->file_type;       //file_type是啥？ not decided
	        new_de->links_count = sub_de->links_count;
            //new_de->de_len = cpu_to_le16(delen);  
            new_de->mtime = cpu_to_le32(CURRENT_TIME_SEC.tv_sec);
            //new_de->isr_sf = sub_de->isr_sf;
            new_de->ino = sub_de->ino;
              
            new_de->size = sub_de->size;
            if(sub_de->ext_flag==1){
                new_de->ext_flag=1;
                ext_de_name(sb, dzt_ei, ze, z_p, dir_pos, sub_len, s_name, 0);

            }else{

                new_de->ext_flag = sub_de->ext_flag;
                memcpy(new_de->name, s_name, sub_len);
                new_de->name[sub_len] = '\0';
            }

            sub_plen = strlen(sub_ph);
            new_de->fname_len = cpu_to_le64(sub_plen);
            //new_de->par_pos = sub_de->par_pos;
            /*set isr_sf, new_de is not root*/
            new_de->isr_sf = 0;
            new_de->par_pos = cpu_to_le32(par_id);

            /*set fulname*/
            /*ROOT_DIRECTORY set fulname and update ei*/
            if(new_de->file_type==ROOT_DIRECTORY) {
                /*set_ful name*/
                if(sub_de->ext_flag==0){
                    if(sub_plen<SMALL_NAME_LEN){
                        memcpy(new_de->ful_name.f_name, sub_ph, sub_plen);
                        new_de->ful_name.f_name[sub_len]='\0';
                    } else {
                        new_de->ext_flag = 2;
                        ext_de_name(sb ,dzt_ei, ze, z_p, dir_pos, sub_plen, sub_ph, 1);
                    }
                } else
                    ext_de_name(sb, dzt_ei, ze, z_p, dir_pos, sub_plen, sub_ph, 1);

                dzt_hn = le64_to_cpu(sub_de->dzt_hn);
                ch_ei = radix_tree_delete(&dzt_m->dzt_root, dzt_hn);
                if(dzt_ei->dzt_eno!=1) {
                    ch_len =(u64)dzt_ei->root_len + strlen(sub_ph);
                    ch_ph = kzalloc(sizeof(char *)*(ch_len+1), GFP_KERNEL);
                    get_zone_path(sb, dzt_ei, ch_ph, sub_ph);
                } else {
                    ch_len = strlen(sub_ph);
                    ch_ph = kzalloc(sizeof(char *)*(ch_len+1), GFP_KERNEL);
                    memcpy(ch_ph, sub_ph, ch_len);
                    ch_ph[ch_len]='\0';
                }
                dzt_hn = BKDRHash(ch_ph, ch_len);
                ch_ei->root_len = (u32)ch_len;
                ch_ei->hash_name = dzt_hn;
                radix_tree_insert(&dzt_m->dzt_root, dzt_hn, ch_ei);
                radix_tree_tag_set(&dzt_m->dzt_root, dzt_hn, 1);
                kfree(ch_ph);
                new_de->dzt_hn = cpu_to_le64(dzt_hn);
            } else {
                new_de->ful_name.f_name[0]='\0';
                new_de->hname = cpu_to_le64(hashname);
                //new_de->dzt_hn = sub_de->dzt_hn;
            }

            /*make valid*/
            bitpos++;
            test_and_set_bit_le(bitpos, (void *)z_p->statemap);
            hashname = BKDRHash(sub_ph, strlen(sub_ph));
           
            /*rename dir_info*/
            if(new_de->file_type==ROOT_DIRECTORY){
                nr_dir = add_dir_info(dzt_ei, hashname, dir_pos);
                o_ze = (struct dafs_zone_entry *)nova_get_block(sb, old_ei->dz_addr);
                rn_len = le64_to_cpu(src_de->fname_len); 
                r_name = kzalloc(sizeof(char)*(rn_len+1),GFP_KERNEL);
                get_de_name(src_de, o_ze, r_name, 1);
                old_hn = BKDRHash(r_name, rn_len);
                old_dir = radix_tree_delete(&old_ei->dir_tree, old_hn);
                this = head = next =NULL;
                head = &old_dir->sub_file;
                list_for_each_safe(this, next, head){
                    tem_sf = list_entry(this, struct file_p, list);
                    new_sf = kzalloc(sizeof(struct file_p),GFP_KERNEL);
                    new_sf->pos = tem_sf->pos;
                    list_add_tail(&new_sf->list, &nr_dir->sub_file);
                    list_del(&tem_sf->list);
                    kfree(tem_sf);
                }
                kfree(old_dir);
                
            }
            /*
            if(new_de->file_type==NORMAL_DIRECTORY){
                new_de->ful_name->f_name[0]="/0";
                new_de->hname = cpu_to_le64(hashname);
            } */

            record_pos_htable(sb, dzt_ei->ht_head, hashname,  dir_pos, 1);
            nova_flush_buffer(new_de, DAFS_DEF_DENTRY_SIZE, 0);
            
            /*add in dir subpos*/
            new_sf = kzalloc(sizeof(struct file_p), GFP_KERNEL);
            new_sf->pos = dir_pos;
            new_dir->sub_num++;
            list_add_tail(&new_sf->list, &new_dir->sub_file);

            bitpos++;
            dir_pos++;
            
        }
        //list_del(&tem_sf->list);
        //old_dir->sub_num--;
        //kfree(tem_sf);
        kfree(s_name);
        kfree(sub_ph);
    }
    kfree(z_p);
    kfree(new_ph);
    //nova_dbg("%s end",__func__);
    return ret;

}

/*rename directories*/
int add_rename_dir(struct dentry *o_dentry, struct dentry *n_dentry, struct dafs_dentry *old_de,
                   struct dzt_entry_info *old_ei)
{
    struct super_block *sb = o_dentry->d_sb;
    //struct dafs_dentry *new_de;
    struct dzt_entry_info *n_ei;
    struct dafs_zone_entry *n_ze;
    char ph_f[DAFS_PATH_LEN], ph_dzt[DAFS_PATH_LEN], ph_name[DAFS_PATH_LEN];
    char *n_phname=ph_name, *ph=ph_f, *n_name, *phn=ph_dzt;
    u32 namelen = n_dentry->d_name.len;
    u64 phlen, flen;
    //u32 bitpos, cur_pos;
    //int i;
    int ret= 0;

    //nova_dbg("%s start",__func__); 
    get_dentry_path(n_dentry, ph, n_dentry->d_inode->i_ino);
    //memcpy(n_phname, ph, strlen(ph)+1);
    n_ei = find_dzt(sb, ph, phn);
    n_ze = (struct dafs_zone_entry *)nova_get_block(sb, n_ei->dz_addr);
    
    phlen = strlen(phn);
    if(phlen==1){
        flen = strlen(ph);
        memcpy(n_phname, ph, flen);
        n_phname[flen]='\0';
    } else {
        flen = strlen(ph)-phlen;
        memcpy(n_phname, ph+phlen, flen);
        n_phname[flen]='\0';
    }

    n_name = kzalloc(sizeof(char)*(namelen+1), GFP_KERNEL);
    memcpy(n_name, n_dentry->d_name.name, namelen);
    n_name[namelen] = '\0';

    ret = __rename_dir(sb, old_de, n_ei, old_ei,n_phname, n_name);
    
    kfree(n_phname);
    kfree(phn);
    kfree(ph);
    kfree(n_name);
    //nova_dbg("%s end",__func__);
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
    struct dafs_dentry *old_de;
    struct dzt_entry_info *ch_ei, *old_ei;
    struct dzt_manager *dzt_m = sbi->dzt_m_info;
    struct dafs_zone_entry *dafs_ze;
    char ph_f[DAFS_PATH_LEN], ph_dzt[DAFS_PATH_LEN], ph_name[DAFS_PATH_LEN];
    char *ph=ph_f, *phname=ph_name, *phn=ph_dzt;
    u32 dzt_eno, de_pos,slen;
    u64 old_hn, new_hn, root_len;
    u64 ph_hash, ht_addr, flen, phlen;
    int err = -ENOENT;
    int ret;

    //nova_dbg("%s start",__func__);
    get_dentry_path(old_dentry, ph, old_dentry->d_inode->i_ino);
    //nova_dbg("strictly full name is %s", ph);
    //nova_dbg("strictly full name length is %llu", strlen(ph));
    old_ei = find_dzt(sb, ph, phn);
    dafs_ze = (struct dafs_zone_entry *)nova_get_block(sb, old_ei->dz_addr);
    phlen = strlen(phn);
    dzt_eno = old_ei->dzt_eno;
    if(phlen==1){
        slen = strlen(ph);
        memcpy(phname, ph, slen);
        phname[slen] = '\0';
    } else {
        flen = strlen(ph)-phlen;
        memcpy(phname, ph+phlen, flen);
        phname[flen] = '\0';
    }
    ph_hash = BKDRHash(phname, strlen(phname));
    ht_addr = old_ei->ht_head;
    ret = lookup_in_hashtable(sb, ht_addr, ph_hash, 1, &de_pos);
    if(!ret){
        //nova_dbg("not found dentry in nvm");
        goto OUT;
    }
    old_de = &dafs_ze->dentry[de_pos];
    kfree(phname);
    kfree(ph);
    kfree(phn);
    //old_de = dafs_find_direntry(sb, old_dentry,0,0);
    //dz_no = le64_to_cpu(old_de->zone_no);
    
    if(old_de->file_type == ROOT_DIRECTORY){
        old_hn = le64_to_cpu(old_de->hname);
        ch_ei = radix_tree_delete(&dzt_m->dzt_root, old_hn);
        err = add_rename_zone_dir(new_dentry, old_de, old_ei, &new_hn, &root_len);
        /*防止zone被删除*/
        if(err)
            return err;
        ch_ei->root_len = root_len;
        ch_ei->hash_name = new_hn;
        /*update ei hashname, root len and set dirty bit*/
        radix_tree_insert(&dzt_m->dzt_root, new_hn, ch_ei);
        radix_tree_tag_set(&dzt_m->dzt_root, new_hn, 1);

        old_de->file_type = NORMAL_FILE;
        err = dafs_remove_dentry(old_dentry);

    } else {
        
        err = add_rename_dir(old_dentry, new_dentry, old_de, old_ei); 
        if(err)
            return err;
        err = dafs_remove_dentry(old_dentry);
    }
OUT:
   return err;
}

int __rename_file_dentry(struct dentry *old_dentry, struct dentry *new_dentry)
{
    struct super_block *sb = old_dentry->d_sb;
    struct dafs_dentry *dafs_de, *o_de, *par_de;
    struct dafs_zone_entry *n_ze;
    struct dzt_entry_info *n_ei;
    struct zone_ptr *z_p;
    struct dir_info *par_dir;
    struct file_p *new_sf;
    char ph_f[DAFS_PATH_LEN], ph_dzt[DAFS_PATH_LEN], ph_name[DAFS_PATH_LEN];
    char *ph=ph_f, *tem, *phname=ph_name, *phn=ph_dzt;
    u32 bitpos=0, cur_pos=0, par_pos;
    //unsigned short namelen = new_dentry->d_name.len;
    //u8 isr_sf;
    u64 temlen, phlen, flen;
    u64 hashname, par_hn, ino;
    int ret = 0;

    o_de = dafs_find_direntry(sb, old_dentry, 0, 0);

    //nova_dbg("dafs start rename file dentry");

    get_dentry_path(new_dentry,ph,new_dentry->d_inode->i_ino);
    //memcpy(phname, ph, strlen(ph)+1);
    n_ei = find_dzt(sb, ph, phn);
    n_ze = (struct dafs_zone_entry *)nova_get_block(sb, n_ei->dz_addr);
    phlen = strlen(phn);
    if(phlen==1){
        flen = strlen(ph);
        memcpy(phname, ph, flen);
        phname[flen]='\0';
    } else {
        flen = strlen(ph)-phlen;
        memcpy(phname, ph+phlen, flen);
        phname[flen]='\0';
    }
    make_zone_ptr(&z_p, n_ze);
    while(bitpos<z_p->zone_max){
        if(test_bit_le(bitpos, (void *)z_p->statemap)||test_bit_le(bitpos+1, (void *)z_p->statemap)){
            bitpos+=2;
            cur_pos++;
        }else{
            break;
        }
    }

    //phlen = strlen(n_phname);
    //pidir = nova_get_inode(sb, dir);
    //dir->i_mtime = dir->i_ctime = CURRENT_TIME_SEC;
    //de_len = DAFS_DIR_LEN(namelen + phlen); 

    /*get dentry on nvm*/
    dafs_de = &n_ze->dentry[cur_pos];
    //memset(dafs_de, 0, sizeof(dafs_de));
    
    dafs_de->entry_type = DAFS_DIR_ENTRY;
    dafs_de->name_len = new_dentry->d_name.len;
    dafs_de->file_type = o_de->file_type;       //file_type是啥？ not decided

	dafs_de->links_count = o_de->links_count;

    //dafs_de->de_len = cpu_to_le16(de_len);  
    dafs_de->mtime = cpu_to_le32(CURRENT_TIME_SEC.tv_sec);
    /*not root at first*/
    //dafs_de->isr_sf = o_de->isr_sf;
    dafs_de->ino = o_de->ino;
    
    dafs_de->size = o_de->size;
     
    /*judge name len && set dentry name*/
    if(new_dentry->d_name.len <= SMALL_NAME_LEN){
        dafs_de->ext_flag = 0;
        memcpy(dafs_de->name,new_dentry->d_name.name,new_dentry->d_name.len);
        dafs_de->name[new_dentry->d_name.len] = '\0'; 

    } else {
        dafs_de->ext_flag = 1;
        ext_de_name(sb, n_ei, n_ze, z_p, cur_pos, new_dentry->d_name.len, new_dentry->d_name.name, 0);
    }
    dafs_de->fname_len = cpu_to_le64(flen);
    /*fulname is null for NORMAL_FILE*/
    dafs_de->ful_name.f_name[0]= '\0';

    /*set isr_sf and par_pos*/
    temlen = flen-new_dentry->d_name.len;
    if(temlen == 1){
        dafs_de->isr_sf = 1;
        dafs_de->par_pos = 0;
        par_de = &n_ze->dentry[0];
        ino = le64_to_cpu(par_de->ino);
        if(ino == NOVA_ROOT_INO){
            //nova_dbg("new par is root");
            par_hn = le64_to_cpu(par_de->hname);
            lookup_in_hashtable(sb, n_ei->ht_head, par_hn, 1, &par_pos);
            par_dir = radix_tree_lookup(&n_ei->dir_tree, par_hn);
            new_sf = kzalloc(sizeof(struct file_p), GFP_KERNEL);
            new_sf->pos = cpu_to_le32(cur_pos);
            list_add_tail(&new_sf->list, &par_dir->sub_file);
            par_dir->sub_num++;
        }
    } else {
        dafs_de->isr_sf = 0;
        tem = kzalloc(sizeof(char)*temlen, GFP_KERNEL);
        temlen--;
        memcpy(tem, phname, temlen);
        tem[temlen]='\0';
        par_hn = BKDRHash(tem, temlen);
        lookup_in_hashtable(sb, n_ei->ht_head, par_hn, 1, &par_pos);
        dafs_de->par_pos = cpu_to_le32(par_pos);
        //nova_dbg("%s new dentry par name %s, pos%d",__func__, tem, par_pos);
        /*set subpos*/
        par_dir = radix_tree_lookup(&n_ei->dir_tree, par_hn);
        new_sf = kzalloc(sizeof(struct file_p), GFP_KERNEL);
        new_sf->pos = cpu_to_le32(cur_pos);
        list_add_tail(&new_sf->list, &par_dir->sub_file);
        par_dir->sub_num++;
    }
    
    /*make valid*/
    bitpos++;
    test_and_set_bit_le(bitpos, (void *)z_p->statemap);
   
    /*set pos in hash table for each zone*/
    hashname = BKDRHash(phn, phlen);
    dafs_de->hname = cpu_to_le64(hashname);
    record_pos_htable(sb, n_ei->ht_head, hashname, cur_pos, 1);

    nova_flush_buffer(dafs_de, DAFS_DEF_DENTRY_SIZE, 0);
    
    //dafs_remove_dentry(old_dentry);
    
    kfree(phname);
    kfree(ph);
    kfree(phn);
    kfree(z_p);
    //NOVA_END_TIMING(add_dentry_t, add_dentry_time);
    //nova_dbg("%s end",__func__);

    return ret;
    
}

/*遍历文件夹，dir_emit填充到用户空间*/
static int dafs_readdir(struct file *file, struct dir_context *ctx)
{
    struct inode *inode = file_inode(file);
    struct super_block *sb = inode->i_sb;
    struct nova_sb_info *sbi = NOVA_SB(sb);
    //struct inode *prev_inode;
    //struct inode *child_inode;
    struct nova_inode *pidir;
    struct nova_inode *child_pi;
    struct dentry *dentry = file->f_path.dentry; 
    struct dafs_dentry *de = NULL;
    //struct dafs *f_de = NULL;
    struct dafs_dentry *prev_de = NULL;
    struct nova_inode  *prev_child_pi = NULL;
    struct dzt_entry_info *ei;
    struct dafs_zone_entry *ze;
    struct dir_info *dir;
    struct file_p *tem_sf;
    struct list_head *this, *head;
    struct dzt_manager *dzt_m;
    //struct path path;
    //unsigned short de_len;
    u64 pi_addr, ei_hn, dir_hn;
    u32 f_pos;
    u64 pos, prev_pos = 0;
    ino_t ino;
    u8 type;
    int ret, isroot=0;
    char ph_f[DAFS_PATH_LEN], ph_dzt[DAFS_PATH_LEN], ph_name[DAFS_PATH_LEN];
    char *phname = ph_name, *phn = ph_dzt;
    char *ppath = ph_f;
    u64 phlen, flen,ph_hash, ht_head;
    u32 de_pos;
    unsigned short mode;
    struct path_entry *pe;
    struct path_tree *pt = sbi->pt;
    timing_t readdir_time, st;

    //nova_dbg("%s: inode ino %llu, dentry ino %llu",__func__, inode->i_ino, dentry->d_inode->i_ino);

    //nova_dbg("%s start %s",__func__,dentry->d_name.name);
    NOVA_START_TIMING(readdir_t, readdir_time);
    //getrawmonotonic(&st); 

    //pidir = nova_get_inode(sb ,inode);
    pos = ctx->pos;

    
    if(pos == READDIR_END){
        //nova_dbg("%s pos end",__func__);
        //BUG();
        goto OUT;
    } 
    
    ppath[0]='\0';
    pe = radix_tree_lookup(&pt->de_path, dentry->d_inode->i_ino);
    if(pe){
        strcat(ppath, pe->path);
        //ph_hash = pe->hn;
    } else {
        goto OUT;
    }
    //get_dentry_path(dentry, ppath, dentry->d_inode->i_ino);
    //phlen = strlen(ppath);


/*
    pe = radix_tree_lookup(&pt->de_path, dentry->d_inode->i_ino);
    if(!pe)
        goto OUT;
    //memcpy(phname, pe->path, pe->len);
    //phname[pe->len]='\0';
    ph_hash = pe->hn;
*/

    //path.mnt = file->f_path.mnt;

    //ei = find_dzt(sb, ppath, phn);
    ei = pe->ei;
    ze = (struct dafs_zone_entry *)nova_get_block(sb, ei->dz_addr);
    /*
    phlen = strlen(phn);
    if(phlen==1){
        phname = ppath;
        //flen = pe->len;
    } else {
        flen = strlen(ppath)-phlen;
        memcpy(phname, ppath+phlen, flen);
        phname[flen]='\0';
    }*/
    //ph_hash = BKDRHash(phname, flen);

    //ht_head = ei->ht_head;
    //getrawmonotonic(&st); 
    /*ret = lookup_in_hashtable(sb, ht_head, ph_hash, 1, &de_pos);
    if(!ret){
        //nova_dbg("%s not find dentry in nvm",__func__);
        BUG();
    }*/
    
    /*f_de = &ze->dentry[de_pos];
    ino = le64_to_cpu(f_de->ino);*/
    /*
    if(ino!=inode->i_ino){
        BUG();
        strcat(ppath, "/");
        strcat(ppath, dentry->d_name.name);
        de_pos = 0;
        ei = find_dzt(sb, ppath, phn);
        //BUG_ON(ei==NULL);
        ze = (struct dafs_zone_entry *)nova_get_block(sb, ei->dz_addr);
        phlen = strlen(phn);
        if(phlen==1){
            flen = strlen(ppath);
            memcpy(phname, ppath, flen);
            phname[flen]='\0';
        } else {
            flen = strlen(ppath)-phlen;
            memcpy(phname, ppath+phlen, flen);
            phname[flen]='\0';
        }
        ph_hash = BKDRHash(phname, flen);
        ht_head = ei->ht_head;
        ret = lookup_in_hashtable(sb, ht_head, ph_hash, 1, &de_pos);
        if(!ret){
            //nova_dbg("%s not find dentry in nvm",__func__);
            BUG();
        }
          
        f_de = &ze->dentry[de_pos];
    }*/

    //dir = radix_tree_lookup(&ei->dir_tree, ph_hash);
    dir = pe->d_f;
    if(dir->sub_num==0)
    {
        ctx->pos = READDIR_END;
        goto OUT;
    }
    
    /*
    if(f_de->file_type==ROOT_DIRECTORY && (ino!=NOVA_ROOT_INO)){
        isroot = 1;
        ei_hn = f_de->dzt_hn;
        dzt_m = sbi->dzt_m_info;
        sei = radix_tree_lookup(&dzt_m->dzt_root, ei_hn);
        //nova_dbg("%s:new root zone addr is %llu",__func__, sei->dz_addr);
        ze = (struct dafs_zone_entry *)nova_get_block(sb, sei->dz_addr);
        ei = sei;
    }*/

    //nova_dbg("%s pos %llu",__func__,pos);
    if(pos==0)
        head = &dir->sub_file;
    else
        head = pos;
    //nova_dbg("%s head is %llu, pos %llu", __func__,head, pos);
    list_for_each(this, head){
        if(prev_pos==&dir->sub_file){
            ctx->pos=READDIR_END;
            goto OUT;
        }
        tem_sf = list_entry(this, struct file_p, list);
        pos = &tem_sf->list;
        f_pos = tem_sf->pos;
        /*if(!f_pos && !isroot){
            ctx->pos = READDIR_END;
            BUG();
            goto OUT;
        }*/

        de = &ze->dentry[f_pos];
        ino = le64_to_cpu(de->ino);
        mode = le16_to_cpu(de->mode);
        /*ret = nova_get_inode_address(sb, ino, &pi_addr, 0);
        if(ret){
            ctx->pos = READDIR_END;
            return ret;
        }
        child_pi = nova_get_block(sb, pi_addr);*/
        //pos = &tem_sf->list;
        //nova_dbg("%s:list subfile name:%s, pos %llu",__func__, de->name, pos);
		if (prev_de && !dir_emit(ctx, prev_de->name,
			prev_de->name_len, ino, IF2DT(mode))) {
			return 0;
		}
        //prev_child_pi = child_pi;
        prev_de = de;
        ctx->pos = prev_pos;
        prev_pos = pos;
        //nova_dbg("%s:list subfile name:%s, pos id %d",__func__, de->name,f_pos);
        /*type = nova_get_entry_type((void *)de);
        if(type != DAFS_DIR_ENTRY){
            //nova_dbg ("unknown type\n");
            BUG();
            return -EINVAL;
        }*/
        /*
        if(de->file_type == NORMAL_DIRECTORY){
            dir_hn = le64_to_cpu(de->hname);
            update_read_hot(ei, dir_hn);
        }*/
	/*	nova_dbg("pos %lu, type %d, ino %llu, "
			"name %s, namelen %u, rec len %u\n", f_pos,
			de->entry_type, le64_to_cpu(de->ino),
			de->name, de->name_len,
			DAFS_DEF_DENTRY_SIZE);*/

/*
        if(de->ino>0){
            ino = __le64_to_cpu(de->ino);
            //pos = BKDRHash(de->name, de->name_len);
            pos = dir_hn;
            //BUG();
            ret = nova_get_inode_address(sb, ino, &pi_addr, 0);
            //BUG_ON(ret==0);
            if(ret){
				//nova_dbgv("%s: get child inode %lu address "
				//	"failed %d\n", __func__, ino, ret);
                BUG();
				ctx->pos = READDIR_END;
				return ret;
            }
            
            child_pi = nova_get_block(sb, pi_addr);
			//nova_dbgv("ctx: pos %d ino %llu, name %s, "
			//	"name_len %u, de_len %u\n", f_pos,
			//	(u64)ino, de->name, de->name_len,
			//	DAFS_DEF_DENTRY_SIZE);
			if (prev_de &&!dir_emit(ctx, prev_de->name,
				prev_de->name_len, ino,
				IF2DT(le16_to_cpu(prev_child_pi->i_mode)))) {
				//nova_dbg("Here: pos %llu\n", ctx->pos);
				return 0;
			}
            prev_de = de;
            prev_child_pi = child_pi;
           // prev_inode = inode;
        }
        */
        //ctx->pos =pos;
        //n++
    }
	if (prev_de && !dir_emit(ctx, prev_de->name, prev_de->name_len, 
                ino, IF2DT(mode))) {
			//nova_dbg("Here: pos %llu\n", ctx->pos);
			return 0;
	}
    ctx->pos = READDIR_END;
    //nova_dbg("dafs ctx pos is %llx", ctx->pos);
OUT:
	NOVA_END_TIMING(readdir_t, readdir_time);
    //print_time(st);
    //nova_dbg("%s ", __func__);
	//nova_dbg("%s readdir return", __func__);
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
