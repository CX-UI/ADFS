/*************************************************************************
	> File Name: zone.c
	> Author:CX
	> Mail: tianfangmmr@126.com
	> Created Time: 2017年09月14日 星期四 13时20分34秒
 ************************************************************************/

#include <linux/string.h>
#include <linux/list.h>
#include <linux/kthread.h>
#include "nova.h"
#include "nova_def.h"

//static struct zone_ptr *def_zp;
//static struct dzt_ptr *def_dp;

/*
* dafs get dir_zonet_table
* put dir zone table block addresss before journal block
* not decided journal pos yet*/
struct dafs_dzt_block *dafs_get_dzt_block(struct super_block *sb)
{
    //struct nova_sb_info *sbi = NOVA_SB(sb); 
    nova_dbg("dafs_get dzt blk");
    return (struct dafs_dzt_block *)((char *)nova_get_block(sb,
         NOVA_DEF_BLOCK_SIZE_4K));
}


/* 
* make dzt bitmap pointer*/
void make_dzt_ptr(struct super_block *sb, struct dzt_ptr **dzt_p)
{
    struct dafs_dzt_block *dzt_blk;
    struct dzt_ptr *def_dp = (struct dzt_ptr *)kzalloc(sizeof(struct dzt_ptr), GFP_KERNEL);
    //struct dzt_ptr *p;

    nova_dbg("dafs make dzt pointer");
    dzt_blk = dafs_get_dzt_block(sb);

    def_dp->bitmap = dzt_blk->dzt_bitmap;
    def_dp->max = DAFS_DZT_ENTRIES_IN_BLOCK;
    def_dp->dzt_entry = dzt_blk->dzt_entry;
    *dzt_p = def_dp;
    nova_dbg("dafs finish make dzt bitmap pointer");
}

/*
* make zone ptr to use statemap*/
void make_zone_ptr(struct zone_ptr **z_p, struct dafs_zone_entry *z_e)
{
    //struct zone_ptr *p;
    struct zone_ptr *def_zp = (struct zone_ptr *)kzalloc(sizeof(struct zone_ptr), GFP_KERNEL);

    nova_dbg("%s start",__func__);
    def_zp->statemap = z_e->zone_statemap;
    def_zp->zone_max = NR_DENTRY_IN_ZONE * 2;
    def_zp->z_entry = z_e->dentry;
    *z_p = def_zp;
}

/*
* record mean frequency 
* bring reference(&) in
* FREE_BATCH not NR_DENTRY_IN_ZONE for considering number is not allowed more than 1024*/
u32 dafs_rec_mf(struct dzt_entry_info *ei)
{
    //struct rf_entry *rf_e;
    struct dir_info *dir_i;
    struct dir_info *entries[FREE_BATCH];
    u32 nr,i;
    u32 rcount=0;
    u32 mean = 0;
    u64 dir_index = 0;

    nova_dbg("%s start",__func__);
    do{
        nr = radix_tree_gang_lookup(&ei->dir_tree, (void **)entries, dir_index, FREE_BATCH);
        for(i=0;i<nr;i++){
            dir_i = entries[i];	
            dir_index = dir_i->dir_hash;
            rcount += dir_i->r_f;
        }
        dir_index++;
    }while (nr == FREE_BATCH);
    /*
    nr = radix_tree_gang_lookup(&ei->dir_tree, (void **)entries, 0, NR_DENTRY_IN_ZONE);
    for(i=0; i<nr; i++){
        dir_i = entries[i];
        rcount+=(u32)dir_i->r_f;
    }*/

    mean = rcount/(nr);
    return mean;
}

/*
* set dentry state
* return statemap value*/
u8 set_dentry_state(struct dafs_dentry *dafs_de, struct dzt_entry_info *ei)
{
    //struct rf_entry *rf_e;
    struct dir_info *dir_i;
    u8 statement = STATEMAP_COLD;
    int mean;
    //int st_sub = STARDARD_SUBFILE_NUM;
    int rcount;
    int sub_s=0;
    int f_s;
    u32 sub_num;
    u64 hashname;
    

    nova_dbg("%s start",__func__);
    if(dafs_de->file_type==ROOT_DIRECTORY){
        return statement;
    }

    mean = dafs_rec_mf(ei);

    //name_len = le64_to_cpu(dafs_de->fname_len);
    hashname = le64_to_cpu(dafs_de->hname);
    //rf_e = radix_tree_lookup(&ei->rf_root, hashname);
    dir_i = radix_tree_lookup(&ei->dir_tree, hashname);
    rcount = dir_i->r_f;
    //rcount = le64_to_cpu(dafs_de->rcount);
    
    /*check and set frequency state and subfiles state*/
    if(dafs_de->file_type == NORMAL_DIRECTORY ){            
        sub_num = dir_i->sub_num;
        if(sub_num < NR_DIR_FILES)
            sub_s = NUMBER_OF_SUBFILES_FEW;         //not decided,few=1,large=2,none=0
        else 
            sub_s = NUMBER_OF_SUBFILES_LARGE;
        dir_i->sub_s = sub_s;
    }

    if(dir_i->f_s!=DENTRY_FREQUENCY_WRITE)
    {
        if(rcount <= mean){
            f_s = DENTRY_FREQUENCY_COLD;
            //dafs_de->f_s = cpu_to_le64(f_s);
        }else{
            f_s = DENTRY_FREQUENCY_WARM;
            //dafs_de->f_s = cpu_to_le64(f_s);
        }
        dir_i->f_s = f_s;
    } else 
        f_s = DENTRY_FREQUENCY_WRITE;

    nova_dbg("%s dentry %s frequency is %d, average fre is %d", __func__,dafs_de->name, f_s, mean);
    /*sub_s=0 =>is a file, or . ..
    * sub =1, 2 => is NORMAL_DIRECTORY */
    /* sub_s!=0->dir is not empty*/
    if(sub_s){
        if(sub_s==NUMBER_OF_SUBFILES_FEW && f_s!= DENTRY_FREQUENCY_WRITE){

            statement = STATEMAP_COLD;
            dir_i->prio = LEVEL_1;
            //dafs_de->prio = LEVEL_1;

        }else if(sub_s==NUMBER_OF_SUBFILES_LARGE && f_s==DENTRY_FREQUENCY_COLD){
            
            statement = STATEMAP_WARM;
            dir_i->prio = LEVEL_2;
            //dafs_de->prio = LEVEL_2;

        }else if(sub_s==NUMBER_OF_SUBFILES_FEW && f_s==DENTRY_FREQUENCY_WRITE){
            
            statement = STATEMAP_WARM;
            dir_i->prio = LEVEL_2;
            //dafs_de->prio = LEVEL_2;

        }else if(sub_s==NUMBER_OF_SUBFILES_LARGE && f_s==DENTRY_FREQUENCY_WARM){
            
            statement = STATEMAP_HOT;
            dir_i->prio = LEVEL_3;
            //dafs_de->prio = LEVEL_3;

        }else if(sub_s==NUMBER_OF_SUBFILES_LARGE && f_s==DENTRY_FREQUENCY_WRITE){
            statement = STATEMAP_HOT;
            dir_i->prio = LEVEL_4;
            //dafs_DE->prio = LEVEL_4;
        }
    } else {

        if (f_s==DENTRY_FREQUENCY_COLD)
            statement = STATEMAP_COLD;
        else if (f_s==DENTRY_FREQUENCY_WARM)
            statement = STATEMAP_WARM;
        else if (f_s==DENTRY_FREQUENCY_WRITE)
            statement = STATEMAP_HOT;
    }   
    
    return statement;
}

/*get ei from eno pos*/
struct dzt_entry_info *DAFS_GET_EI(struct super_block *sb, u64 eno)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dafs_dzt_block *dzt_blk = dafs_get_dzt_block(sb);
    struct dafs_dzt_entry *dzt_e;
    struct dzt_ptr *dzt_p;
    struct dzt_manager *dzt_m = sbi->dzt_m_info;
    struct dzt_entry_info *ei=NULL;
    u64 hashname;

    nova_dbg("%s start",__func__);
    make_dzt_ptr(sb, &dzt_p);
    
    if(!test_bit_le(eno, dzt_p->bitmap)){
        nova_err(sb, "not found dzt_entry");
        return ERR_PTR(-EINVAL);
    }
    dzt_e = &dzt_blk->dzt_entry[eno];
    hashname = le64_to_cpu(dzt_e->hash_name);
    ei = radix_tree_lookup(&dzt_m->dzt_root, hashname);
    if(!ei){
        nova_err(sb, "not found ei");
        return ERR_PTR(-EINVAL);
    }

    kfree(dzt_p);
    return ei;

}
/*
* set state in statemap for each zone*/
int zone_set_statemap(struct super_block *sb, struct dzt_entry_info *ei)
{
    //struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dafs_zone_entry *ze;
    struct zone_ptr *z_p;
    struct dafs_dentry *dafs_de;
    struct dir_info *dir_i;
    struct dir_info *entries[FREE_BATCH];
    //struct dafs_dzt_entry *dzt_e;
    //struct dzt_entry_info *par_ei;
    u32 bitpos = 0, nr, i, pos;
    //int mean;
    u8 statement;
    u32 id = 0;
    int ret = 0;
    u32 par_eno;
    u64 dir_hash = 0;

    nova_dbg("%s start",__func__);
    ze = (struct dafs_zone_entry *)nova_get_block(sb, ei->dz_addr);
    //par_eno = le64_to_cpu(ze->dz_no);
    //par_ei = DAFS_GET_EI(sb, par_eno);
    //BUG_ON(par_ei==NULL);

    make_zone_ptr(&z_p, ze);
    
    do{
        nr = radix_tree_gang_lookup(&ei->dir_tree, (void **)entries, dir_hash, FREE_BATCH);
        for(i=0;i<nr;i++){
            dir_i = entries[i];	
            pos = dir_i->dir_pos;
            dafs_de = &ze->dentry[pos];
            dir_hash = dir_i->dir_hash;
            statement = set_dentry_state(dafs_de, ei);
            nova_dbg("%s dentry %s statement is %d",__func__, dafs_de->name, statement);
            
            bitpos = pos*2;
            if(statement == STATEMAP_COLD){
                test_and_clear_bit_le(bitpos, (void *)z_p->statemap);
                bitpos++;
                test_and_set_bit_le(bitpos, (void *)z_p->statemap);

            }else if(statement == STATEMAP_WARM){
                test_and_set_bit_le(bitpos, (void *)z_p->statemap);
                bitpos++;
                test_and_clear_bit_le(bitpos, (void *)z_p->statemap);

            }else if(statement == STATEMAP_HOT){
                test_and_set_bit_le(bitpos, (void *)z_p->statemap);
                bitpos++;
                test_and_set_bit_le(bitpos, (void *)z_p->statemap);

            }
        }
        dir_hash++;
    }while (nr == FREE_BATCH);

    /*
    while(bitpos < z_p->zone_max){
        if((!test_bit_le(bitpos, z_p->statemap)) && (!test_bit_le(bitpos+1, z_p->statemap))){
            bitpos+=2;
            id++;

        }else{      
            dafs_de = &ze->dentry[id];

            if(dafs_de->file_type == NORMAL_DIRECTORY){
                statement = set_dentry_state(dafs_de, ei);
            
                if(statement == STATEMAP_COLD){
                    test_and_clear_bit_le(bitpos, (void *)z_p->statemap);
                    bitpos++;
                    test_and_set_bit_le(bitpos, (void *)z_p->statemap);
                    bitpos++;

                }else if(statement == STATEMAP_WARM){
                    test_and_set_bit_le(bitpos, (void *)z_p->statemap);
                    bitpos++;
                    test_and_clear_bit_le(bitpos, (void *)z_p->statemap);
                    bitpos++;

                }else if(statement == STATEMAP_HOT){
                    test_and_set_bit_le(bitpos, (void *)z_p->statemap);
                    bitpos++;
                    test_and_set_bit_le(bitpos, (void *)z_p->statemap);
                    bitpos++;

                }
                id++;

            }
        }    
        
    }*/
    
    kfree(z_p);
    nova_dbg("%s end",__func__);
    return ret;
    
}
/*=================================================== set up system ========================================*/
/*
* dafs get dir_zonet_table
* put dir zone table block addresss before journal block
* not decided journal pos yet*/
/*static inline
struct dafs_dzt_block *dafs_get_dzt_block(struct super_block *sb)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);

    return (struct dafs_dzt_block *)((char *)nova_get_block(sb,
         NOVA_DEF_BLOCK_SIZE_4K));
}*/

/*
* build dzt radix-tree
* 初始化entry_info*/
static struct dzt_entry_info *dafs_build_dzt(struct super_block *sb, struct dafs_dzt_entry \
                     *dafs_dzt_entry)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dzt_entry_info *entry_info;
    struct dzt_manager *dzt_m = sbi->dzt_m_info;

    nova_dbg("dafs start build dzt");
    /*take into acount when to destroy this entry*/
    entry_info = kzalloc(sizeof(struct dzt_entry_info), GFP_KERNEL);  //move dzt entry into DRAM B-tree
    
    if(!entry_info)
        return ERR_PTR(-ENOMEM);

    entry_info->zone_blk_type = DAFS_BLOCK_TYPE_512K; 
    entry_info->root_len = le32_to_cpu(dafs_dzt_entry->root_len);
    entry_info->dzt_eno = le32_to_cpu(dafs_dzt_entry->dzt_eno);
    //entry_info->dz_no = le64_to_cpu(dafs_dzt_entry->dz_no);
    entry_info->dz_addr = le64_to_cpu(dafs_dzt_entry->dz_addr);
    entry_info->hash_name = le64_to_cpu(dafs_dzt_entry->hash_name);
    entry_info->ht_head = le64_to_cpu(dafs_dzt_entry->ht_head);

    //INIT_LIST_HEAD(&entry_info->child_list);

    //dzt_m = kzalloc(sizeof(struct dzt_manager), GFP_KERNEL);

    if(!dzt_m)
        return ERR_PTR(-ENOMEM);
    
    //INIT_RADIX_TREE(&dzt_m->dzt_root, GFP_ATOMIC);

    INIT_RADIX_TREE(&entry_info->dir_tree, GFP_ATOMIC);

    radix_tree_insert(&dzt_m->dzt_root, entry_info->hash_name, entry_info);

    nova_dbg("dafs finish build dzt_e");
    return entry_info;
}

/*
* alloc zone action
* 1.big enough direcotries will becomes a new zone
* 2.hot enough e.g frequently renames & chmod dir will becomes new zone*/
int dafs_alloc_dir_zone(struct super_block *sb, struct dafs_dzt_entry *dzt_e)
{
    //struct nova_sb_info *sbi = NOVA_SB(sb);
    //struct dafs_dzt_entry *dzt_e;
    //struct dzt_entry_info *dzt_ei;
    //struct dzt_manager *dzt_m = sbi->dzt_manager;
    //struct dafs_zone_entry *new_ze;
    //u8 zone_type = dzt_e->zone_blk_type;
    unsigned long blocknr;
    //uint64_t hash_name;
    u64 block;
    //int i;
    int allocated;
    //unsigned long bp;
    int ret = 0;

    nova_dbg("dafs allocate zone blocks");
    allocated = dafs_new_zone_blocks(sb, dzt_e, &blocknr, 1, 1);
    nova_dbg("%s: allocate zone @ 0x%lx\n", __func__,
							blocknr);
    if(allocated != 1 || blocknr == 0)
        return -ENOMEM;

    block = nova_get_block_off(sb, blocknr, DAFS_BLOCK_TYPE_512K);
    
    /*get zone address*/
    dzt_e->dz_addr = cpu_to_le64(block);

    PERSISTENT_BARRIER();
    return ret;
}  

/*
* 2017/09/12
* init dir_zone
* 添加 . ..项
* dafs_de 在create的时候创建的根目录
* 此函数只在初始化根目录的时候有用
* 其他zone不需要初始化直接迁移*/
int dafs_init_dir_zone(struct super_block *sb, struct dzt_entry_info *ei)
{
    //struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dafs_zone_entry *zone_entry;
    struct dafs_dentry *dafs_rde;
    struct zone_ptr *z_p;
    struct dir_info *rdir;
    //u32 bitpos = 0;
    //int i;
    u64 hn;

    nova_dbg("dafs start init dir zones");
    zone_entry = (struct dafs_zone_entry *)nova_get_block(sb, ei->dz_addr);
    nova_dbg("root ze addr is %llu", ei->dz_addr);

    hn = BKDRHash("/",1);
    nova_dbg("the root dir hashname is %llu", hn);

    /*create root directory*/
    dafs_rde = &zone_entry->dentry[0];
    dafs_rde->entry_type = DAFS_DIR_ENTRY;             /*not decided yet*/
    dafs_rde->name_len = 1;
    dafs_rde->file_type = ROOT_DIRECTORY;
    dafs_rde->links_count = 0;
    dafs_rde->mtime = CURRENT_TIME_SEC.tv_sec;
    dafs_rde->isr_sf = 0;
    //dafs_rde->path_len = 1;
    dafs_rde->ino = NOVA_ROOT_INO;      /*not decided*/
    //dafs_rde->par_ino = 0;   /*not decided*/
    dafs_rde->par_pos = 0;
    dafs_rde->size = sb->s_blocksize; /*not decided*/
    dafs_rde->dzt_hn = cpu_to_le64(hn);
    nova_dbg("test root hash name is %llu", le64_to_cpu(dafs_rde->dzt_hn));
    dafs_rde->ext_flag =0;
    //dafs_rde->prio = LEVEL_0;
    //dafs_rde->sub_num = 0;
    //dafs_rde->sub_pos[NR_DENTRY_IN_ZONE]={0};
    memcpy(dafs_rde->name, "/",1);
    dafs_rde->fname_len = 1;
    memcpy(dafs_rde->ful_name.f_name, "/", 1);
    nova_dbg("dafs finish creat root directory");

    record_pos_htable(sb, ei->ht_head, hn, 0, 1);
    rdir = add_dir_info(ei, hn, 0);
    make_zone_ptr(&z_p, zone_entry);
    test_and_clear_bit_le(0, (void *)z_p->statemap);
    test_and_set_bit_le(1, (void *)z_p->statemap);
    zone_entry->dz_no = cpu_to_le32(ei->dzt_eno);

    dafs_append_dir_init_entries(sb, 0, ei, NOVA_ROOT_INO, NOVA_ROOT_INO, "/");

    nova_dbg("dafs finish init dir zones");
    return 0;

}

/*compare dir name and file name,
* then get subfile position*/
int set_sf_pos(struct super_block *sb, struct dzt_entry_info *dzt_ei, \
               struct dir_info *sf_info, int par_pos)
{
    struct dafs_zone_entry *ze;
    struct dafs_dentry *de;
    struct zone_ptr *z_p;
    struct file_p *fp;
    u32 bitpos = 0, filepos = 0, ppos;
    //u64 pathlen; 
    int ret =0;
    //char *s_name;


    ze = (struct dafs_zone_entry *)nova_get_block(sb, dzt_ei->dz_addr);
    make_zone_ptr(&z_p, ze);

    //s_name = kzalloc(DAFS_PATH_LEN*sizeof(char), GFP_ATOMIC);
    //pathlen = strlen(dir);
    while(filepos<NR_DENTRY_IN_ZONE){
        if(test_bit_le(bitpos, (void *)z_p->statemap)){
            de = &ze->dentry[filepos];
            //namelen = de->ful_name->f_namelen;
            if(de->isr_sf==0 ){
                ppos = le32_to_cpu(de->par_pos);
                //memcpy(name, de->ful_name.f_name, pathlen);
                if(par_pos==ppos) {
                    fp = kzalloc(sizeof(struct file_p), GFP_ATOMIC);
                    fp->pos = filepos;
                    list_add_tail(&fp->list, &sf_info->sub_file);
                    sf_info->sub_num++;
                }
            }
            filepos++;
            bitpos++;
            bitpos++;
        }else {
            bitpos ++;
            if(test_bit_le(bitpos, (void *)z_p->statemap)){
                de = &ze->dentry[filepos];
                //namelen = de->ful_name->f_namelen;
                if(de->isr_sf==0){
                    //memcpy(name, de->ful_name.f_name, pathlen);
                    ppos = le32_to_cpu(de->par_pos);
                    if(ppos==par_pos) {
                        fp = kzalloc(sizeof(struct file_p), GFP_ATOMIC);
                        fp->pos = filepos;
                        list_add_tail(&fp->list, &sf_info->sub_file);
                        sf_info->sub_num++;
                    }
                }
            }
            bitpos ++;
            filepos ++;
        }
    }

    kfree(z_p);
    return ret;
}

/* init dir info tree */
int init_dir_info(struct super_block *sb, struct dzt_entry_info *dzt_ei)
{
    struct dafs_zone_entry *ze;
    struct dafs_dentry *de;
    struct dir_info *dir_i;
    struct zone_ptr *zp;
    u32 bitpos = 0, filepos = 0;
    //u64 pathlen;
    int ret = 0;
    //char *path;
    u64 hashname;

    nova_dbg("%s start",__func__);
    ze = (struct dafs_zone_entry *)nova_get_block(sb, dzt_ei->dz_addr);
    make_zone_ptr(&zp, ze);
    //path = kzalloc(DAFS_PATH_LEN*sizeof(char), GFP_KERNEL);
    while(filepos<NR_DENTRY_IN_ZONE){
        if(test_bit_le(bitpos, (void *)zp->statemap)){
            de = &ze->dentry[filepos];
            if(de->file_type==NORMAL_DIRECTORY){
                //pathlen = le64_to_cpu(de->ful_name.f_namelen);
                //memcpy(path, de->ful_name.f_name, pathlen);
                //memcpy(path+pathlen, "/0", 1);
                hashname = le64_to_cpu(de->hname);
                dir_i = kzalloc(sizeof(struct dir_info), GFP_ATOMIC);
                dir_i->r_f = 0;
                dir_i->sub_num = 0;
                dir_i->sub_s =0;
                dir_i->f_s = 0;
                dir_i->prio = 0;
                dir_i->dir_hash = hashname;
                dir_i->dir_pos = filepos;
                INIT_LIST_HEAD(&dir_i->sub_file);
                ret = set_sf_pos(sb, dzt_ei, dir_i, filepos);
                if(ret)
                    return -ENOMEM;
                radix_tree_insert(&dzt_ei->dir_tree, hashname, dir_i);
            }
            bitpos+=2;
            filepos++;
        } else{
            bitpos++;
            if(test_bit_le(bitpos, (void *)zp->statemap)){
                de = &ze->dentry[filepos];
                if(de->file_type==NORMAL_DIRECTORY){
                    //pathlen = le64_to_cpu(de->ful_name.f_namelen);
                    //memcpy(path, de->ful_name.f_name, pathlen);
                    //memcpy(path+pathlen, "/0", 1);
                    hashname = le64_to_cpu(de->hname);
                    dir_i = kzalloc(sizeof(struct dir_info), GFP_ATOMIC);
                    dir_i->r_f = 0;
                    dir_i->sub_num = 0;
                    dir_i->sub_s =0;
                    dir_i->f_s = 0;
                    dir_i->prio = 0;
                    dir_i->dir_hash = hashname;
                    dir_i->dir_pos = filepos;
                    INIT_LIST_HEAD(&dir_i->sub_file);
                    ret = set_sf_pos(sb, dzt_ei, dir_i, filepos);
                    if(ret)
                        return -ENOMEM;
                    radix_tree_insert(&dzt_ei->dir_tree, hashname, dir_i);
                }
            }
            bitpos++;
            filepos++;
        }
    }
    kfree(zp);
    nova_dbg("%s end",__func__);
    return ret;
}

int dafs_init_dzt_block(struct super_block *sb)
{
    struct dafs_dzt_block *dzt_block;
    int allocated;
    unsigned long blocknr;
    u64 block;
   
    nova_dbg("dafs init dzt block");
    dzt_block = dafs_get_dzt_block(sb);
    if(!dzt_block)
        return -EINVAL;
    allocated = dafs_new_dzt_blocks(sb, NOVA_BLOCK_TYPE_4K, &blocknr, 1, 1);
	nova_dbg("%s: allocate log @ 0x%lx\n", __func__, blocknr);
	if (allocated != 1 || blocknr == 0)
		return -ENOSPC; 
    block = nova_get_block_off(sb, blocknr, NOVA_DEF_BLOCK_SIZE_4K);
    dzt_block->dzt_head = cpu_to_le64(block);
    return 0;
}

/*
*build dir zone table for first time run*/
int dafs_build_dzt_block(struct super_block *sb)
{
    //struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dafs_dzt_block *dzt_block;
    struct dzt_entry_info *ei;
    struct dzt_ptr *dzt_p;
    //int allocated;
    //unsigned long blocknr;
    //u64 block;
    char *name = "/"; 
    int ret = 0;
    u64 ht_addr;

    /*init linux root directory '/' 
    * dir zone no is pos in bitmap*/
    dzt_block = dafs_get_dzt_block(sb);
    if(!dzt_block)
        return -EINVAL;
    /*
    allocated = dafs_new_dzt_blocks(sb, NOVA_BLOCK_TYPE_4K, &blocknr, 1, 1);
	nova_dbg("%s: allocate log @ 0x%lx\n", __func__, blocknr);
	if (allocated != 1 || blocknr == 0)
		return -ENOSPC; 
    block = nova_get_block_off(sb, blocknr, NOVA_DEF_BLOCK_SIZE_4K);
    dzt_block->dzt_head = cpu_to_le64(block);
    */

    dzt_block-> dzt_entry[0].zone_blk_type = DAFS_BLOCK_TYPE_512K;
    dzt_block-> dzt_entry[0].root_len = 1;
    dzt_block-> dzt_entry[0].dzt_eno = 0;
    dzt_block-> dzt_entry[0].pdz_addr = 0;
    dzt_block-> dzt_entry[0].rden_pos = 0;
    dzt_block-> dzt_entry[0].hash_name = cpu_to_le64(BKDRHash(name, 1));        

    /*alloc htable zone */
    get_hash_table(sb, 1, &ht_addr);
    dzt_block->dzt_entry[0].ht_head = cpu_to_le64(ht_addr);

    /*alloc zone area
    * get zone addr*/
    dafs_alloc_dir_zone(sb, &dzt_block->dzt_entry[0]);
    
    /*make valid*/
    make_dzt_ptr(sb, &dzt_p);
    test_and_set_bit_le(0, (void *)dzt_p->bitmap);

    /*build radix search tree
    * initialize entry info*/ 
    ei = dafs_build_dzt(sb, &dzt_block->dzt_entry[0]);

    /*init dir_zone*/
    /*append . and .. into new zone*/
    dafs_init_dir_zone(sb, ei);

    /*init rf_entry*/
    //init_rf_entry(sb, ei);
    init_dir_info(sb, ei);
    
    kfree(dzt_p);
    return ret;
}


/*===================================build dzt when start up system ===========================================*/


/*
 * make dzt entry valid*/
void set_dzt_entry_valid(struct super_block *sb, unsigned long bitpos)
{
    //struct dafs_dzt_block *dzt_blk;
    struct dzt_ptr *dzt_p;
    //int ret = 0;

    make_dzt_ptr(sb, &dzt_p);

    kfree(dzt_p);
    test_and_set_bit(bitpos, (void *)dzt_p->bitmap);

}


/*
 * make radix tree by inserting*/
/*
static void make_dzt_tree(struct nova_sb_info *sbi, struct dzt_entry_info *dzt_ei)
{
    struct dzt_entry_info *dzt_entry_info;
    struct dzt_manager *dzt_m = sbi->dzt_m_info;
    //int ret = 0;

    dzt_entry_info = kzalloc(sizeof(struct dzt_entry_info), GFP_KERNEL);
    dzt_entry_info->zone_blk_type = dzt_ei->zone_blk_type;
    dzt_entry_info->root_len = dzt_ei->root_len;
    dzt_entry_info->dzt_eno = dzt_ei->dzt_eno;
    //dzt_entry_info->dz_no = dzt_ei->dz_no;
    dzt_entry_info->dz_addr = dzt_ei->dz_addr;
    dzt_entry_info->hash_name = dzt_ei->hash_name;
    //INIT_RADIX_TREE(&dzt_entry_info->rf_root, GFP_ATOMIC);
    //init_rf_entry(sbi->sb, dzt_entry_info);
    
    //init sub file pos
    INIT_RADIX_TREE(&dzt_entry_info->dir_tree, GFP_ATOMIC);
    init_dir_info(sbi->sb, dzt_entry_info);
    radix_tree_insert(&dzt_m->dzt_root, dzt_entry_info->hash_name, dzt_entry_info);

}*/

/*
 * init dzt tree
 * scant dzt_bit_map and init dzt tree*/
int dafs_init_dzt(struct super_block *sb)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dzt_manager *dzt_m = sbi->dzt_m_info;
    struct dafs_dzt_entry *dzt_entry;
    struct dafs_dzt_block *dzt_blk;
    struct dzt_ptr *dzt_p;
    struct dzt_entry_info *dzt_ei;
    u32 bit_pos = 0;
    int ret = 0;
    //unsigned long max = DAFS_DZT_ENTRIES_IN_BLOCK;

    dzt_blk = dafs_get_dzt_block(sb);

    make_dzt_ptr(sb, &dzt_p);
    /*
    dzt_p->bitmap = dzt_blk->dzt_bitmap;
    dzt_p->max = DAFS_DZT_ENTRIES_IN_BLOCK;
    dzt_p->dzt_entry = dzt_blk->dzt_entry;*/

    while(bit_pos < dzt_p->max){
        if(!test_bit_le(bit_pos, (void *)dzt_p->bitmap)){
            bit_pos++;
            continue;
        }

        dzt_entry = &dzt_p->dzt_entry[bit_pos];
        dzt_ei = kzalloc(sizeof(struct dzt_entry_info), GFP_ATOMIC);

        dzt_ei->root_len = le64_to_cpu(dzt_entry->root_len);
        dzt_ei->zone_blk_type = dzt_entry->zone_blk_type; 
        dzt_ei->dzt_eno = le32_to_cpu(dzt_entry->dzt_eno);
        //dzt_ei->dz_no = le32_to_cpu(dzt_entry->dz_no);
        dzt_ei->dz_addr = le64_to_cpu(dzt_entry->dz_addr);
        dzt_ei->hash_name = le64_to_cpu(dzt_entry->hash_name);

        INIT_RADIX_TREE(&dzt_ei->dir_tree, GFP_ATOMIC);
        ret = init_dir_info(sb, dzt_ei);
        radix_tree_insert(&dzt_m->dzt_root, dzt_ei->hash_name, dzt_ei);

    }

    return ret;
}

/*init read frequency tree*/
/*
int init_rf_entry(struct super_block *sb, struct dzt_entry_info *dzt_ei)
{
    //struct rf_entry *rfe;
    struct dir_info *dir_entry;
    struct ht_ptr *ht_p;
    struct hash_table *ht;
    struct hash_entry *he;
    u64 ht_addr, tail;
    u32 bit_pos = 0;
    int key;

    
    ht_addr = dzt_ei->ht_head;
    if(!ht_addr)
        return 0;
    ht = (struct hash_table *)nova_get_block(sb, ht_addr);
lookup:
    make_ht_ptr(&ht_p,ht);
    rfe = kzalloc(sizeof(struct rf_entry), GFP_KERNEL);
    while(bit_pos < ht_p->hash_max){
        if(test_bit_le(bit_pos, (void *)ht_p->bitmap)){
            he = ht->hash_entry[bit_pos];
            rfe->r_f = 0;
            rfe->hash_name = le64_to_cpu(ht->hd_name);
            radix_tree_insert(&dzt_ei->rf_root, rfe->hash_name, rfe);
            bit_pos++;
        }
        else
            bitpos++;
    }
    tail =le64_to_cpu(ht->hash_tail);
    if(tail){
        ht = (struct hash_table *)nova_get_block(sb, tail);
        bitpos = 0;
        goto lookup;
    }
    return 0;    
}
*/

/*
 * destroy DRAM radix dzt tree*/
int dafs_destroy_dzt(struct nova_sb_info *sbi)
{
    struct dzt_manager *dzt_m = sbi->dzt_m_info;

    /*destroy dzt_entries*/

    /*free dzt_manager*/
    kfree(dzt_m);

    return 0;
}


/*======================================= dzt&zone adaption =================================================*/

/*
*alloc dzt_entry
* 1. append at tail 
* 2. scan bitmap */
u32 alloc_dzt_entry(struct super_block *sb)
{
    //struct nova_sb_info *sbi = NOVA_SB(sb);  
    struct dafs_dzt_block *dzt_blk;
    struct dzt_ptr *dzt_p;
    //unsigned long tail_pos;
    u32 bitpos = 0;
    
    dzt_blk = dafs_get_dzt_block(sb);
    //tail_pos = le64_to_cpu(dzt_blk->dzt_tail_pos);

    make_dzt_ptr(sb, &dzt_p);
    while(bitpos < dzt_p->max){
        if(!test_bit_le(bitpos, (void *)dzt_p->bitmap))
            goto end;
        else
            bitpos++;
    }

    nova_err(sb, "dzt_blk is full");
    return ENOMEM;
end:
    kfree(dzt_p);
    nova_dbg("%s end get pos %d",__func__,bitpos);
    return bitpos;
}

/*
* add dzt entries in DRAM
* used in split*/
struct dzt_entry_info *add_dzt_entry(struct super_block *sb, struct dzt_entry_info *par_dei, u32 sp_id)
{
    //struct nova_sb_info *sbi = NOVA_SB(sb);
    //struct dafs_dzt_entry *new_dzt_e;
    struct dzt_entry_info *new_dzt_ei = (struct dzt_entry_info *)kzalloc(sizeof(struct dzt_entry_info), GFP_KERNEL);
    //struct dzt_manager *dzt_m = sbi->dzt_m_info;
    struct dafs_dentry *dafs_rde;
    struct dafs_zone_entry *par_ze;
    u64 name_len;
    unsigned long eno_pos; 
    int ret;
    u64 de_nlen, phash;
    char *pname, *cur_name, *end = "";

    nova_dbg("%s start",__func__);
    par_ze = (struct dafs_zone_entry *)nova_get_block(sb, par_dei->dz_addr); 

    eno_pos = alloc_dzt_entry(sb);

    if(!eno_pos)
        goto end;             //not decided
    /* modify dzt_eno, dz_log_head, dz_addr */
    

    dafs_rde = &par_ze->dentry[sp_id];
    de_nlen = le64_to_cpu(dafs_rde->fname_len);

    //new_dzt_ei = (struct dzt_entry_info *)kzalloc(sizeof(struct dzt_entry_info), GFP_KERNEL);
    new_dzt_ei->zone_blk_type = DAFS_BLOCK_TYPE_512K;
    new_dzt_ei->dzt_eno = eno_pos;
    new_dzt_ei->pdz_addr = par_dei->dz_addr;
    new_dzt_ei->rden_pos = sp_id;

    if(par_dei->dzt_eno!=0){
        /*not decided*/
        cur_name = kzalloc(sizeof(char)*(de_nlen+1), GFP_ATOMIC);
        /*get ful_name of rde*/
        if(!dafs_rde->ext_flag){
            memcpy(cur_name, dafs_rde->ful_name.f_name, de_nlen);
            memcpy(cur_name+de_nlen, end, 1);
        } else {
            get_ext_name(dafs_rde->ful_name.fn_ext, cur_name);
        }

        name_len = (u64)(par_dei->root_len) + de_nlen;
        pname = kzalloc(sizeof(char *)*(name_len+1), GFP_KERNEL);
        get_zone_path(sb, par_dei, pname, cur_name);
        BUG_ON(strlen(pname)!=name_len);
        phash = BKDRHash(pname, name_len);
        new_dzt_ei->root_len =name_len;
        new_dzt_ei->hash_name = phash;

        kfree(cur_name);
        kfree(pname);
    } else {
        name_len = de_nlen;
        //phash = BKDRHash(dafs_rde->ful_name.f_name, name_len);
        new_dzt_ei->root_len = name_len;
        new_dzt_ei->hash_name = le64_to_cpu(dafs_rde->hname);
    }

    /* DRAM 中新建entry的时候一定是split zone的时候，不需要condition验证*/
    //new_dzt_e = append_dzt_entry(sb, dzt_ei, root_path, SPLIT_ZONE);
    /*build hashtable*/
    get_hash_table(sb, 1, &new_dzt_ei->ht_head);
    BUG_ON(ret!=0);
    //if(!ret)
        //return ERR_PTR(-ENOMEM);

    /*build dir_info_radix tree*/
    INIT_RADIX_TREE(&new_dzt_ei->dir_tree, GFP_ATOMIC);
    //ret = add_rf_entry(new_dzt_ei, phash);
    if(ret)
        return ERR_PTR(-EINVAL);

end:
    //kfree(cur_name);
    nova_dbg("%s end dzt no is %d",__func__, new_dzt_ei->dzt_eno);
    return new_dzt_ei;

}


/*
* append dzt_entry in NVM
* set append condition to decide whether alloc zones*/
struct dafs_dzt_entry *append_dzt_entry(struct super_block *sb, struct dzt_entry_info *dzt_ei)
{
    //struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dafs_dzt_entry *dzt_e;
    struct dafs_dzt_block *dzt_blk;
    u32 en_pos;
    //int ret = 0;

    nova_dbg("%s start",__func__);
    en_pos = dzt_ei->dzt_eno;
    dzt_blk = dafs_get_dzt_block(sb);

    dzt_e = &dzt_blk->dzt_entry[en_pos];

    dzt_e->zone_blk_type = dzt_ei->zone_blk_type;
    dzt_e->root_len = cpu_to_le64(dzt_ei->root_len);
    dzt_e->dzt_eno = cpu_to_le32(dzt_ei->dzt_eno);
    dzt_e->pdz_addr = cpu_to_le64(dzt_ei->pdz_addr);
    dzt_e->rden_pos = cpu_to_le32(dzt_ei->rden_pos);
    //dzt_e->dz_sf = cpu_to_le64(dzt_ei->dz_sf);
    dzt_e->hash_name = cpu_to_le64(dzt_ei->hash_name);

    nova_dbg("%s end",__func__);
    return dzt_e;
}


/*
* delete dzt_entry in DRAM
* not used in inherit
* rdei root dzt_entry_info*/
struct dzt_entry_info *delete_dzt_entry(struct super_block *sb, struct dzt_entry_info *old_rdei)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dzt_manager *dzt_m = sbi->dzt_m_info;
    struct dzt_ptr *dzt_p;
    unsigned long hash_name;
    u32 ch_pos;

    make_dzt_ptr(sb, &dzt_p);
    ch_pos = old_rdei->dzt_eno;
    hash_name = old_rdei->hash_name;
    radix_tree_delete(&dzt_m->dzt_root, hash_name);
    test_and_clear_bit(ch_pos, (void *)dzt_p->bitmap);

    kfree(dzt_p);
    return old_rdei;
}

/*
*copy andd get new zone_dentry 
*递归
* z_p  for make every dentry statemap valid
* new_ze and old_ze for get old dentry and new dentry
* par_de for record sub_file pos 
* ch_no is subfile_id
* ch_pos is the star pos for copy*/
static  void cpy_new_zentry(struct super_block *sb, struct dzt_entry_info *new_ei,\
        struct dzt_entry_info *old_ei, unsigned long old_len,
        int par_pos, struct dir_info *par_f, u32 ch_no, u32 *ch_pos, int isr_sf)
{
    struct dafs_dentry *new_de, *old_de, *par_de;
    struct zone_ptr *new_p, *old_p;
    struct dafs_zone_entry *new_ze, *old_ze;
    struct list_head *head, *this, *next;
    struct dir_info *o_dir, *new_dir;
    struct file_p *new_sf, *old_sf;
    //unsigned long old_len = r_ze->name_len;
    char *name, *fname, *tname, *end = ""; 
    u32 sub_no, np_id;
    //u64 ch_len;
    u32 new_id = *ch_pos;  /* ch_pos initalized as 0*/
    u32 bitpos = 0;
    u64 name_len, nlen;
    u64 hashname;
    //int j;

    nova_dbg("%s start",__func__);
    old_ze = (struct dafs_zone_entry *)nova_get_block(sb, new_ei->pdz_addr);
    new_ze = (struct dafs_zone_entry *)nova_get_block(sb, new_ei->dz_addr);
    make_zone_ptr(&old_p, old_ze);
    make_zone_ptr(&new_p, new_ze);
    nova_dbg("%s new zone %llu, old zone %llu",__func__,new_ei->dz_addr,new_ei->pdz_addr);
    //ch_len = par_de->sub_num;
    //for(i=0;i<ch_len;i++){
        //old_id = le64_to_cpu(ch_no[i]);
    old_de = &old_ze->dentry[ch_no];
    new_de = &new_ze->dentry[new_id];
    name = kzalloc(sizeof(char)*LARGE_NAME_LEN, GFP_ATOMIC);
    BUG_ON(old_de==NULL);

    nova_dbg("%s new zone %llu, old zone %llu, old dentry fname %s, name %s",__func__,new_ei->dz_addr,new_ei->pdz_addr, old_de->ful_name.f_name, old_de->name);
    if(isr_sf==0)
        par_de = &new_ze->dentry[par_pos];

    if(old_de->file_type == NORMAL_FILE){
        new_de->entry_type = old_de->entry_type;
        new_de->name_len = old_de->name_len;
        new_de->file_type = old_de->file_type;
        new_de->links_count = old_de ->links_count;
        new_de->mtime = CURRENT_TIME_SEC.tv_sec;
        new_de->isr_sf = isr_sf;
        new_de->ino = old_de->ino;
        //new_de->par_ino = old_de->par_ino;
        new_de->size = old_de->size;
        //new_de->dzt_hn = old_de->dzt_hn;

        /*set name and ext_flag*/
        if(old_de->ext_flag==1){
            new_de->ext_flag = 1;
            nlen = old_de->name_len;
            get_ext_name(old_de->next, name);
            ext_de_name(sb, old_ei, new_ze, new_p, new_id, nlen, name, 0);
        } else {
            new_de->ext_flag = old_de->ext_flag;
            nlen = old_de->name_len;
            memcpy(name, old_de->name, nlen);
            memcpy(new_de->name, name, nlen);
            new_de->name[nlen] = '\0';
        }

        //memcpy(new_de->name, old_de->name, le64_to_cpu(old_de->name_len)+1);
        name_len = le64_to_cpu(old_de->fname_len) - old_len;
        new_de->fname_len = cpu_to_le64(name_len);
        fname = kzalloc(sizeof(char)*name_len, GFP_ATOMIC);
        tname = kzalloc(sizeof(char)*name_len, GFP_ATOMIC);
        /*get fulname*/
        /*
        if(new_de->ext_flag ==0){
            if(name_len<SMALL_NAME_LEN){
                memcpy(new_de->ful_name->f_name, old_de->ful_name->f_name + old_len, name_len);
                new_de->ful_name->f_name[name_len]="/0";
            } else {
                new_de->ext_flag = 2;
                get_ext_name(old_de->ful_name->fn_ext, fname);
                ext_de_name(sb, old_ei, new_ze, new_p, new_id, name_len, fname, 1);
            }
        } else {
            get_ext_name(old_de->ful_name->fn_ext, fname);
            ext_de_name(sb, old_ei, new_ze, new_p, new_id, name_len, fname, 1);
        }
        */

        /*set par_pos 
        * get fname
        * set ful_name*/
        if(isr_sf==1){
            /*set par_pos*/
            new_de->par_pos = 0;
            /*get fulname*/
            //fname = kzalloc(sizeof(char)*name_len, GFP_ATOMIC);
            /*get fname*/
            memcpy(fname, "/",1);
            memcpy(fname+1,end,1);
            strcat(fname, name);
            /*set ful name*/
            if(new_de->ext_flag ==0){
                if(name_len<SMALL_NAME_LEN){
                    memcpy(new_de->ful_name.f_name, fname, name_len);
                    new_de->ful_name.f_name[name_len]='\0';
                } else {
                    new_de->ext_flag = 2;
                    //get_ext_name(old_de->ful_name.fn_ext, fname);
                    ext_de_name(sb, old_ei, new_ze, new_p, new_id, name_len, fname, 1);
                }
            } else {
                //get_ext_name(old_de->ful_name.fn_ext, fname);
                ext_de_name(sb, old_ei, new_ze, new_p, new_id, name_len, fname, 1);
            }
        } else {
            /*set par_pos and fulname*/
            new_de->par_pos = cpu_to_le32(par_pos);
            new_de->ful_name.f_name[0]='\0';
            /*get ful_name*/
            get_de_name(old_de, old_ze, tname, 1);
            memcpy(fname, tname+old_len, name_len);
            memcpy(fname+name_len, end, 1);

        } 

        /*set this file's pos in its par_de
        * update sub_num*/
        if(isr_sf!=1){
            new_sf = kzalloc(sizeof(struct file_p), GFP_ATOMIC);
            new_sf->pos = new_id;
            list_add_tail(&new_sf->list, &par_f->sub_file);
            par_f->sub_num++;
        }

        /*atomic*/
        bitpos = new_id *2 +1;
        set_bit_le(bitpos, (void *)new_p->statemap);

        /*record pos in hashtable*/
        nova_dbg("%s fulname %s",__func__,fname);
        hashname = BKDRHash(fname, name_len);
        new_de->hname = cpu_to_le64(hashname);
        record_pos_htable(sb, new_ei->ht_head, hashname, new_id, 1);

        /*set old invalid*/
        bitpos = ch_no*2;
        test_and_clear_bit_le(bitpos, (void *)old_p->statemap);
        bitpos++;
        test_and_clear_bit_le(bitpos, (void *)old_p->statemap);
        delete_ext(old_p, old_de);

        /*make invalid in hashtable*/
        //name_len = le64_to_cpu(fname_len);
        hashname = le64_to_cpu(old_de->hname);
        make_invalid_htable(sb, old_ei->ht_head, hashname, 1);

        new_id++;
        *ch_pos = new_id;
        kfree(fname);
        kfree(tname);
    }else if(old_de->file_type == ROOT_DIRECTORY){
        new_de->entry_type = old_de->entry_type;
        new_de->name_len = old_de->name_len;
        //new_de->name_len = old_de->name_len-old_len;
        new_de->file_type = old_de->file_type;
        new_de->links_count = old_de ->links_count;
        new_de->mtime = CURRENT_TIME_SEC.tv_sec;
        new_de->isr_sf = isr_sf;
        //new_de->path_len = old_de->path_len-old_len;
        new_de->ino = old_de->ino;
        //new_de->par_ino = old_de->par_ino;
        new_de->size = old_de->size;
        new_de->dzt_hn = old_de->dzt_hn;
        
        /*set name and ext_flag*/
        if(old_de->ext_flag==1){
            new_de->ext_flag = 1;
            nlen = old_de->name_len;
            get_ext_name(old_de->next, name);
            ext_de_name(sb, old_ei, new_ze, new_p, new_id, nlen, name, 0);
        } else {
            new_de->ext_flag = old_de->ext_flag;
            nlen = old_de->name_len;
            memcpy(name, old_de->name, nlen);
            memcpy(new_de->name, name, nlen);
            new_de->name[nlen] = '\0';
        }
        //memcpy(new_de->name, old_de->name, le64_to_cpu(old_de->name_len)+1);
        name_len = le64_to_cpu(old_de->fname_len) - old_len;
        new_de->fname_len = cpu_to_le64(name_len);
        fname = kzalloc(sizeof(char)*(name_len+1), GFP_ATOMIC);
        tname = kzalloc(sizeof(char)*(name_len+1), GFP_ATOMIC);

        /*set par_pos 
        * get fname
        * set ful_name*/
        if(isr_sf==1){
            /*set par_pos*/
            new_de->par_pos = 0;
            /*get fulname*/
            //fname = kzalloc(sizeof(char)*name_len, GFP_ATOMIC);
            /*get fname*/
            memcpy(fname, "/",1);
            memcpy(fname+1,end,1);
            strcat(fname, name);
            /*set ful name*/
            if(new_de->ext_flag ==0){
                if(name_len<SMALL_NAME_LEN){
                    memcpy(new_de->ful_name.f_name, fname, name_len);
                    new_de->ful_name.f_name[name_len]='\0';
                } else {
                    new_de->ext_flag = 2;
                    //get_ext_name(old_de->ful_name->fn_ext, fname);
                    ext_de_name(sb, old_ei, new_ze, new_p, new_id, name_len, fname, 1);
                }
            } else {
                //get_ext_name(old_de->ful_name.fn_ext, fname);
                ext_de_name(sb, old_ei, new_ze, new_p, new_id, name_len, fname, 1);
            }
        } else {
            /*set par_pos and fulname*/
            new_de->par_pos = cpu_to_le32(par_pos);
            //new_de->ful_name.f_name[0]="/0";

            /*get ful_name
            * and set*/
            if(new_de->ext_flag==0){
                if(name_len<SMALL_NAME_LEN){
                    memcpy(fname, old_de->ful_name.f_name+old_len, name_len);
                    memcpy(fname+name_len, end, 1);
                    memcpy(new_de->ful_name.f_name, fname, name_len+1);
                } else {
                    new_de->ext_flag = 2;
                    //tname = kzalloc(sizeof(char)*name_len, GFP_ATOMIC);
                    get_ext_name(old_de->ful_name.fn_ext, tname);
                    memcpy(fname, tname+old_len, name_len);
                    memcpy(fname+name_len, end, 1);
                    ext_de_name(sb, old_ei, new_ze, new_p, new_id, name_len, fname, 1);
                    //kfree(tname);
                }
            } else {               
                //tname = kzalloc(sizeof(char)*name_len, GFP_ATOMIC);
                get_ext_name(old_de->ful_name.fn_ext, tname);
                memcpy(fname, tname+old_len, name_len);
                memcpy(fname+name_len, end, 1);
                ext_de_name(sb, old_ei, new_ze, new_p, new_id, name_len, fname, 1);
                //kfree(tname);
            }
        } 
        //memcpy(new_de->ful_name->f_name, old_de->ful_name->f_name+old_len, name_len+1);
     
        /*set this file's pos in its par_de*/
        if(!isr_sf){
            new_sf = kzalloc(sizeof(struct file_p), GFP_ATOMIC);
            new_sf->pos = new_id;
            list_add_tail(&new_sf->list, &par_f->sub_file);
            par_f->sub_num++;
        }
        
        bitpos = new_id *2 +1;
        set_bit_le(bitpos, (void *)new_p->statemap);

        /*record pos in hashtable*/
        hashname = BKDRHash(fname, name_len);
        record_pos_htable(sb, new_ei->ht_head, hashname, new_id, 1);

        /*set old invalid*/
        bitpos = ch_no*2;
        test_and_clear_bit_le(bitpos, (void *)old_p->statemap);
        bitpos++;
        test_and_clear_bit_le(bitpos, (void *)old_p->statemap);
        delete_ext(old_p, old_de);

        /*make invalid in hashtable*/
        if(old_de->ext_flag==0){
            name_len = le64_to_cpu(old_de->fname_len);
            memcpy(tname, old_de->ful_name.f_name, name_len);
            memcpy(tname+name_len, end, 1);
        } else {
            name_len = le64_to_cpu(old_de->fname_len);
            get_ext_name(old_de->ful_name.fn_ext, tname);
        }
            
        name_len = le64_to_cpu(old_de->fname_len);
        hashname = BKDRHash(fname, name_len);
        make_invalid_htable(sb, old_ei->ht_head, hashname, 1);

        new_id++;
        *ch_pos = new_id;
        kfree(tname);
        kfree(fname);
    }else if(old_de->file_type == NORMAL_DIRECTORY){
            
        new_de->entry_type = old_de->entry_type;
        new_de->name_len = old_de->name_len;
        //new_de->name_len = old_de->name_len-old_len;
        new_de->file_type = old_de->file_type;
        new_de->links_count = old_de ->links_count;
        new_de->mtime = CURRENT_TIME_SEC.tv_sec;
        new_de->isr_sf = isr_sf;
        new_de->ino = old_de->ino;
        //new_de->par_ino = old_de->par_ino;
        new_de->size = old_de->size;
        
        /*set name and ext_flag*/
        if(old_de->ext_flag==1){
            new_de->ext_flag = 1;
            nlen = old_de->name_len;
            get_ext_name(old_de->next, name);
            ext_de_name(sb, old_ei, new_ze, new_p, new_id, nlen, name, 0);
        } else {
            new_de->ext_flag = old_de->ext_flag;
            nlen = old_de->name_len;
            memcpy(name, old_de->name, nlen);
            memcpy(new_de->name, name, nlen);
            new_de->name[nlen] = '\0';
        }

        //memcpy(new_de->name, old_de->name, le64_to_cpu(old_de->name_len)+1);
        name_len = le64_to_cpu(old_de->fname_len) - old_len;
        new_de->fname_len = cpu_to_le64(name_len);
        fname = kzalloc(sizeof(char)*(name_len+1), GFP_ATOMIC);
        tname = kzalloc(sizeof(char)*(name_len+1), GFP_ATOMIC);
        
        /*set par_pos 
        * get fname
        * set ful_name*/
        if(isr_sf==1){
            /*set par_pos*/
            new_de->par_pos = 0;
            /*get fulname*/
            //fname = kzalloc(sizeof(char)*name_len, GFP_ATOMIC);
            /*get fname*/
            memcpy(fname, "/",1);
            memcpy(fname+1, end,1);
            strcat(fname, name);
            nova_dbg("%s ful name is %s",__func__,fname);
            /*set ful name*/
            if(new_de->ext_flag ==0){
                if(name_len<SMALL_NAME_LEN){
                    memcpy(new_de->ful_name.f_name, fname, name_len);
                    new_de->ful_name.f_name[name_len]='\0';
                } else {
                    new_de->ext_flag = 2;
                    //get_ext_name(old_de->ful_name->fn_ext, fname);
                    ext_de_name(sb, old_ei, new_ze, new_p, new_id, name_len, fname, 1);
                }
            } else {
                //get_ext_name(old_de->ful_name->fn_ext, fname);
                ext_de_name(sb, old_ei, new_ze, new_p, new_id, name_len, fname, 1);
            }
        } else {
            /*set par_pos and fulname*/
            new_de->par_pos = cpu_to_le32(par_pos);
            //new_de->ful_name->f_name[0]="/0";

            /*get ful_name
            * and set*/
            if(new_de->ext_flag==0){
                if(name_len<SMALL_NAME_LEN){
                    memcpy(fname, old_de->ful_name.f_name+old_len, name_len);
                    memcpy(fname+name_len, end, 1);
                    memcpy(new_de->ful_name.f_name, fname, name_len+1);
                } else {
                    new_de->ext_flag = 2;
                    //tname = kzalloc(sizeof(char)*name_len, GFP_ATOMIC);
                    get_ext_name(old_de->ful_name.fn_ext, tname);
                    memcpy(fname, tname+old_len, name_len);
                    memcpy(fname+name_len, end, 1);
                    ext_de_name(sb, old_ei,new_ze, new_p, new_id, name_len, fname, 1);
                    //kfree(tname);
                }
            } else {               
                //tname = kzalloc(sizeof(char)*name_len, GFP_ATOMIC);
                get_ext_name(old_de->ful_name.fn_ext, tname);
                memcpy(fname, tname+old_len, name_len);
                memcpy(fname+name_len, end, 1);
                ext_de_name(sb, old_ei, new_ze, new_p, new_id, name_len, fname, 1);
                //kfree(tname);
            }
        }

        //memcpy(new_de->ful_name->f_name, old_de->ful_name->f_name+old_len, name_len+1);
         
        /*set this file's pos in its par_de*/
        if(!isr_sf){
            new_sf = kzalloc(sizeof(struct file_p), GFP_ATOMIC);
            new_sf->pos = new_id;
            list_add_tail(&new_sf->list, &par_f->sub_file);
            par_f->sub_num++;
        }

        bitpos = new_id *2 +1;
        set_bit_le(bitpos, (void *)new_p->statemap);
            
        /*record pos in hashtable*/
        hashname = BKDRHash(fname, name_len);
        new_de->hname = cpu_to_le64(hashname);
        record_pos_htable(sb, new_ei->ht_head, hashname, new_id, 1);

        /*add dir_info*/
        new_dir = add_dir_info(new_ei, hashname, new_id);
        
        /*set old invalid*/
        bitpos = ch_no*2;
        test_and_clear_bit_le(bitpos, (void *)old_p->statemap);
        bitpos++;
        test_and_clear_bit_le(bitpos, (void *)old_p->statemap);
        delete_ext(old_p, old_de);

        /*make invalid in hashtable*/
        //name_len = le64_to_cpu(old_de->fname_len);
        //o_hn = BKDRHash(old_de->ful_name->f_name, name_len);
        hashname = le64_to_cpu(old_de->hname);
        make_invalid_htable(sb, old_ei->ht_head, hashname, 1);

        /* delete dir_info in old dir_info tree*/
        //delete_dir_info(old_ei, hashname);

        np_id = new_id;
        new_id++;
        kfree(tname);
        kfree(fname);

        o_dir = radix_tree_delete(&old_ei->dir_tree, hashname);
        head = &o_dir->sub_file;
        list_for_each_safe(this, next, head){
            old_sf = list_entry(this, struct file_p, list);
            sub_no = old_sf->pos;
            cpy_new_zentry(sb, new_ei, old_ei, old_len, np_id, new_dir, sub_no, &new_id, 0);
            //new_id ++;
            list_del(&old_sf->list);
            o_dir->sub_num--;
            kfree(old_sf);
        }

        /* delete dir_info in old dir_info tree*/
        kfree(o_dir);
        new_id++;
        *ch_pos = new_id;
       
    }
    
    kfree(name);
    kfree(old_p);
    kfree(new_p);
    nova_dbg("%s end new de name %s",__func__, new_de->name);
}

/*
* migrate zone entries */
int migrate_zone_entry(struct super_block *sb, u32 ch_pos, struct dzt_entry_info *dzt_nei)
{
    //struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dafs_zone_entry *old_ze, *new_ze;
    struct dafs_dentry *dafs_rde;
    struct dzt_entry_info *old_ei;
    struct dir_info *dir_i;
    struct list_head *this, *head, *next; 
    struct file_p *o_sf;
    u64 old_namelen;
    u32 ch_no, start_pos, eno;
    //u32 bitpos = 0;
    //int i = 0;
    //int oi = 0;
    int ret = 0;
    u64 hashname, name_len;
   
    nova_dbg("%s start",__func__);
    start_pos = 0;

    old_ze = (struct dafs_zone_entry *)nova_get_block(sb, dzt_nei->pdz_addr);
    new_ze = (struct dafs_zone_entry *)nova_get_block(sb, dzt_nei->dz_addr);

    dafs_rde = &old_ze->dentry[ch_pos];
    /*clear statemap of new zone*/

    //new_z_e->dz_no = dzt_ne->dzt_eno;
    old_namelen = le64_to_cpu(dafs_rde->fname_len);

    /*record old hashname before change to dzt_hn*/
    hashname = le64_to_cpu(dafs_rde->hname);

    /* modify root dentry 
    * not change rde sub_state*/
    dafs_rde->file_type = ROOT_DIRECTORY;
    dafs_rde->mtime = CURRENT_TIME_SEC.tv_sec;
    //dafs_rde->vroot = 1;
    //dafs_rde->zoon_no = dzt_nei->dzt_eno;
    dafs_rde->dzt_hn = cpu_to_le64(dzt_nei->hash_name);
    
    name_len = le64_to_cpu(dafs_rde->fname_len);

    eno = le64_to_cpu(old_ze->dz_no);
    old_ei = DAFS_GET_EI(sb, eno);

    /*move sub files*/
    dir_i = radix_tree_delete(&old_ei->dir_tree, hashname);
    head = &dir_i->sub_file;
    list_for_each_safe(this, next, head) {
        o_sf = list_entry(this, struct file_p, list);
        ch_no = o_sf->pos;
        cpy_new_zentry(sb, dzt_nei, old_ei, old_namelen, ch_pos, dir_i, ch_no, &start_pos, 1);
        //ch_pos ++;
        nova_dbg("%s next new id %d",__func__,start_pos);
        list_del(&o_sf->list);
        dir_i->sub_num--;
        kfree(o_sf);
    }
   
    kfree(dir_i);
    //kfree(ch_no);
    nova_dbg("%s end",__func__);
    return ret;
}

/*
* allocate and initalize for migrate zone*/
struct dafs_zone_entry *alloc_mi_zone(struct super_block *sb, struct dafs_dzt_entry *n_dzt_e,\
                                     struct dzt_entry_info *n_dzt_ei, unsigned long sp_id)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dafs_zone_entry *new_ze, *par_ze;
    //struct dafs_dentry *dafs_rde;
    struct dzt_manager *dzt_m = sbi->dzt_m_info;
    //struct dzt_entry_info *par_ei;
    struct dzt_ptr *dzt_p;
    unsigned long blocknr;
    //unsigned long par_root_len;
    int allocated;
    u64 block;
    //char root_path[DAFS_PATH_LEN];
    //char *root = root_path;
    //int i;


    nova_dbg("%s start",__func__);
    allocated = dafs_new_zone_blocks(sb, n_dzt_e, &blocknr, 1, 1);
    
    if(allocated != 1 || blocknr == 0)
        return ERR_PTR(-ENOMEM);
    
    block = nova_get_block_off(sb, blocknr, DAFS_BLOCK_TYPE_512K);
    
    /*get zone address*/
    //bp = (unsigned long)nova_get_block(sb, block);
    
    /* add attributes to dzt_entry  */
    n_dzt_e->dz_addr = cpu_to_le64(block);
    n_dzt_ei->dz_addr = block;

    /* init new zone_entry */
    new_ze =(struct dafs_zone_entry *)nova_get_block(sb, n_dzt_ei->dz_addr);

    /* clear statemap of new zone*/
    memset(new_ze->zone_statemap, 0, SIZE_OF_ZONE_BITMAP);

    new_ze->dz_no = cpu_to_le64(n_dzt_ei->dzt_eno);
    /*clear dentry, memset after test null*/

    par_ze = (struct dafs_zone_entry *)nova_get_block(sb, n_dzt_ei->pdz_addr);
    /* migrate*/
    migrate_zone_entry(sb, sp_id, n_dzt_ei);

    /* init new dzt ei dir_info tree*/
    //init_dir_info(sb, n_dzt_ei);
    /*reset statemap*/
    //zone_set_statemap(sb, par_ze);

    make_dzt_ptr(sb, &dzt_p);
    test_and_set_bit_le(n_dzt_ei->dzt_eno, (void *)dzt_p->bitmap);
    //make_dzt_entry_valid(sbi, n_dzt_e->dzt_eno);
    radix_tree_insert(&dzt_m->dzt_root, n_dzt_ei->hash_name, n_dzt_ei);

    kfree(dzt_p);
    nova_dbg("%s end",__func__);
    return new_ze;
}

/*
* split zone 
* s_pos split pos
* sp_id split id*/
int dafs_split_zone(struct super_block *sb, struct dzt_entry_info *par_dzt_ei,\
                    unsigned long sp_id, int SPLIT_TYPE)
{
    struct zone_ptr *z_p;
    struct dafs_dentry *dafs_de;
    struct dafs_dzt_entry *new_dzt_e;
    struct dzt_entry_info *new_dzt_ei;
    struct dafs_zone_entry *new_ze;
    struct dafs_zone_entry *par_ze;
    struct dir_info *dir_i;
    struct dir_info *entries[FREE_BATCH];
    u8 statement;
    u32 nr,i;
    //struct rf_e;
    u32 bitpos = 0;
    int ret = 0;
    u32 ne_id = 0;
    //u32 name_len;
    u64 hashname;
    u64 dir_index = 0;

    nova_dbg("%s start",__func__);
    par_ze = (struct dafs_zone_entry *)nova_get_block(sb, par_dzt_ei->dz_addr);

    if(SPLIT_TYPE == POSITIVE_SPLIT){
        //dafs_rde = &par_ze->dentry[sp_id];
        new_dzt_ei = add_dzt_entry(sb, par_dzt_ei, sp_id);
        new_dzt_e = append_dzt_entry(sb, new_dzt_ei);
        new_ze = alloc_mi_zone(sb, new_dzt_e, new_dzt_ei, sp_id);
        goto ret;

    }else if(SPLIT_TYPE == NEGTIVE_SPLIT){
        //make_zone_ptr(&z_p, par_ze);
        /* could split one time */

        do{
            nr = radix_tree_gang_lookup(&par_dzt_ei->dir_tree, (void **)entries, dir_index, FREE_BATCH);
            for(i=0;i<nr;i++){
                dir_i = entries[i];	
                dir_index = dir_i->dir_hash;
                statement = dir_i->sub_s;
                if(statement == NUMBER_OF_SUBFILES_LARGE){
                    ne_id = dir_i->dir_pos;
                    new_dzt_ei = add_dzt_entry(sb, par_dzt_ei, ne_id);
                    new_dzt_e = append_dzt_entry(sb, new_dzt_ei);
                    new_ze = alloc_mi_zone(sb, new_dzt_e, new_dzt_ei, ne_id);
                    goto ret;
                }
            }
            dir_index++;
        }while (nr == FREE_BATCH);
        /*while(ne_id<NR_DENTRY_IN_ZONE){
            if(test_bit_le(bitpos, (void *)z_p->statemap)){
                bitpos++;
                if(test_bit_le(bitpos, (void *)z_p->statemap)){
                    dafs_de = &par_ze->dentry[ne_id];
                    if(dafs_de->file_type!=NORMAL_DIRECTORY)
                        continue;
                    //name_len = le64_to_cpu(dafs_de->ful_name->f_namelen);
                    hashname = dafs_de->hname;
                    dir_i = radix_tree_lookup(&par_dzt_ei->dir_tree, hashname);
                    if(dir_i->prio==LEVEL_3 || dir_i->prio==LEVEL_4){
                        new_dzt_ei = add_dzt_entry(sb, par_dzt_ei, ne_id);
                        new_dzt_e = append_dzt_entry(sb, new_dzt_ei);
                        new_ze = alloc_mi_zone(sb, new_dzt_e, new_dzt_ei, ne_id);
                        goto ret;

                    }else{
                        bitpos++;
                        ne_id++;
                    }
                }else{
                    bitpos++;
                    ne_id++;
                }
            }
            else{
                bitpos+=2;
                ne_id++;
            }
        }*/
        
        //kfree(z_p);
    }

ret:
    //kfree(z_p);
    /*reset statemap in detail*/
    nova_dbg("%s end new dzt no %d",__func__, new_dzt_ei->dzt_eno);
    return ret;
}

/*find invalid dentry in zone
* start pos = start dentry id*/
u32 find_invalid_id(struct super_block *sb, struct dzt_entry_info *dzt_ei, \
                    struct zone_ptr *z_p, u32 start_id)
{
    //struct dafs_dentry *dafs_de;
    u32 bitpos = start_id*2;
    //u32 eno;
    while(bitpos<z_p->zone_max){
        if(test_bit_le(bitpos, (void *)z_p->statemap)){
            bitpos+=2;
            start_id++;
            continue;
        }else{
            bitpos++;
            if(test_bit_le(bitpos, (void *)z_p->statemap)){
                bitpos++;
                start_id++;
            }else{
                break;
            }
        }
    }

    /* if not enough entries, negtive split*/
    if(bitpos == NR_DENTRY_IN_ZONE){
        dafs_split_zone(sb, dzt_ei, 0 , NEGTIVE_SPLIT);
    }

    return start_id;
}

/*merge*/
int __merge_dentry(struct super_block *sb, struct dzt_entry_info *cur_ei, unsigned long cur_pos,\
                  int rde_pos)
{
    struct dafs_zone_entry *des_ze, *cur_ze;
    struct zone_ptr *par_p, *cur_p;
    struct dafs_dentry *cur_de, *des_de, *rde;
    struct dzt_entry_info *par_ei;
    //struct rf_entry *old_rf, *new_rf;
    struct dir_info *old_idir, *new_idir, *par_idir;
    struct file_p *fp, *o_sub; 
    struct list_head *this, *head;
    u32 bitpos = 0, fpos = 0,eno, pos; 
    u64 plen, old_hn, rnamelen, hn;
    int ret =0;
    char *name;
    char *tem;
    char *rname;
    unsigned short nlen;

    des_ze = (struct dafs_zone_entry *)nova_get_block(sb, cur_ei->pdz_addr);
    cur_ze = (struct dafs_zone_entry *)nova_get_block(sb, cur_ei->dz_addr);

    eno = le64_to_cpu(des_ze->dz_no);
    par_ei = DAFS_GET_EI(sb, eno);

    rde = &des_ze->dentry[rde_pos];
    cur_de = &cur_ze->dentry[cur_pos];
    //memcpy(name, rde->ful_name->f_name, le64_to_cpu(rde->ful_name->f_namelen));
    rnamelen = le64_to_cpu(rde->fname_len);
    rname = kzalloc(sizeof(char)*(rnamelen+1), GFP_ATOMIC);
    tem = kzalloc(sizeof(char)*(rnamelen+1), GFP_ATOMIC);
    get_de_name(rde, des_ze, rname, 1);
    //memcpy(name, rde->ful_name->f_name, rnamelen);
    //memcpy(name+rnamelen, "\0", 1);
    memcpy(tem, rname, rnamelen);

    make_zone_ptr(&par_p, des_ze);
    make_zone_ptr(&cur_p, cur_ze);
    if(cur_de->file_type != NORMAL_DIRECTORY){
        fpos = find_invalid_id(sb, par_ei,par_p, fpos);
        des_de = &des_ze->dentry[fpos];
        des_de->entry_type = cur_de->entry_type;
        des_de->name_len = cur_de->name_len;
        des_de->file_type = cur_de->file_type;
        des_de->links_count = cur_de->links_count;
        des_de->mtime = CURRENT_TIME_SEC.tv_sec;
        des_de->isr_sf = 0;
        des_de->ino = cur_de->ino;
        des_de->size = cur_de->size;

        /*set name and ext_flag*/
        name = kzalloc((cur_de->name_len)*sizeof(char), GFP_ATOMIC);
        if(cur_de->ext_flag==1){
            des_de->ext_flag = 1;
            nlen = cur_de->name_len;
            get_ext_name(cur_de->next, name);
            ext_de_name(sb, par_ei, des_ze, par_p, fpos, nlen, name, 0);
        } else {
            des_de->ext_flag = cur_de->ext_flag;
            nlen = cur_de->name_len;
            memcpy(name, cur_de->name, nlen);
            memcpy(des_de->name, name, nlen);
            des_de->name[nlen] = '\0';
        }

        //memcpy(des_de->name, cur_de->name, le64_to_cpu(cur_de->name_len));
        plen = le64_to_cpu(cur_de->fname_len)+rnamelen;
        des_de->fname_len = cpu_to_le64(plen);
        /*get fulname*/
        strcat(rname, "/");
        strcat(rname, name);

        /*record pos in hash table*/
        //eno = le64_to_cpu(par_ze->dz_no);
        //par_ei = DAFS_GET_EI(sb, eno);
        hn = BKDRHash(rname, plen);
        record_pos_htable(sb, par_ei->ht_head, hn,fpos, 1);

        /*set fulname and dzt_hn or hnama*/
        if(des_de->file_type == NORMAL_FILE){
            des_de->ful_name.f_name[0]='\0';
            des_de->par_pos = cpu_to_le32(rde_pos); 

            des_de->hname = cpu_to_le64(hn);
        } else {
            if(des_de->ext_flag==0){
                if(plen<SMALL_NAME_LEN){
                    memcpy(des_de->ful_name.f_name, rname, plen);
                    des_de->ful_name.f_name[0] = '\0';
                } else {
                    des_de->ext_flag = 2;
                    ext_de_name(sb, par_ei, des_ze, par_p, fpos, plen, rname, 1);
                }
            } else {
                ext_de_name(sb, par_ei, des_ze, par_p, fpos, plen, rname, 1);
            }
            des_de->dzt_hn = cur_de->dzt_hn;
        }

        /*状态表*/
        bitpos = fpos*2+1;
        test_and_set_bit_le(bitpos, (void *)par_p->statemap);
        
        bitpos = cur_pos*2;
        test_and_clear_bit_le(bitpos, (void *)cur_p->statemap);
        bitpos++;
        test_and_clear_bit_le(bitpos, (void *)cur_p->statemap);
        delete_ext(cur_p, cur_de);


        /*update par dir info entry*/
        old_hn = BKDRHash(tem, rnamelen);
        par_idir = radix_tree_lookup(&par_ei->dir_tree, old_hn);
        par_idir->sub_num++;
        fp = kzalloc(sizeof(struct file_p), GFP_ATOMIC);
        fp->pos = cur_pos;
        list_add_tail(&fp->list, &par_idir->sub_file);
    } else {
        /*migrate dir*/  
        fpos = find_invalid_id(sb, par_ei, par_p, fpos);
        des_de = &des_ze->dentry[fpos];
        des_de->entry_type = cur_de->entry_type;
        des_de->name_len = cur_de->name_len;
        des_de->file_type = cur_de->file_type;
        des_de->links_count = cur_de->links_count;
        des_de->mtime = CURRENT_TIME_SEC.tv_sec;
        des_de->isr_sf = 0;
        des_de->ino = cur_de->ino;
        //des_de->par_ino = cur_de->par_ino;
        des_de->size = cur_de->size;
        //des_de->dzt_hn = cur_de->dzt_hn;
        
        /*set name and ext_flag*/
        name = kzalloc((cur_de->name_len)*sizeof(char), GFP_ATOMIC);
        if(cur_de->ext_flag==1){
            des_de->ext_flag = 1;
            nlen = cur_de->name_len;
            get_ext_name(cur_de->next, name);
            ext_de_name(sb, par_ei, des_ze, par_p, fpos, nlen, name, 0);
        } else {
            des_de->ext_flag = cur_de->ext_flag;
            nlen = cur_de->name_len;
            memcpy(name, cur_de->name, nlen);
            memcpy(des_de->name, name, nlen);
            des_de->name[nlen] = '\0';
        }

        //memcpy(des_de->name, cur_de->name, le64_to_cpu(cur_de->name_len));
        plen = le64_to_cpu(cur_de->fname_len)+rnamelen;
        des_de->fname_len = cpu_to_le64(plen);
        strcat(rname, "/");
        strcat(rname, name);
        /*set ful name*/
        if(des_de->ext_flag==0){
            if(plen<SMALL_NAME_LEN){
                memcpy(des_de->ful_name.f_name, rname, plen);
                des_de->ful_name.f_name[0] = '\0';
            } else {
                des_de->ext_flag = 2;
                ext_de_name(sb, par_ei, des_ze, par_p, fpos, plen, rname, 1);
            }
        } else {
            ext_de_name(sb, par_ei, des_ze, par_p, fpos, plen, rname, 1);
        }

        /*set par_pos*/
        des_de->par_pos = cpu_to_le32(rde_pos);
        //memcpy(des_de->ful_name->f_name, rname, plen);

        /*record pos in hash table*/
        //eno = le64_to_cpu(par_ze->dz_no);
        //par_ei = DAFS_GET_EI(sb, eno);
        hn = BKDRHash(rname, plen);
        record_pos_htable(sb, par_ei->ht_head, hn,fpos, 1);

        /*set hname*/
        des_de->hname = cpu_to_le64(hn);

        /*热度, subfile etc*/
        old_hn = le64_to_cpu(cur_de->hname);
        old_idir = radix_tree_lookup(&cur_ei->dir_tree, old_hn);
        new_idir = kzalloc(sizeof(struct dir_info),GFP_KERNEL);
        new_idir->r_f = old_idir->r_f;
        new_idir->sub_num = old_idir->sub_num;
        new_idir->sub_s = old_idir->sub_s;
        new_idir->f_s = 0;
        new_idir->prio = LEVEL_0;
        new_idir->dir_hash = hn;
        new_idir->dir_pos = fpos;
        INIT_LIST_HEAD(&new_idir->sub_file);
        radix_tree_insert(&par_ei->dir_tree, hn, new_idir); 

        /*状态表*/
        bitpos = fpos*2+1;
        test_and_set_bit_le(bitpos, (void *)par_p->statemap);
        
        bitpos = cur_pos*2;
        test_and_clear_bit_le(bitpos, (void *)cur_p->statemap);
        bitpos++;
        test_and_clear_bit_le(bitpos, (void *)cur_p->statemap);
        delete_ext(cur_p, cur_de);

        /*update par dir info entry*/
        old_hn = BKDRHash(tem, rnamelen);
        par_idir = radix_tree_lookup(&par_ei->dir_tree, old_hn);
        par_idir->sub_num++;
        fp = kzalloc(sizeof(struct file_p), GFP_ATOMIC);
        fp->pos = fpos;
        list_add_tail(&fp->list, &par_idir->sub_file);
        
        /*sub files*/
        //f_num = le64_to_cpu(cur_de->sub_num);
        head = &old_idir->sub_file;
        list_for_each(this, head){
            o_sub = list_entry(this, struct file_p, list);
            pos = o_sub->pos;
            ret = __merge_dentry(sb, cur_ei, pos, fpos);
        }
    }
    kfree(rname);
    kfree(tem);
    kfree(name);
    kfree(par_p);
    kfree(cur_p);
    return ret;
}

/*find root par_dir hn*/
u64 get_par_hn(const char *name, u64 hash_name, u64 *len)
{
    char *ph, *tem, *pname, *end = "";
    u64 namelen, temlen, hn;
    
    namelen = strlen(name);
    ph = kzalloc(namelen*sizeof(char), GFP_KERNEL);
    pname = kzalloc(namelen*sizeof(char),GFP_KERNEL);
    memcpy(pname, name, namelen);
    tem = strrchr(name, '/');
    temlen = namelen - strlen(tem);
    //memset(ph, 0, temlen);
    //memcpy(ph, name, temlen);
    //hn = BKDRHash(ph, temlen);
    while(!temlen) {
        memcpy(ph, pname, temlen);
        memcpy(ph+temlen, end, 1);
        hn = BKDRHash(ph, temlen);
        if(hn == hash_name){
            hn = BKDRHash(pname, namelen);
            *len = namelen;
            break;
        }

        memcpy(pname, ph, temlen+1);
        namelen = strlen(pname);
        tem = strrchr(pname, '/');
        temlen = namelen - strlen(tem);
    }
    
    kfree(pname);
    kfree(ph);

    if(temlen ==0)
        return -EINVAL;

    return hn;
}


int isROOT_Child(u64 plen, u64 nlen )
{
    int i = plen - nlen;
    if(i==1)
        return 1;
    else 
        return 0;
}
/*cpy merge
* 向上回溯*/
int merge_dentry(struct super_block *sb, struct dzt_entry_info *cur_ei)
{
    struct zone_ptr *cur_p;
    struct dafs_zone_entry *par_ze;
    struct dafs_zone_entry *cur_ze;
    //struct hash_table *cur_ht, *par_ht;
    //struct hash_entry *he;
    struct dafs_dentry *de, *rde;
    //struct dzt_entry_info *des_ei;
    u32 bitpos, filepos = 0, rde_pos;
    //char *name = kzalloc(DAFS_PATH_LEN*sizeof(char), GFP_KERNEL);
    //char *tem;
    //u64 nlen,plen,hn, len;
    //unsigned long pos;
    int ret = 0;
    //char *end = "";

    cur_ze = (struct dafs_zone_entry *)nova_get_block(sb, cur_ei->dz_addr);
    par_ze = (struct dafs_zone_entry *)nova_get_block(sb, cur_ei->pdz_addr);

    rde_pos = cur_ei->rden_pos;
    rde = &par_ze->dentry[rde_pos];
    
    make_zone_ptr(&cur_p, cur_ze);

    bitpos = 0;
    while(bitpos<cur_p->zone_max){
        if(test_bit_le(bitpos, (void *)cur_p->statemap)){
            de = &cur_ze->dentry[filepos];
            //plen = le64_to_cpu(de->ful_name->f_namelen);
            //nlen = le64_to_cpu(de->name_len);
            if(de->isr_sf==1){
                __merge_dentry(sb, cur_ei, filepos, rde_pos);
            }
            /*
            memcpy(name, de->ful_name->f_name, nlen);
            memcpy(name+plen, end, 1);
            hn = BKDRHash(name, nlen);
            
            if(hn == cur_ei->hash_name){
                pos = filepos;
                __merge_dentry(sb, cur_ei, pos, rde);
            } else {
                hn = get_par_hn(name, cur_ei->hash_name, &len);
                if(!hn)
                    nova_err(sb, "can not find par dir");
                ret = lookup_in_hashtable(sb, cur_ei->ht_head, hn, 1, &pos);
                __merge_dentry(sb, cur_ei, pos, rde);

            }*/
            bitpos++;
        }else {
            bitpos++;
            if(test_bit_le(bitpos, (void *)cur_p->statemap)){
                de = &cur_ze->dentry[filepos];
                //plen = le64_to_cpu(de->ful_name->f_namelen);
                //nlen = le64_to_cpu(de->name_len);
                if(de->isr_sf==1){
                    __merge_dentry(sb, cur_ei, filepos, rde_pos);
                }
            }
            //bitpos++;
        }

        filepos++;
    }
    

    kfree(cur_p);
    return ret;
}


/*inherit*/
int __inherit_dentry(struct super_block *sb, struct dzt_entry_info *cur_ei, unsigned long cur_pos,\
                  u32 rde_pos)
{
    struct dafs_zone_entry *des_ze, *cur_ze;
    struct zone_ptr *par_p, *cur_p;
    struct dafs_dentry *cur_de, *des_de, *rde;
    struct dzt_entry_info *par_ei;
    //struct rf_entry *old_rf, *new_rf;
    struct dir_info *old_idir, *new_idir, *par_idir;
    struct file_p *fp, *o_sub; 
    struct list_head *this, *head;
    u32 bitpos = 0, fpos = 0, eno, pos;
    u64 plen, hn, old_hn, par_hn, phash, rnamelen;
    int ret =0;
    char *name;
    char *pname;
    char *rname;
    u64 nlen, zlen;

    des_ze = (struct dafs_zone_entry *)nova_get_block(sb, cur_ei->pdz_addr);
    cur_ze = (struct dafs_zone_entry *)nova_get_block(sb, cur_ei->dz_addr);
        
    eno = le64_to_cpu(des_ze->dz_no);
    par_ei = DAFS_GET_EI(sb, eno);

    rde = &des_ze->dentry[rde_pos];
    cur_de = &cur_ze->dentry[cur_pos];
    //memcpy(name, rde->ful_name.f_name, le64_to_cpu(rde->ful_name.f_namelen));
    rnamelen = le64_to_cpu(rde->fname_len);
    rname = kzalloc(sizeof(char)*(rnamelen+1), GFP_ATOMIC);
    //tem = kzalloc(sizeof(char)*(rnamelen+1), GFP_ATOMIC);
    get_de_name(rde, des_ze, rname, 1);
    /*update par dir info entry*/
    par_hn = BKDRHash(rname, rnamelen);
    par_idir = radix_tree_lookup(&par_ei->dir_tree, par_hn);

    make_zone_ptr(&par_p, des_ze);
    make_zone_ptr(&cur_p, cur_ze);
    if(cur_de->file_type == NORMAL_FILE || cur_de->file_type == ROOT_DIRECTORY){
        fpos = find_invalid_id(sb, par_ei, par_p, fpos);
        des_de = &des_ze->dentry[fpos];
        des_de->entry_type = cur_de->entry_type;
        des_de->name_len = cur_de->name_len;
        des_de->file_type = cur_de->file_type;
        des_de->links_count = cur_de->links_count;
        des_de->mtime = CURRENT_TIME_SEC.tv_sec;
        des_de->isr_sf = 0;
        des_de->ino = cur_de->ino;
        //des_de->par_ino = cur_de->par_ino;
        des_de->size = cur_de->size;
        //des_de->dzt_hn = cur_de->dzt_hn;

        /*set name and ext_flag*/
        name = kzalloc((cur_de->name_len)*sizeof(char), GFP_ATOMIC);
        if(cur_de->ext_flag==1){
            des_de->ext_flag = 1;
            nlen = cur_de->name_len;
            get_ext_name(cur_de->next, name);
            ext_de_name(sb, par_ei, des_ze, par_p, cur_pos, nlen, name, 0);
        } else {
            des_de->ext_flag = cur_de->ext_flag;
            nlen = cur_de->name_len;
            memcpy(name, cur_de->name, nlen);
            memcpy(des_de->name, name, nlen);
            des_de->name[nlen] = '\0';
        }

        //memcpy(des_de->name, cur_de->name, le64_to_cpu(cur_de->name_len));
        plen = le64_to_cpu(cur_de->fname_len)+rnamelen;
        des_de->fname_len = cpu_to_le64(plen);
        /*get fulname*/
        strcat(rname, "/");
        strcat(rname, name);
        //memcpy(des_de->ful_name.f_name, rname, plen);

        /*record pos in hash table*/
        //eno = le64_to_cpu(par_ze->dz_no);
        //par_ei = DAFS_GET_EI(sb, eno);
        hn = BKDRHash(rname, plen);
        record_pos_htable(sb, par_ei->ht_head, hn, fpos, 1);

        /*set fulname and dzt_hn or hnama
        * delete in hashtable*/
        if(des_de->file_type == NORMAL_FILE){
            des_de->ful_name.f_name[0]='\0';
            des_de->par_pos = cpu_to_le32(rde_pos); 

            des_de->hname = cpu_to_le64(hn);

            /*delete in  previous hashtable*/
            old_hn = le64_to_cpu(cur_de->hname);
            make_invalid_htable(sb, cur_ei->ht_head, old_hn, 1);

        } else {
            if(des_de->ext_flag==0){
                if(plen<SMALL_NAME_LEN){
                    memcpy(des_de->ful_name.f_name, rname, plen);
                    des_de->ful_name.f_name[0] = '\0';
                } else {
                    des_de->ext_flag = 2;
                    ext_de_name(sb, par_ei, des_ze, par_p, fpos, plen, rname, 1);
                }
            } else {
                ext_de_name(sb, par_ei, des_ze, par_p, fpos, plen, rname, 1);
            }
            des_de->dzt_hn = cur_de->dzt_hn;
            /*delete in previous hashtable*/
            pname = kzalloc(sizeof(char)*plen,GFP_ATOMIC);
            get_de_name(cur_de, cur_ze, pname,1);
            old_hn = BKDRHash(pname, strlen(pname));
            make_invalid_htable(sb, cur_ei->ht_head, old_hn, 1);
            kfree(pname);
        }

        
        /*状态表*/
        bitpos = fpos*2+1;
        test_and_set_bit_le(bitpos, (void *)par_p->statemap);
        
        bitpos = cur_pos*2;
        test_and_clear_bit_le(bitpos, (void *)cur_p->statemap);
        bitpos++;
        test_and_clear_bit_le(bitpos, (void *)cur_p->statemap);
        delete_ext(cur_p, cur_de);


        /*update par dir info entry*/
        //old_hn = BKDRHash(tem, rnamelen);
        //par_idir = radix_tree_lookup(&par_ei->dir_tree, old_hn);
        par_idir->sub_num++;
        fp = kzalloc(sizeof(struct file_p), GFP_ATOMIC);
        fp->pos = cur_pos;
        list_add_tail(&fp->list, &par_idir->sub_file);
    } else if (cur_de->file_type == NORMAL_DIRECTORY){
        /*migrate dir*/  
        fpos = find_invalid_id(sb, par_ei, par_p, fpos);
        des_de = &des_ze->dentry[fpos];
        des_de->entry_type = cur_de->entry_type;
        des_de->name_len = cur_de->name_len;
        des_de->file_type = cur_de->file_type;
        des_de->links_count = cur_de->links_count;
        des_de->mtime = CURRENT_TIME_SEC.tv_sec;
        des_de->isr_sf = 0;
        des_de->ino = cur_de->ino;
        //des_de->par_ino = cur_de->par_ino;
        des_de->size = cur_de->size;
        //des_de->dzt_hn = cur_de->dzt_hn;
        
        /*set name and ext_flag*/
        name = kzalloc((cur_de->name_len)*sizeof(char), GFP_ATOMIC);
        if(cur_de->ext_flag==1){
            des_de->ext_flag = 1;
            nlen = cur_de->name_len;
            get_ext_name(cur_de->next, name);
            ext_de_name(sb, par_ei, des_ze, par_p, fpos, nlen, name, 0);
        } else {
            des_de->ext_flag = cur_de->ext_flag;
            nlen = cur_de->name_len;
            memcpy(name, cur_de->name, nlen);
            memcpy(des_de->name, name, nlen);
            des_de->name[nlen] = '\0';
        }

        //memcpy(des_de->name, cur_de->name, le64_to_cpu(cur_de->name_len));
        plen = le64_to_cpu(cur_de->fname_len)+rnamelen;
        des_de->fname_len = cpu_to_le64(plen);
        strcat(rname, "/");
        strcat(rname, name);
        /*set ful name*/
        if(des_de->ext_flag==0){
            if(plen<SMALL_NAME_LEN){
                memcpy(des_de->ful_name.f_name, rname, plen);
                des_de->ful_name.f_name[plen] = '\0';
            } else {
                des_de->ext_flag = 2;
                ext_de_name(sb, par_ei, des_ze, par_p, fpos, plen, rname, 1);
            }
        } else {
            ext_de_name(sb, par_ei, des_ze, par_p, fpos, plen, rname, 1);
        }

        /*set par_pos*/
        des_de->par_pos = cpu_to_le32(rde_pos);
        //memcpy(des_de->ful_name.f_name, rname, plen);

        /*record pos in hash table*/
        //eno = le64_to_cpu(par_ze->dz_no);
        //par_ei = DAFS_GET_EI(sb, eno);
        hn = BKDRHash(rname, plen);
        record_pos_htable(sb, par_ei->ht_head, hn, fpos, 1);

        /*set hname*/
        des_de->hname = cpu_to_le64(hn);

        /*热度, subfile etc*/
        old_hn = le64_to_cpu(cur_de->hname);
        old_idir = radix_tree_lookup(&cur_ei->dir_tree, old_hn);
        new_idir = kzalloc(sizeof(struct dir_info),GFP_KERNEL);
        new_idir->r_f = old_idir->r_f;
        new_idir->sub_num = old_idir->sub_num;
        new_idir->sub_s = old_idir->sub_s;
        new_idir->f_s = 0;
        new_idir->prio = LEVEL_0;
        new_idir->dir_hash = hn;
        new_idir->dir_pos = fpos;
        INIT_LIST_HEAD(&new_idir->sub_file);
        radix_tree_insert(&par_ei->dir_tree, hn, new_idir); 

        /*delete in hashtable*/
        make_invalid_htable(sb, cur_ei->ht_head, old_hn, 1);

        /*状态表*/
        bitpos = fpos*2+1;
        test_and_set_bit_le(bitpos, (void *)par_p->statemap);
        
        bitpos = cur_pos*2;
        test_and_clear_bit_le(bitpos, (void *)cur_p->statemap);
        bitpos++;
        test_and_clear_bit_le(bitpos, (void *)cur_p->statemap);
        delete_ext(cur_p, cur_de);

        /*update par dir info entry*/
        //old_hn = BKDRHash(tem, rnamelen);
        //par_idir = radix_tree_lookup(&par_ei->dir_tree, old_hn);
        par_idir->sub_num++;
        fp = kzalloc(sizeof(struct file_p), GFP_ATOMIC);
        fp->pos = fpos;
        list_add_tail(&fp->list, &par_idir->sub_file);
        
        /*sub files*/
        //f_num = le64_to_cpu(cur_de->sub_num);
        head = &old_idir->sub_file;
        list_for_each(this, head){
            o_sub = list_entry(this, struct file_p, list);
            pos = o_sub->pos;
            ret = __inherit_dentry(sb, cur_ei, pos, fpos);
        }

        /*delete_dir_info*/
        delete_dir_info(cur_ei, old_hn);

    } else {
        fpos = find_invalid_id(sb, par_ei, par_p, fpos);
        des_de = &des_ze->dentry[fpos];
        des_de->entry_type = cur_de->entry_type;
        des_de->name_len = cur_de->name_len;
        des_de->file_type = ROOT_DIRECTORY;
        des_de->links_count = cur_de->links_count;
        des_de->mtime = CURRENT_TIME_SEC.tv_sec;
        des_de->isr_sf = 0;
        des_de->ino = cur_de->ino;
        des_de->size = cur_de->size;
        /*set name and ext_flag*/
        name = kzalloc((cur_de->name_len)*sizeof(char), GFP_ATOMIC);
        if(cur_de->ext_flag==1){
            des_de->ext_flag = 1;
            nlen = cur_de->name_len;
            get_ext_name(cur_de->next, name);
            ext_de_name(sb, par_ei, des_ze, par_p, fpos, nlen, name, 0);
        } else {
            des_de->ext_flag = cur_de->ext_flag;
            nlen = cur_de->name_len;
            memcpy(name, cur_de->name, nlen);
            memcpy(des_de->name, name, nlen);
            des_de->name[nlen] = '\0';
        }
        plen = le64_to_cpu(cur_de->fname_len)+rnamelen;
        des_de->fname_len = cpu_to_le64(plen);
        strcat(rname, "/");
        strcat(rname, name);
        /*set ful name*/
        if(des_de->ext_flag==0){
            if(plen<SMALL_NAME_LEN){
                memcpy(des_de->ful_name.f_name, rname, plen);
                des_de->ful_name.f_name[0] = '\0';
            } else {
                des_de->ext_flag = 2;
                ext_de_name(sb, par_ei, des_ze, par_p, fpos, plen, rname, 1);
            }
        } else {
            ext_de_name(sb, par_ei, des_ze, par_p, fpos, plen, rname, 1);
        }

        /*set par_pos*/
        des_de->par_pos = cpu_to_le32(rde_pos);
        //memcpy(des_de->ful_name.f_name, rname, plen);
        //
        
        /*record pos in hash table*/
        //eno = le64_to_cpu(par_ze->dz_no);
        //par_ei = DAFS_GET_EI(sb, eno);
        hn = BKDRHash(rname, plen);
        record_pos_htable(sb, par_ei->ht_head, hn,fpos, 1);

        /*update cur_ei*/
        cur_ei->rden_pos = cpu_to_le32(fpos);

        if(par_ei->dzt_eno !=1){
            zlen = par_ei->root_len + plen;
            pname = kzalloc(sizeof(char)*(zlen+1), GFP_ATOMIC);
            get_zone_path(sb, par_ei, pname, rname);
            phash = BKDRHash(pname, zlen);
            cur_ei->root_len = zlen;
            cur_ei->hash_name = phash;
            kfree(pname);
        } else {
            cur_ei->root_len = plen;
            phash = hn;
            cur_ei->hash_name = phash;
        }
        
        /*set dzt_hn*/
        des_de->dzt_hn = cpu_to_le64(phash);

        /*delete old dir*/
        old_hn = le64_to_cpu(cur_de->hname);
        //old_idir = radix_tree_delete(&cur_ei->dir_tree, old_hn);
        delete_dir_info(cur_ei, old_hn);

        /*delete in hashtable*/
        make_invalid_htable(sb, cur_ei->ht_head, old_hn, 1);
        
        /*状态表 set and clear*/
        bitpos = fpos*2+1;
        test_and_set_bit_le(bitpos, (void *)par_p->statemap);
        
        bitpos = cur_pos*2;
        test_and_clear_bit_le(bitpos, (void *)cur_p->statemap);
        bitpos++;
        test_and_clear_bit_le(bitpos, (void *)cur_p->statemap);
        delete_ext(cur_p, cur_de);

        /*update par dir info entry*/
        //old_hn = BKDRHash(tem, rnamelen);
        //par_idir = radix_tree_lookup(&par_ei->dir_tree, old_hn);
        par_idir->sub_num++;
        fp = kzalloc(sizeof(struct file_p), GFP_ATOMIC);
        fp->pos = fpos;
        list_add_tail(&fp->list, &par_idir->sub_file);
        
    }
    kfree(rname);
    //kfree(tem);
    kfree(name);
    kfree(par_p);
    kfree(cur_p);
    return ret;
}


/*inherit dentry
* make inherit dir invalid*/
void inherit_dentry(struct super_block *sb, struct dzt_entry_info *cur_ei)
{
    struct dafs_zone_entry *cur_ze;
    struct dafs_dentry *de;
    struct zone_ptr *cur_p;
    //char *iname, *name, *tem, *end;
    //u64 namelen, phlen;
    u32 bitpos = 0, rde_pos, filepos=0;
    //int re;

    cur_ze = (struct dafs_zone_entry *)nova_get_block(sb, cur_ei->dz_addr);
    rde_pos = cur_ei->rden_pos;
    //rde = &par_ze->dentry[rde_pos];

    make_zone_ptr(&cur_p, cur_ze);

    //name = kzalloc(DAFS_PATH_LEN*sizeof(char), GFP_ATOMIC);
    //tem = kzalloc((namelen+1)*sizeof(char),GFP_ATOMIC);

    while(bitpos<cur_p->zone_max){
        if(test_bit_le(bitpos, (void *)cur_p->statemap)) {
            de = &cur_ze->dentry[filepos];
            if(de->isr_sf==1)
                __inherit_dentry(sb, cur_ei, filepos, rde_pos);
            bitpos++;
        } else {
            bitpos++;
            if(test_bit_le(bitpos, (void *)cur_p->statemap)){
                de = &cur_ze->dentry[filepos];
                if(de->isr_sf==1) 
                    __inherit_dentry(sb, cur_ei, filepos, rde_pos);
            }
        }
        filepos++;
        /*
        if(test_bit_le(bitpos, (void *)z_p->statemap)){
            de = &cur_ze->dentry[filepos];
            plen = de->ful_name.f_namelen;
            nlen = plen - le64_to_cpu(de->name_len); 
            memcpy(name, de->ful_name.f_name, nlen);
            memcpy(name+plen, end, 1);
            if(plen!=namelen ){
                memcpy(tem, name, namelen);
                re = strcmp(tem,iname);
                if(re){
                    hn = BKDRHash(name, nlen);
                    if(hn == cur_ei->hash_name){
                        pos = filepos;
                        __inherit_dentry(sb, cur_ei, pos, rde);
                    } else {
                        hn = get_par_hn(name, cur_ei->hash_name, &len);
                        if(!hn)
                            nova_err(sb, "can not find par dir");
                        ret = lookup_in_hashtable(sb, cur_ei->ht_head, hn,1, &pos);
                        __inherit_dentry(sb, cur_ei, pos, rde);
                    }
                }
            }
        }
        bitpos++;
        filepos++;
        */
    }
    //kfree(iname);
    //kfree(tem);
    kfree(cur_p);

}



/*====================================== self adaption strategy==============================================*/

/*
*2017/09/12
* merge zone
* 1.small zone or cold zone will merge together
* 2.subdirectory has more files will take place of parent dir to be root dir**/
int dafs_merge_zone(struct super_block *sb, struct dzt_entry_info *cur_rdei)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dzt_manager *dzt_m = sbi->dzt_m_info;
    struct dafs_dentry *dafs_orde;
    struct dafs_zone_entry *par_ze, *cur_ze;
    //struct hash_table *ht;
    struct dzt_entry_info *par_ei; 
    //struct zone_ptr *src_p, *des_p;
    struct dzt_ptr *dzt_p;
    u32 ch_pos, or_pos, eno;
    //struct dir_info *dir_sf;
    u64 tail, hash_name, root_hash;
    char *rname;
    u64 rlen;

    cur_ze = (struct dafs_zone_entry *)nova_get_block(sb, cur_rdei->dz_addr);

    /*delete entry info
    * delete dzt on nvm*/
    hash_name = cur_rdei->hash_name;
    radix_tree_delete(&dzt_m->dzt_root, hash_name);
    make_dzt_ptr(sb, &dzt_p);
    ch_pos = cur_rdei->dzt_eno;
    test_and_clear_bit_le(ch_pos, (void *)dzt_p->bitmap);

    /* find and modify old_root dentry*/
    par_ze = (struct dafs_zone_entry *)nova_get_block(sb, cur_rdei->pdz_addr);
    or_pos = cur_rdei->rden_pos;
    dafs_orde = &par_ze->dentry[or_pos];
    dafs_orde->file_type = NORMAL_DIRECTORY;
    dafs_orde->mtime = CURRENT_TIME_SEC.tv_sec;
    //dafs_orde->vroot = 0;
    //dafs_orde->dzt_hn = 0;

    /*add dir_info*/
    //dir_sf = kzalloc(sizeof(struct dir_info), GFP_ATOMIC);
    rlen = le64_to_cpu(dafs_orde->fname_len);
    rname = kzalloc(sizeof(char)*(rlen+1), GFP_ATOMIC);
    get_de_name(dafs_orde, par_ze, rname, 1);
    root_hash = BKDRHash(rname, rlen);
    dafs_orde->hname = cpu_to_le64(root_hash);
    
    /*add root dir info*/
    eno = le64_to_cpu(par_ze->dz_no);
    par_ei = DAFS_GET_EI(sb , eno);
    add_dir_info(par_ei, root_hash, or_pos);

    /*merge, cur_rdei is not used*/
    merge_dentry(sb, cur_rdei);
    
    /*delete dir tree*/
    delete_dir_tree(cur_rdei);

    /* kfree redi
     * free hash table
     * free zone
    *  */

    tail = le64_to_cpu(cur_rdei->ht_head);
    free_htable(sb, tail, 1);
    dafs_free_zone_blocks(sb, cur_rdei, cur_rdei->dz_addr >> PAGE_SHIFT, 1);
    kfree(cur_rdei);
    
    kfree(rname);
    kfree(dzt_p);
    return 0;

}

/*
 * inherit zone
 * when parent is not stranger than childs 
 * nr_pos >> new root pos
 * or_pos >> old root pos*/
int dafs_inh_zone(struct super_block *sb, struct dzt_entry_info *cur_rdei, u32 nr_pos)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dzt_manager *dzt_m = sbi->dzt_m_info;
    struct dafs_zone_entry *par_ze, *cur_ze;
    struct dafs_dentry *dafs_orde, *dafs_nrde;
    struct dzt_entry_info *par_ei;
    struct dzt_ptr *dzt_p;
    //struct dir_info *dir_sf;
    //struct zone_ptr *cz_p;
    u64 hash_name;
    u32 ch_pos, or_pos, eno;
    char *rname;
    u64 rlen;
    u64 root_hash;

    cur_ze = (struct dafs_zone_entry *)nova_get_block(sb, cur_rdei->dz_addr);

    /*delete eni from radix tree*/
    make_dzt_ptr(sb, &dzt_p);
    ch_pos = cur_rdei->dzt_eno;
    hash_name = cur_rdei->hash_name;
    radix_tree_delete(&dzt_m->dzt_root, hash_name);
    test_and_clear_bit(ch_pos, (void *)dzt_p->bitmap);

    /*find old root dentry and modify*/
    par_ze = (struct dafs_zone_entry *)nova_get_block(sb, cur_rdei->pdz_addr);
    or_pos = cur_rdei->rden_pos;
    dafs_orde = &par_ze->dentry[or_pos];
    dafs_orde->file_type = NORMAL_DIRECTORY;
    dafs_orde->mtime = CURRENT_TIME_SEC.tv_sec;
    //dafs_orde->vroot = 0;
    //dafs_orde->dzt_hn = 0;
    
    /*add dir_info*/
    //dir_sf = kzalloc(sizeof(struct dir_info), GFP_ATOMIC);
    rlen = le64_to_cpu(dafs_orde->fname_len);
    rname = kzalloc(sizeof(char)*(rlen+1), GFP_ATOMIC);
    get_de_name(dafs_orde, par_ze, rname, 1);
    root_hash = BKDRHash(rname, rlen);
    dafs_orde->hname = cpu_to_le64(root_hash);
    
    /*add root dir info*/
    eno = le64_to_cpu(par_ze->dz_no);
    par_ei = DAFS_GET_EI(sb , eno);
    add_dir_info(par_ei, root_hash, or_pos);

    /*modify new root dentry, atomic finished*/
    dafs_nrde = &cur_ze->dentry[nr_pos];
    dafs_nrde->file_type = INHE_ROOT_DIRECTORY;

    /*inherit*/
    inherit_dentry(sb, cur_rdei);

    /* insert cur_rdei and make dirty*/
    radix_tree_insert(&dzt_m->dzt_root, cur_rdei->hash_name, cur_rdei);
    radix_tree_tag_set(&dzt_m->dzt_root, cur_rdei->hash_name, 1);

    /* make valid*/
    test_and_set_bit_le(ch_pos, (void *)dzt_p->bitmap);
    kfree(rname);
    kfree(dzt_p);
    return 0;
}

/*
* check zones
* 1. positive split
* 2. negtive split
* 3. merge
* 4. inherit*/
int dafs_check_zones(struct super_block *sb, struct dzt_entry_info *dzt_ei)
{
    //struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dafs_zone_entry *z_e;
    struct zone_ptr *z_p;
    struct dafs_dentry *dafs_de;
    struct dir_info *dir;
    unsigned long bitpos = 0;
    uint64_t prio = 0;
    u32 hot_num = 0, cold_num = 0, warm_num = 0, id = 0;
    //u32 cd_no = 0;          /**/
    //int hd = 0;                /* counter for positive split*/
    //u32 hd_no[NR_DENTRY_IN_ZONE];          /* hot dentry NO, not decided how many */
    u32 hd_no[FREE_BATCH];    /*not more 1024 has no warning*/
    int ret = 0;
    u32 sp_id = 0;      /* impossible for pos_0 */
    int i;
    u32 inh_id = 0;
    u64 zf_num = 0, sub_s, hashname;  /*record zone valid sub_files num*/

    nova_dbg("%s start",__func__);
    z_e = (struct dafs_zone_entry *)nova_get_block(sb, dzt_ei->dz_addr);
    make_zone_ptr(&z_p, z_e);

    BUG_ON(z_e==NULL);
    while(id < NR_DENTRY_IN_ZONE){
        if((!test_bit_le(bitpos, (void *)z_p->statemap))){
            bitpos++;
            if(!test_bit_le(bitpos, (void *)z_p->statemap)){
                bitpos++;
                id++;
            }else{
                bitpos++;
                cold_num++;
                id++;
                zf_num++;
            }

        } else {
            bitpos++;
            if(!test_bit_le(bitpos, (void *)z_p->statemap)){
                bitpos++;
                warm_num++;
                id++;
            }else{
                bitpos++;
                if(hot_num <= FREE_BATCH){
                    hd_no[hot_num] = id;
                    hot_num++;
                    id++;
                }
            }
            zf_num++;
        }
    }

    nova_dbg("%s zone file num is %llu",__func__, zf_num);
    /*judge zone sub_num state*/
    if(zf_num < NR_ZONE_FILES )
        sub_s = NUMBER_OF_ZONE_SUBFILES_FEW;
    else
        sub_s = NUMBER_OF_ZONE_SUBFILES_LARGE;

    if(warm_num == 0 && hot_num ==1 && dzt_ei->dzt_eno!=0){
        //if(sub_s!= NUMBER_OF_SUBFILES_LARGE)
            inh_id = hd_no[0];
            BUG();
            dafs_inh_zone(sb, dzt_ei, inh_id);
            goto RET;
    
    } else if(hot_num == 0){
        if(sub_s ==NUMBER_OF_ZONE_SUBFILES_FEW && dzt_ei->dzt_eno!=0){
            nova_dbg("%s merge zone no %d",__func__,dzt_ei->dzt_eno);
            BUG();
            dafs_merge_zone(sb, dzt_ei);
            goto RET;
        }
        /*else if(sub_s == NUMBER_OF_ZONE_SUBFILES_LARGE){
            BUG();
            dafs_split_zone(sb, dzt_ei, 0, NEGTIVE_SPLIT);
        }*/
    }else if(hot_num!=0){
        for(i=0;i<hot_num;i++){
            sp_id = hd_no[i];
            dafs_de = &z_e->dentry[sp_id];
            if(dafs_de->file_type!=NORMAL_DIRECTORY)
                continue;
            hashname = le64_to_cpu(dafs_de->hname);
            dir = radix_tree_lookup(&dzt_ei->dir_tree, hashname);
            prio = dir->prio;
            if(prio == LEVEL_4){
                BUG();
                dafs_split_zone(sb, dzt_ei,sp_id, POSITIVE_SPLIT);  
                /*每次只分裂一次,避免子和父文件夹冲突*/
                goto RET;
            }
        }
        if(prio == LEVEL_3){
            //BUG();
            dafs_split_zone(sb, dzt_ei, sp_id, POSITIVE_SPLIT); 
            /*每次只分裂一次,避免子和父文件夹冲突 */
            goto RET;
        }
    } else if(sub_s == NUMBER_OF_ZONE_SUBFILES_LARGE){
        //BUG();
        dafs_split_zone(sb, dzt_ei,0, NEGTIVE_SPLIT);
    }

RET:
    kfree(z_p);
    nova_dbg("%s end",__func__);
    return ret;
}


/*==============================================free zone======================================================*/
void free_zone_area(struct super_block *sb, struct dzt_entry_info *dzt_ei)
{
    //struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dzt_ptr *dzt_p;
    u64 tail;
    u32 eno;
    //struct hash_table *ht;

    /*make dzt invalid*/
    eno = dzt_ei->dzt_eno;
    make_dzt_ptr(sb, &dzt_p);
    test_and_clear_bit_le(eno, (void *)dzt_p->bitmap);

    /*delete dir tree*/
    delete_dir_tree(dzt_ei);

    /* kfree redi
     * free hash table
     * free zone
    *  */

    tail = le64_to_cpu(dzt_ei->ht_head);
    free_htable(sb, tail, 1);
    dafs_free_zone_blocks(sb, dzt_ei, dzt_ei->dz_addr >> PAGE_SHIFT, 1);
    kfree(dzt_ei);
    kfree(dzt_p);
}

/*=================================================check zone thread======================================*/
/*initialize thread*/
int check_thread_func(void *data)
{
    struct super_block *sb = data;
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dzt_entry_info *ei;
    struct dzt_manager *dzt_m = sbi->dzt_m_info;
    struct dzt_entry_info *dzt_eis[FREE_BATCH];
    int nr=0, i;
    int time_count = 0;
    int ret = 0;
    u64 ei_index = 0;

    nova_dbg("%s start",__func__);
    BUG_ON(sbi==NULL);
    BUG_ON(dzt_m==NULL);
    do{
        set_current_state(TASK_INTERRUPTIBLE);
        schedule_timeout_interruptible(msecs_to_jiffies(CHECK_ZONES_SLEEP_TIME));
        //dzt_m = sbi->dzt_m_info;
        //BUG_ON(dzt_m==NULL);
        do{
            nr = radix_tree_gang_lookup(&dzt_m->dzt_root, (void **)dzt_eis, ei_index, FREE_BATCH);
            BUG_ON(nr==0);
            nova_dbg("%s check dzt num is %d", __func__, nr);
            for(i=0; i<nr; i++) {
                ei = dzt_eis[i];
                ei_index = ei->hash_name;
                ret = zone_set_statemap(sb, ei);
                if(ret)
                    return -EINVAL;
                ret = dafs_check_zones(sb, ei);
                if(ret)
                    return -EINVAL;
            }
            ei_index ++;
        }while(nr==FREE_BATCH);
        ei_index=0;
        /*nr = radix_tree_gang_lookup(&dzt_m->dzt_root, (void **)dzt_eis, 0, DAFS_DZT_ENTRIES_IN_BLOCK);
        nova_dbg("%s check dzt num is %d", __func__, nr);
        for(i=0; i<nr; i++) {
            ei = dzt_eis[i];
            ret = zone_set_statemap(sb, ei);
            if(ret)
                return -EINVAL;
            ret = dafs_check_zones(sb, ei);
            if(ret)
                return -EINVAL;
        }*/
    }while(!kthread_should_stop());
    return time_count;
}

/*start kthread*/
int start_cz_thread(struct super_block *sb)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct zone_kthread *check_thread;
    int err = 0;

    nova_dbg("%s start",__func__);
    BUG_ON(sbi==NULL);
    //sbi->check_thread = NULL;
    /*initialize zone check thread*/
    check_thread = kzalloc(sizeof(struct zone_kthread), GFP_KERNEL);
    if(!check_thread){
        nova_dbg("%s malloc failed",__func__);
        return -ENOMEM;
    }

    init_waitqueue_head(&(check_thread->wait_queue_head));
    //check_thread->zone_task = kthread_create(check_thread_func, sb, "DAFS_CHECK_ZONE");
    //kthread_bind(check_thread->zone_task, 1);
    check_thread->zone_task = kthread_run(check_thread_func, sb, "DAFS_CHECK_ZONE");
    nova_dbg("%s fill task",__func__);
    sbi->check_thread = check_thread;
    
    if(IS_ERR(check_thread->zone_task)){
        nova_dbg("%s thread do not match",__func__);
        err = PTR_ERR(check_thread->zone_task);
        goto free_check;
    }

    //wake_up_process(check_thread->zone_task);

    //nova_dbg("%s fill task end",__func__);
    //sbi->check_thread = check_thread;

    return 0;

free_check:
    kfree(check_thread);
    return err;
}

/*stop check zones thread*/
int stop_cz_thread(struct super_block *sb)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);

    nova_dbg("%s start",__func__);
    if(sbi->check_thread) {
        kthread_stop(sbi->check_thread->zone_task);
        kfree(sbi->check_thread);
        sbi->check_thread = NULL;
    }
    return 0;
}

/*=======================================dzt delete && flush=========================================*/
/*delete dzt tree*/


/*delete dir info tree*/


/*flush dirtry dzt_ei back to nvm*/
int dzt_flush_dirty(struct super_block *sb)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dzt_manager *dzt_m = sbi->dzt_m_info;
    struct dafs_dzt_entry *dzt_entry;
    struct dafs_dzt_block *dzt_blk;
    struct dzt_entry_info *entries[FREE_BATCH];
    struct dzt_entry_info *ei;
    int nr, i;
    u32 eno;
    u64 ei_index = 0;

    dzt_blk = (struct dafs_dzt_block *)dafs_get_dzt_block(sb);
    do {
        nr = radix_tree_gang_lookup_tag(&dzt_m->dzt_root, (void **)entries, ei_index, FREE_BATCH, 1);
        for(i=0; i<nr; i++) {
            ei = entries[i];
            ei_index = ei->hash_name;
            eno = ei->dzt_eno;
            dzt_entry = &dzt_blk->dzt_entry[eno];
            dzt_entry->zone_blk_type = ei->zone_blk_type;
            dzt_entry->rden_pos = cpu_to_le32(ei->rden_pos);
            dzt_entry->root_len = cpu_to_le64(ei->root_len);
            dzt_entry->dz_addr = cpu_to_le64(ei->dz_addr);
            dzt_entry->ht_head = cpu_to_le64(ei->ht_head);
            dzt_entry->pdz_addr = cpu_to_le64(ei->pdz_addr);
            dzt_entry->hash_name = cpu_to_le64(ei->hash_name);
        }
        ei_index ++;
    } while(nr==FREE_BATCH); 
    return 0;
}
/*======================================build system=========================================================*/
/*build zone
 * first time set up fs*/
int dafs_build_zone(struct super_block *sb)
{
   dafs_build_dzt_block(sb);
   //make_dzt_ptr(sb);
   return 0;
}
/*init zone
 * use in remount
 * init system in dram*/
int dafs_init_zone(struct super_block *sb)
{
    //struct dentry *root = sb->s_root;
    int ret = 0;
    ret = dafs_init_dzt(sb);
    return ret;
}
