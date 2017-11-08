/*************************************************************************
	> File Name: zone.c
	> Author:CX
	> Mail: tianfangmmr@126.com
	> Created Time: 2017年09月14日 星期四 13时20分34秒
 ************************************************************************/

#include <stdio.h>
//#include <linux/slab.h>
#include <linux/string.h>
#include "nova.h"
#include "nova_def.h"


/*=================================================== set up system ========================================*/
/*
* dafs get dir_zonet_table
* put dir zone table block addresss before journal block
* not decided journal pos yet*/
static inline
struct dafs_dzt_block *dafs_get_dzt_block(struct super_block *sb)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);

    return (struct dafs_dzt_block *)((char *)nova_get_block(sb,
         NOVA_DEF_BLOCK_SIZE_4K));
}

/*
*build dir zone table for first time run*/
int dafs_build_dzt_block(struct super_block *sb)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dafs_dzt_block *dzt_block;
    struct dzt_ptr * dzt_p;
    char *name = '/'; 
    int ret = 0;

    /*init linux root directory '/' 
    * dir zone no is pos in bitmap*/
    dzt_block = dafs_get_dzt_block(sbi);

    dzt_block-> dzt_entry[0].zone_blk_type = DAFS_BLOCK_TYPE_512K;
    dzt_block-> dzt_entry[0].root_len = 1;
    dzt_block-> dzt_entry[0].dzt_eno = 0;
    //dzt_block-> dzt_entry[0].dz_no = 0;
    //dzt_block-> dzt_entry[0].dz_addr = ROOT_ZONE_ADDR;            //not decided yet
    dzt_block-> dzt_entry[0].pdz_addr = NULL;
    dzt_block-> dzt_entry[0].rden_pos = NULL;
    dzt_block-> dzt_entry[0].hash_name = cpu_to_le64(BKDRHash(name, 1));        
    dzt_block-> dzt_entry[0].child_dzt_eno = NULL;            // init NULL not decided yet
    // dzt_block-> dzt_entry[0].path_name = "/";    
    //dzt_block->dzt_bitmap[0] = (1 << 0) | (1 << 1); 

    /*alloc zone area
    * get zone addr*/
    dafs_alloc_dir_zone(sbi, dzt_block->dzt_entry[0]);
    
    /*make valid*/
    make_dzt_ptr(sbi, &dzt_p);
    set_dzt_entry_valid(sbi, 0); 

    /*init dir_zone*/
    /*append . and .. into new zone*/
    dafs_init_dir_zone(sbi, dzt_block->dzt_entry[0]);
    
    /*build radix search tree
    * initialize entry info*/ 
    dafs_build_dzt(sbi, dzt_block->dzt_entry[0]);

    return ret;
}

/*
* 2017/09/12
* init dir_zone
* 添加 . ..项
* dafs_de 在create的时候创建的根目录
* 此函数只在初始化根目录的时候有用
* 其他zone不需要初始化直接迁移*/
int dafs_init_dir_zone(struct super_block *sb, struct dafs_dzt_entry *dzt_e)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dafs_zone_entry *zone_entry;
    struct dafs_dentry *dafs_rde;
    struct zone_ptr *z_p;
    unsigned long bitpos = 0;
    int i;

    /*create root directory*/
    dafs_rde->entry_type = DAFS_DIR_ENTRY;             /*not decided yet*/
    dafs_rde->name_len = 1;
    dafs_rde->file_type = ROOT_DIRECTORY;
    dafs_rde->links_count = 0;
    dafs_rde->mtime = CURRENT_TIME_SEC.tv_sec;
    dafs_rde->vroot = 1;
    dafs_rde->path_len = 1;
    dafs_rde->ino = 0;      /*not decided*/
    dafs_rde->par_ino = 0;   /*not decided*/
    dafs_rde->size = DENTRY_SIZE; /*not decided*/
    dafs_rde->zone_no = dzt_e->dzt_eno;
    dafs_rde->prio = LEVEL_0;
    dafs_rde->d_f = 0;
    dafs_rde->sub_s = NULL;
    dafs_rde->f_s = NULL;
    dafs_rde->sub_num = 0;
    dafs_rde->name = "/";

    //zone_entry->zone_blk_type = DAFS_BLOCK_TYPE_512K;         /* not decided */
    //zone_entry->root_len = dzt_e-> root_len;
    //zone_entry->log_head = NULL;               /*not decided*/
    zone_entry->dz_no = dzt_e->dzt_eno;
    //zone_entry->dz_sf = 0;
    //zone_entry->dz_size = DAFS_DEF_ZONE_SIZE;        /*default size is 512K*/
    zone_entry->root_path = "/";

    /*sub  file "."*/
    zone_entry->dentry[0].entry_type = DAFS_DIR_ENTRY;      /*not decided */
    zone_entry->dentry[0].name_len = 1;
    zone_entry->dentry[0].links_count = 1;
    zone_entry->dentry[0].mtime = CURRENT_TIME_SEC.tv_sec;
    zone_entry->dentry[0].vroot = 0;
    zone_entry->dentry[0].path_len = 1;         //besides file name length and root dir
    zone_entry->dentry[0].size = DAFS_DEF_ZONE_ENTRY_SIZE;      //not decided
    zone_entry->dentry[0].zone_no = dzt_e->dzt_eno;          //not decided
    //zone_entry->dentry[0].subpos = NULL;
    //zone_entry->dentry[0].path = "/";         /*not decided*/
    zone_entry->dentry[0].name = ".";

    /*sub file ".."*/
    zone_entry->dentry[1].entry_type = DAFS_DIR_ENTRY;      /*default file type*/
    zone_entry->dentry[1].name_len = 2;
    zone_entry->dentry[1].links_count = 2;
    zone_entry->dentry[1].mtime = CURRENT_TIME_SEC.tv_sec;
    zone_entry->dentry[1].vroot = 0;
    zone_entry->dentry[1].path_len = 1;         //besides file name length and root dir, not decided
    zone_entry->dentry[1].ino = dafs_de->par_ino;
    zone_entry->dentry[1].size = DAFS_DEF_ZONE_ENTRY_SIZE;
    zone_entry->dentry[1].zone_no = NULL;          //not decided
    //zone_entry->dentry[1].subpos = NULL;
    //zone_entry->dentry[1].path = NULL;
    zone_entry->dentry[1].name = "..";

    make_zone_ptr(&z_p, zone_entry);
    /*change 2-bitmap*/
    for(i=0;i<2;i++){
        if(!test_bit_le(bit_pos, z_p->statemap))
             set_bit(bit_pos++, z_p->statemap);
        else{
            clear_bit_le(bit_pos, z_p->statemap);
            set_bit_le(bit_pos++, z_p->statemap);
        }
    }
}

/*
* make zone ptr to use statemap*/
static inline void make_zone_ptr(struct zone_ptr **z_p, struct dafs_zone_entry *z_e)
{
    struct zone_ptr *p;
    p->statemap = z_e->zone_statemap;
    p->zone_max = NR_DENTRY_IN_ZONE * 2;
    p->z_entry = z_e->dentry;
    *z_p = p;
}


/*
* alloc zone action
* 1.big enough direcotries will becomes a new zone
* 2.hot enough e.g frequently renames & chmod dir will becomes new zone*/
int dafs_alloc_dir_zone(struct super_block *sb, struct dafs_dzt_entry *dzt_e)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    //struct dafs_dzt_entry *dzt_e;
    //struct dzt_entry_info *dzt_ei;
    //struct dzt_manager *dzt_m = sbi->dzt_manager;
    struct dafs_zone_entry *new_ze;
    unsigned long zone_type = dzt_e->zone_blk_type;
    unsigned long blocknr;
    uint64_t hash_name;
    u64 block;
    int i;
    int allocated;
    unsigned long bp;
    int ret = 0;

    allocated = dafs_new_zone_blocks(sb, dzt_e, &blocknr, 1, 1);
    nova_dbg_verbose("%s: allocate zone @ 0x%lx\n", __func__,
							blocknr);
    if(allocated != 1 || blocknr == 0)
        return -ENOMEM;

    block = nova_get_block_off(sb, blocknr, DAFS_BLOCK_TYPE_512K);
    
    /*get zone address*/
    //bp = (unsigned long)nova_get_block(sb, block);
    //hash_name = le64_to_cpu(z_entry->dz_root_hash);
    dzt_e->dz_addr = cpu_to_le64(block);
    //dzt_e->dz_log_head = cpu_to_le64(block);
    //dzt_ei->dz_log_head = block;
    //dzt_ei->dz_addr = bp;
   

    /*not decided set root path and dz_no for new zone*/

    //make_dzt_entry_valid(sbi, dzt_e->dzt_eno);

    //radix_tree_insert(&dzt_m->dzt_root, dzt_ei->hash_name, dzt_ei);
    
    //dafs_init_dir_zone(sb, dzt_e, root_path, );        //not decided

    PERSISTENT_BARRIER();
    return ret;
}   

/*===================================build dzt when start up system ===========================================*/

/* 
* make dzt bitmap pointer*/
void make_dzt_ptr(struct nova_sb_info *sbi, struct dzt_ptr **dzt_p)
{
    struct dafs_dzt_block *dzt_blk;
    struct dzt_ptr *p;

    dzt_blk = dafs_get_dzt_block(sbi);

    p->bitmap = dzt_blk->dzt_bitmap;
    p->max = DAFS_DZT_ENTRIES_IN_BLOCK;
    p->dzt_entry = dzt_blk->dzt_entry;
    *dzt_p = p;
}

/*
 * make dzt entry valid*/
void set_dzt_entry_valid(struct nova_sb_info *sbi, unsigned long bitpos)
{
    //struct dafs_dzt_block *dzt_blk;
    struct dzt_ptr *dzt_p;
    int ret = 0;

    make_dzt_ptr(sbi, &dzt_p);

    test_and_set_bit(bitpos, dzt_p->bitmap);

}

/*
* build dzt radix-tree
* 初始化entry_info*/
static void dafs_build_dzt(struct super_block *sb, struct dafs_dzt_entry \
                     *dafs_dzt_entry)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dzt_entry_info *entry_info;
    struct dzt_manager *dzt_m;
    //int ret = 0;
    //struct dzt_entry *dzt_entry;

    /*take into acount when to destroy this entry*/
    //entry_info = kzalloc(sizeof(struct dzt_entry_info), GFP_KERNEL);  //move dzt entry into DRAM B-tree
    
    if(!dzt_entry)
        return -ENOMEM;
    entry_info->zone_blk_type = DAFS_BLOCK_TYPE_512K; 
    entry_info->root_len = le32_to_cpu(dafs_dzt_entry->root_len);
    entry_info->dzt_eno = le64_to_cpu(dafs_dzt_entry->dzt_eno);
    //entry_info->dz_no = le64_to_cpu(dafs_dzt_entry->dz_no);
    entry_info->dz_addr = le64_to_cpu(dafs_dzt_entry->dz_addr);
    entry_info->hash_name = le64_to_cpu(dafs_dzt_entry->hash_name);

    INIT_LIST_HEAD(&entry_info->child_list);

    dzt_m = kzalloc(sizeof(struct dzt_manager), GFP_KERNEL);

    if(!dzt_m)
        return -ENOMEM;
    
    INIT_RADIX_TREE(&dzt_m->dzt_root, GFP_ATOMIC);

    make_dzt_tree(entry_info);
    
    //return ret;
}

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
    unsigned long bit_pos = 0;
    int ret = 0;
    //unsigned long max = DAFS_DZT_ENTRIES_IN_BLOCK;

    dzt_blk = dafs_get_dzt_block(sbi);

    dzt_p->bitmap = dzt_blk->dzt_bitmap;
    dzt_p->max = DAFS_DZT_ENTRIES_IN_BLOCK;
    dzt_p->dzt_entry = dzt_blk->dzt_entry;

    while(bit_pos < dzt_p->max){
        if(!test_bit_le(bit_pos, dzt_p->bitmap)){
            bit_pos++;
            continue;
        }

        dzt_entry = dzt_p->dzt_entry[bit_pos];

        dzt_ei->root_len = le32_to_cpu(dzt_entry->root_len);
        dzt_ei->dzt_eno = le64_to_cpu(dzt_entry->dzt_eno);
        dzt_ei->dz_no = le64_to_cpu(dzt_entry->dz_no);
        dzt_ei->dz_addr = le64_to_cpu(dzt_entry->dz_addr);
        dzt_ei->hash_name = le64_to_cpu(dzt_entry->hash_name);

        /*not decided 不设置有效位么*/
        make_dzt_tree(sbi, dzt_ei);
    }

    return ret;
}

/*init read frequency tree*/
int init_rf_entry(struct super_block *sb, struct dzt_entry_info *dzt_ei)
{
    struct rf_entry *rfe;
    struct ht_ptr *ht_p;
    struct hash_table *ht;
    struct hash_entry *he;
    u64 ht_addr, bit_pos = 0, tail;
    int key;

    //rfe = kzalloc(sizeof(struct rf_entry), GFP_KERNEL);
    //rfe->r_f = 0;
    //rfe->hash_name = dzt_ei->hash_name;
    //radix_tree_insert(&dzt_ei->rf_root, rfe->hash_name, rfe);
    
    ht_addr = dzt_ei->ht_head;
    if(!ht_addr)
        return 0;
    ht = (struct hash_table *)nova_get_block(sb, ht_addr);
lookup:
    make_ht_ptr(&ht_p,ht);
    rfe = kzalloc(sizeof(struct rf_entry), GFP_KERNEL);
    while(bit_pos < ht_p->hash_max) {
        if(test_bit_le(bit_pos, ht_p->bitmap) {
            he = ht->hash_entry[bit_pos];
            rfe->r_f = 0;
            rfe->hash_name = le64_to_cpu(ht->hd_name);
            radix_tree_insert(&dzt_ei->rf_root, rfe->hash_name, rfe);
            bit_pos++;
        }

    }
    tail =le64_to_cpu(ht->hash_tail);
    if(tail){
        ht = (struct hash_table *)nova_get_block(sb, tail);
        bitpos = 0;
        goto lookup;
    }
    return 0;    
}

/*
 * make radix tree by inserting*/
static void make_dzt_tree(struct nova_sb_info *sbi, struct dzt_entry_info *dzt_ei)
{
    struct dzt_entry_info *dzt_entry_info;
    struct dzt_manager *dzt_m = sbi->dzt_manager;
    //int ret = 0;

    dzt_entry_info = kzalloc(sizeof(struct dzt_entry_info), GFP_KERNEL);
    dzt_entry_info->zone_blk_type = dzt_ei->zone_blk_type;
    dzt_entry_info->root_len = dzt_ei->root_len;
    dzt_entry_info->dzt_eno = dzt_ei->dzt_eno;
    //dzt_entry_info->dz_no = dzt_ei->dz_no;
    dzt_entry_info->dz_addr = dzt_ei->dz_addr;
    dzt_entry_info->hash_name = dzt_ei->hash_name;
    INIT_RADIX_TREE(&dzt_entry_info->rf_root, GFP_ATOMIC);
    init_rf_entry(sbi->sb, dzt_entry_info);

    radix_tree_insert(&dzt_m->dzt_root, dzt_entry_info->hash_name, dzt_entry_info);

}

/*
 * destroy DRAM radix dzt tree*/
int dafs_destroy_dzt(struct nova_sb_info *sbi)
{
    struct dzt_manager *dzt_m = sbi->dzt_manager;

    /*destroy dzt_entries*/

    /*free dzt_manager*/
    kfree(dzt_m);

    return 0;
}


/*======================================= dzt&zone adaption =================================================*/

/*
* add dzt entries in DRAM
* used in split*/
struct dzt_entry_info *add_dzt_entry(struct super_block *sb, struct dzt_entry_info *par_dei,\ 
        unsigned long sp_id)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dafs_dzt_entry *new_dzt_e;
    struct dzt_entry_info *new_dzt_ei;
    struct dzt_manager *dzt_m = sbi->dzt_manager;
    struct dafs_dentry *dafs_rde;
    struct dafs_zone_entry *par_ze;
    //struct dafs_dzt_block *dzt_blk;
    //struct dzt_ptr *dzt_p;
    u64 name_len;
    unsigned long eno_pos; 
    //char root_path[DAFS_PATH_LEN];
    int ret;
    u64 de_nlen, phash;
    char *pname;

    par_ze = (struct dafs_zone_entry *)nova_get_block(sb, par_dei->dz_addr); 

    eno_pos = alloc_dzt_entry(sb);

    if(!eno_pos)
        goto end;             //not decided
    /* modify dzt_eno, dz_log_head, dz_addr */
    

    dafs_rde = par_ze->dentry[sp_id];
    de_nlen = le64_to_cpu(dafs_rde->ful_name->f_namelen);
    
    new_dzt_ei = kzalloc(sizeof(struct dzt_entry_info), GFP_KERNEL);
    new_dzt_ei->zone_blk_type = DAFS_BLOCK_TYPE_512K;
    new_dzt_ei->dzt_eno = eno_pos;
    new_dzt_ei->pdz_addr = par_dei->dz_addr;
    new_dzt_ei->rden_pos = sp_id;

    if(par_dei->eno!=1){
        /*not decided*/
        name_len = (u64)(par_dei->root_len) + de_nlen;
        pname = kzalloc(sizeof(char *)*name_len, GFP_KERNEL);
        get_zone_path(sb, par_dei, pname, dafs_rde->ful_name->f_name);
        if(strlen(pname)!=name_len){
            nova_err(sb, "wrong name");
            goto end;
        }
        phash = BKDRHash(pname, name_len);
        new_dzt_ei->root_len =(u32) name_len;
        new_dzt_ei->hash_name = phash;
        kfree(pname);
    } else {
        name_len = de_nlen;
        phash = BKDRHash(dafs_rde->ful_name->f_name, name_len);
        new_dzt_ei->root_len = (u32)name_len;
        new_dzt_ei->hash_name = phash;
    }

    /* DRAM 中新建entry的时候一定是split zone的时候，不需要condition验证*/
    //new_dzt_e = append_dzt_entry(sb, dzt_ei, root_path, SPLIT_ZONE);
    /*build hashtable*/
    ret = get_hash_table(sb, &new_dzt_ei->ht_head);
    if(!ret)
        return -ENOMEM;

    /*build rf_radix tree*/
    INIT_RADIX_TREE(&new_dzt_ei->rf_root, GFP_ATOMIC);
    ret = add_rf_entry(new_dzt_ei, phash);
    if(ret)
        return -EINVAL;

end:
    return new_dzt_ei;

}

/*
*alloc dzt_entry
* 1. append at tail 
* 2. scan bitmap */
u64 alloc_dzt_entry(struct super_block *sb)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);  
    struct dafs_dzt_block *dzt_blk;
    struct dzt_ptr *dzt_p;
    unsigned long tail_pos;
    unsigned long bitpos = 1;
    unsigned long i;
    
    dzt_blk = dafs_get_dzt_block(sbi);
    tail_pos = le64_to_cpu(dzt_blk->dzt_tail_pos);

    make_dzt_ptr(sbi, &dzt_p);
    /*
    if(!test_bit_le(tail_pos, dzt_p->bitmap)){
        // not decided  清空
        i = tail_pos;
        i++;
        dzt_blk->dzt_tail_pos = cpu_to_le64(i);      //not decided 原子性
        return tail_pos;
    }*/
    while(bitpos < dzt_p->max){
        if(!test_bit_le(bitpos, dzt_p->bitmap))
            goto end;
        else
            bitpos++;
    }

    nova_err(sb, "dzt_blk is full");
    return ENOMEM;
end:
    return bitpos;
}

/*
* append dzt_entry in NVM
* set append condition to decide whether alloc zones*/
struct dafs_dzt_entry *append_dzt_entry(struct super_block *sb, struct dzt_entry_info *dzt_ei)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dafs_dzt_entry *dzt_e;
    struct dafs_dzt_block *dzt_blk;
    unsigned long en_pos;
    int ret = 0;

    en_pos = dzt_ei->dzt_eno;
    dzt_blk = dafs_get_dzt_block(sbi);

    dzt_e = dzt_blk->dzt_entry[en_pos];

    dzt_e->zoon_blk_type = cpu_to_le64(dzt_ei->zoon_blk_type);
    dzt_e->root_len = cpu_to_le64(dzt_ei->root_len);
    dzt_e->dzt_eno = cpu_to_le64(dzt_ei->dzt_eno);
    dzt_e->pdz_addr = cpu_to_le64(dzt_ei->pdz_addr);
    dzt_e->rden_pos = cpu_to_le64(dzt_ei->rden_pos);
    //dzt_e->dz_sf = cpu_to_le64(dzt_ei->dz_sf);
    dzt_e->hash_name = cpu_to_le64(dzt_ei->hash_name);
    /* not decided sub files */
    
    /*
    if(AP_CON == SPLIT_ZONE){
        ret = dafs_alloc_dir_zone(sb, dzt_e, dzt_ei, par_ze, path_name);
    }*/

    return dzt_e;
}


/*
* delete dzt_entry in DRAM
* not used in inherit
* rdei root dzt_entry_info*/
struct dzt_entry_info *delete_dzt_entry(struct super_block *sb, struct dzt_entry_info *old_rdei)
{
    struct nova_sb_info *sbi = NOVA_SB(sbi);
    struct dzt_manager *dzt_m = sbi->dzt_m_info;
    struct dzt_ptr *dzt_p;
    unsigned long hash_name;
    unsigned long ch_pos;

    make_dzt_ptr(sbi, &dzt_p);
    ch_pos = old_rdei->dzt_eno;
    hash_name = old_rdei->hash_name;
    radix_tree_delete(&dzt_m->dzt_root, hash_name);
    test_and_clear_bit(ch_pos, dzt_p->bitmap);

    return old_rdei;
}



/*
* allocate and initalize for migrate zone*/
struct dafs_zone_entry *alloc_mi_zone(struct super_block *sb, struct dafs_dzt_entry *n_dzt_e,\
                                     struct dzt_entry_info *n_dzt_ei, unsigned long sp_id)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dafs_zone_entry *new_ze, *par_ze;
    struct dafs_dentry *dafs_rde;
    struct dzt_manager *dzt_m = sbi->dzt_manager;
    //struct dzt_entry_info *par_ei;
    unsigned long blocknr;
    unsigned long par_root_len, name_len;
    int allocated;
    char root_path[DAFS_PATH_LEN];
    char *root = root_path;
    int i;


    allocated = dafs_new_zone_blocks(sb, dzt_e, &blocknr, 1, 1);
    
    if(allocated != 1 || blocknr == 0)
        return -ENOMEM;
    
    block = nova_get_block_off(sb, blocknr, DAFS_BLOCK_TYPE_512K);
    
    /*get zone address*/
    //bp = (unsigned long)nova_get_block(sb, block);
    
    /* add attributes to dzt_entry  */
    n_dzt_e->dz_addr = cpu_to_le64(block);
    n_dzt_ei->dz_addr = block;

    /* init new zone_entry */
    new_ze =(struct dafs_zone_entry *)nova_get_block(sb, n_dzt_ei->dz_addr);

    /* clear statemap of new zone*/
    memset(new_ze->statemap, 0, SIZE_OF_ZONE_BITMAP);

    new_ze->dz_no = cpu_to_le64(n_dzt_ei->dzt_eno);
    //new_ze->dz_sf = 0;
    
    /*
    dafs_rde = par_ze->dentry[sp_id];
    par_root_len = par_dzt_ei->root_len;
    memcpy(root_path[0], par_ze->root_path, par_root_len);
    memcpy(root_path[par_root_len], dafs_rde->name, cpu_to_le64(dafs_rde->name_len));
    name_len = par_root_len + cpu_to_le64(dafs_rde->name_len);
    memcpy(new_ze->root_path[0], root, name_len);*/

    /*clear dentry, memset after test null*/

    par_ze = (struct dafs_zone_entry *)nova_get_block(sb, n_dzt_ei->pdz_addr);
    /* migrate*/
    migrate_zone_entry(sb, sp_id, n_dzt_ei);

    /*reset statemap*/
    zone_set_statemap(sb, par_ze);

    make_dzt_entry_valid(sbi, n_dzt_e->dzt_eno);
    radix_tree_insert(&dzt_m->dzt_root, n_dzt_ei->hash_name, n_dzt_ei);

    return new_ze;
}
/*get ei from eno pos*/
struct dzt_entry_info *DAFS_GET_EI(sb, u64 eno)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dafs_dzt_block *dzt_blk = dafs_get_dzt_block(sb);
    struct dafs_dzt_entry *dzt_e;
    struct dzt_ptr *dzt_p;
    struct dzt_manager *dzt_m = sbi->dzt_m_info;
    struct dzt_entry_info *ei;
    u64 hashname;

    make_dzt_ptr(sbi, &dzt_p);
    if(!test_bit_le(eno, dzt_p->bitmap)){
        nova_err(sb, "not found dzt_entry");
        return -EINVAL;
    }
    dzt_e = dzt_blk->dzt_entry[eno];
    hashname = le64_to_cpu(dzt_e->hash_name);
    ei = radix_tree_lookup(&dzt_m->dzt_root, hashname);
    if(!ei){
        nova_err(sb, "not found ei");
        return -EINVAL;
    }
    return ei;

}

/*
* migrate zone entries */
int migrate_zone_entry(struct super_bolck *sb, unsigned long ch_pos, struct dzt_entry_info *dzt_nei)
{
    //struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dafs_zone_entry *old_ze, *new_ze;
    struct dafs_dentry *dafs_rde;
    struct dzt_entry_info *old_ei;
    struct zone_ptr *z_p;
    struct rf_entry *rf_e;
    unsigned long old_id, ch_len, old_namelen, sub_no;
    unsigned long *ch_no, ch_pos;
    unsigned long sub_pos[NR_DENTRY_IN_ZONE];
    unsigned long bitpos = 0;
    unsigned long new_id = 0;
    int i = 0;
    int oi = 0;
    int ret = 0;
    u64 eno, hashname, name_len;
    
    ch_pos = 0;

    old_ze = (struct dafs_zone_entry *)nova_get_block(sb, dzt_nei->pdz_addr);
    new_ze = (struct dafs_zone_entry *)nova_get_block(sb, dzt_nei->dz_addr);

    dafs_rde = old_ze->dentry[ch_pos];
    /*clear statemap of new zone*/

    //new_z_e->dz_no = dzt_ne->dzt_eno;
    old_namelen = le64_to_cpu(dafs_rde->ful_name->f_namelen);

    ch_len = le64_to_cpu(dafs_rde->sub_num);
    ch_no = kzalloc(sizeof(unsigned long)*ch_len);
    for(i =0;i<ch_len;i++){
        ch_no[i] = le64_to_cpu(dafs_rde->sub_pos[i]);
    }

    /* modify root dentry 
    * not change rde sub_state*/
    dafs_rde->file_type = ROOT_DIRECTORY;
    dafs_rde->mtime = CURRENT_TIME_SEC.tv_sec;
    dafs_rde->vroot = 1;
    //dafs_rde->zoon_no = dzt_nei->dzt_eno;
    dafs_rde->dzt_hn = cpu_to_le64(dzt_nei->hash_name);
    dafs_rde->sub_num = 0;
    dafs_rde->sub_pos[NR_DENTRY_IN_ZONE] = {0};
    
    name_len = le64_to_cpu(dafs_rde->ful_name->f_namelen);
    hashname = BKDRHash(dafs_rde->ful_name->f_name, name_len);

    eno = le64_to_cpu(old_ze->dz_no);
    old_ei = DAFS_GET_EI(sb, eno);

    /*change rf value of root dir*/
    rf_e = radix_tree_lookup(&old_ei->rf_root, hashname);
    rf_e->sub_s = 0;
    rf_e->f_s = 0;
    rf_e->prio = 0;

    make_zone_ptr(&z_p, new_ze);
    cpy_new_zentry(dzt_nei, old_ei, old_namelen, dafs_rde, ch_no, &ch_pos);
    
    kfree(ch_no);
    return ret;
}

/*
*copy andd get new zone_dentry 
*递归
* z_p  for make every dentry statemap valid
* new_ze and old_ze for get old dentry and new dentry
* par_de for record sub_file pos 
* ch_no is an array records subfile_id
* ch_pos is the star pos for copy*/
static  void cpy_new_zentry(struct super_bolck *sb, struct dzt_entry_info *new_ei,\
        struct dzt_entry_info *old_ei, unsigned long old_len, struct dafs_dentry *par_de,\
        const unsigned long *ch_no, unsigned long *ch_pos)
{
    struct dafs_dentry *new_de, *old_de;
    struct zone_ptr *new_p, *old_p;
    struct dafs_zone_entry *new_ze, *old_ze;
    //unsigned long old_len = r_ze->name_len;
    char name[NOVA_NAME_LEN]; 
    unsigned long  j,k,old_id;
    unsigned long ch_len, *sub_no, sub_len;
    unsigned long new_id = *ch_pos;  /* ch_pos initalized as 0*/
    unsigned long bitpos = 0;
    unsigned long i, name_len;
    u64 hashname, hashlen;
    int j;

    old_ze = (struct dafs_zone_entry *)nova_get_block(sb, new_ei->pdz_addr);
    new_ze = (struct dafs_zone_entry *)nova_get_block(sb, old_ei->dz_addr);
    make_zone_ptr(&old_p, old_ze);
    make_zone_ptr(&new_p, new_ze);
    ch_len = par_de->sub_num;
    for(i=0;i<ch_len;i++){
        old_id = le64_to_cpu(ch_no[i]);
        old_de = old_ze->dentry[old_id];
        new_de = new_ze->dentry[new_id];
        if(old_de->file_type == NORMAL_FILE){
            new_de->entry_type = old_de->entry_type;
            new_de->name_len = old_de->name_len;
            //new_de->name_len = old_de->name_len-old_len;
            new_de->file_type = old_de->file_type;
            new_de->links_count = old_de ->links_count;
            new_de->mtime = CURRENT_TIME_SEC.tv_sec;
            new_de->vroot = old_de->vroot;
            //new_de->path_len = old_de->path_len-old_len;
            new_de->ino = old_de->ino;
            new_de->par_ino = old_de->par_ino;
            new_de->size = old_de->size;
            new_de->dzt_hn = old_de->dzt_hn;
            //new_de->prio = LEVEL_0;
            //new_de->d_f = 0;            //not decided
            //new_de->sub_s = old_de->sub_s;
            new_de->f_s = DENTRY_FREQUENCY_COLD;
            memcpy(new_de->name, old_de->name, le64_to_cpu(old_de->name_len)+1);
            name_len = le64_to_cpu(old_de->ful_name->f_namelen) - old_len;
            new_de->ful_name->f_namelen = cpu_to_le64(name_len);
            memcpy(new_de->ful_name->f_name, old_de->ful_name->f_name+old_len, name_len+1);


            /*for(k = 0;k<new_de->name_len;k++){
                new_de->name[k] = old_de->name[old_len];
                old_len++:
            }*/

            /*set sum frequency*/
            //old_ze->dz_sf -= old_de->d_f;

            /*set this file's pos in its par_de*/
            par_de->sub_pos[i] = new_id;
            /*atomic*/
            bitpos = new_id *2 +1;
            set_bit_le(bitpos, new_p->statemap);

            /*record pos in hashtable*/
            hashname = BKDRHash(new_de->ful_name->f_name, name_len);
            record_pos_htable(sb, new_ei->ht_head, hashname, name_len, new_id, 1);
            /*set rf_entry*/
            add_rf_entry(new_ei, hashname);

            /*set old invalid*/
            bitpos = old_id*2;
            test_and_clear_bit_le(bitpos, old_p->statemap);
            bitpos++;
            test_and_clear_bit_le(bitpos, old_p->statemap);

            /*make invalid in hashtable*/
            name_len = le64_to_cpu(old_de->ful_name->f_namelen);
            hashname = BKDRHash(old_de->ful_name->f_name, name_len);
            make_invalid_htable(old_ei->ht_head, hashname, name_len, 1);

            /*delete ef_entry in old rf_tree*/
            delete_rf_entry(old_ei, hashname);

            new_id++;
            *ch_pos = new_id;

        }else if(old_de->file_type == ROOT_DIRECTORY){
            new_de->entry_type = old_de->entry_type;
            new_de->name_len = old_de->name_len;
            //new_de->name_len = old_de->name_len-old_len;
            new_de->file_type = old_de->file_type;
            new_de->links_count = old_de ->links_count;
            new_de->mtime = CURRENT_TIME_SEC.tv_sec;
            new_de->vroot = old_de->vroot;
            //new_de->path_len = old_de->path_len-old_len;
            new_de->ino = old_de->ino;
            new_de->par_ino = old_de->par_ino;
            new_de->size = old_de->size;
            new_de->dzt_hn = old_de->dzt_hn;
            //new_de->zone_no = old_de->zone_no;
            //new_de->prio = LEVEL_0;
            //new_de->d_f = 0;
            //new_de->sub_s = old_de->sub_s;
            //new_de->f_s = DENTRY_FREQUENCY_COLD;
            new_de->sub_num = old_de->sub_num;
            memcpy(new_de->name, old_de->name, le64_to_cpu(old_de->name_len)+1);
            name_len = le64_to_cpu(old_de->ful_name->f_namelen) - old_len;
            new_de->ful_name->f_namelen = cpu_to_le64(name_len);
            memcpy(new_de->ful_name->f_name, old_de->ful_name->f_name+old_len, name_len+1);

            /*
            for(k = 0;k<new_de->name_len;k++){
                new_de->name[k] = old_de->name[old_len];
                old_len++;
            }*/
            
            /*set sum frequency*/
            //old_ze->dz_sf -= old_de->d_f;
            
            par_de->sub_pos[i] = new_id;
            bitpos = new_id *2 +1;
            set_bit_le(bitpos, new_p->statemap);

            /*record pos in hashtable*/
            hashname = BKDRHash(new_de->ful_name->f_name, name_len);
            record_pos_htable(sb, new_ei->ht_head, hashname, name_len, new_id, 1);
            /*set rf_entry*/
            add_rf_entry(new_ei, hashname);

            /*set old invalid*/
            bitpos = old_id*2;
            test_and_clear_bit_le(bitpos, old_p->statemap);
            bitpos++;
            test_and_clear_bit_le(bitpos, old_p->statemap);

            /*make invalid in hashtable*/
            name_len = le64_to_cpu(old_de->ful_name->f_namelen);
            hashname = BKDRHash(old_de->ful_name->f_name, name_len);
            make_invalid_htable(old_ei->ht_head, hashname, name_len, 1);

            /*delete ef_entry in old rf_tree*/
            delete_rf_entry(old_ei, hashname);

            new_id++;
            *ch_pos = new_id;
        }else if(old_de->file_type == NORMAL_DIRECTORY){
                    
            new_de->entry_type = old_de->entry_type;
            new_de->name_len = old_de->name_len;
            //new_de->name_len = old_de->name_len-old_len;
            new_de->file_type = old_de->file_type;
            new_de->links_count = old_de ->links_count;
            new_de->mtime = CURRENT_TIME_SEC.tv_sec;
            new_de->vroot = old_de->vroot;
            //new_de->path_len = old_de->path_len-old_len;
            new_de->ino = old_de->ino;
            new_de->par_ino = old_de->par_ino;
            new_de->size = old_de->size;
            //new_de->prio = LEVEL_0;
            //new_de->d_f = 0;
            //new_de->sub_s = old_de->sub_s;
            //new_de->f_s = DENTRY_FREQUENCY_COLD;
            new_de->sub_num = old_de->sub_num;
            memcpy(new_de->name, old_de->name, le64_to_cpu(old_de->name_len)+1);
            name_len = le64_to_cpu(old_de->ful_name->f_namelen) - old_len;
            new_de->ful_name->f_namelen = cpu_to_le64(name_len);
            memcpy(new_de->ful_name->f_name, old_de->ful_name->f_name+old_len, name_len+1);
            /*
            for(k = 0;k<new_de->name_len;k++){
                new_de->name[k] = old_de->name[old_len];
                old_len++;
            }*/
            
            /*set sum frequency*/
            //old_ze->dz_sf -= old_de->d_f;
            
            par_de->sub_pos[i] = new_id;
            bitpos = new_id *2 +1;
            set_bit_le(bitpos, z_p->statemap);
            
            /*record pos in hashtable*/
            hashname = BKDRHash(new_de->ful_name->f_name, name_len);
            record_pos_htable(sb, new_ei->ht_head, hashname, name_len, new_id, 1);
            /*set rf_entry*/
            add_rf_entry(new_ei, hashname);

            /*set old invalid*/
            bitpos = old_id*2;
            test_and_clear_bit_le(bitpos, old_p->statemap);
            bitpos++;
            test_and_clear_bit_le(bitpos, old_p->statemap);

            /*make invalid in hashtable*/
            name_len = le64_to_cpu(old_de->ful_name->f_namelen);
            hashname = BKDRHash(old_de->ful_name->f_name, name_len);
            make_invalid_htable(old_ei->ht_head, hashname, name_len, 1);

            /*delete ef_entry in old rf_tree*/
            delete_rf_entry(old_ei, hashname);

            new_id++;
            *ch_pos = new_id;
            sub_len = le64_to_cpu(old_de->sub_num);
            sub_no = (unsigned long *)kzalloc(sizeof(unsigned long)*sub_len)
            for(j=0;j<sub_len;j++){
                sub_no[j] = le64_to_cpu(old_de->sub_pos[j]);
            }
            //memcpy(sub_no[0],old_de->sub_pos,old_de->sub_num);
            /*input new_de when it is a directory*/
            cpy_new_zentry(sb, new_ei, old_ei, old_len, new_de, sub_no, &new_id);

        }

    } 
    
}
/*merge*/
int __merge_dentry(struct super_block *sb, struct dzt_entry_info *cur_ei, unsigned long cur_pos,\
                  struct dafs_dentry *rde)
{
    struct dafs_zone_entry *des_ze, *cur_ze;
    struct zone_ptr *par_p, *cur_p;
    struct dafs_dentry *cur_de, *des_de;
    struct dzt_entry_info *par_ei;
    struct rf_entry *old_rf, *new_rf;
    u64 bitpos = 0, fpos = 0, plen， hn, eno, old_hn, subnum, pos, f_num;
    int i, ret =0;
    char *name = kzalloc(DAFS_PATH_LEN*sizeof(char), GFP_KERNEL);

    des_ze = (struct dafs_zone_entry *)nova_get_block(sb, cur_ei->pdz_addr);
    cur_ze = (struct dafs_zone_entry *)nova_get_block(sb, cur_ei->dz_addr);

    cur_de = cur_ze->dentry[cur_pos];
    memcpy(name, rde->ful_name->f_name, le64_to_cpu(rde->ful_name->f_namelen)+1);

    make_zone_ptr(&par_p, des_ze);
    if(cur_de->file_type != NORMAL_DIRECTORY){
        fpos = find_invalid_id(par_p, fpos);
        des_de = des_ze->dentry[fpos];
        des_de->entry_type = cur_de->entry_type;
        des_de->name_len = cur_de->name_len;
        des_de->file_type = cur_de->file_type;
        des_de->links_count = cur_de->links_count;
        des_de->mtime = CURRENT_TIME_SEC.tv_sec;
        des_de->vroot = cur_de->vroot;
        des_de->ino = cur_de->ino;
        des_de->par_ino = cur_de->par_ino;
        des_de->size = cur_de->size;
        des_de->dzt_hn = cur_de->dzt_hn;
        des_de->sub_num = 0;
        des_de->sub_pos[NR_DENTRY_IN_ZONE]={0};
        memcpy(des_de->name, cur_de->name, le64_to_cpu(cur_de->name_len));
        plen = le64_to_cpu(cur_de->ful_name->f_namelen)+le64_to_cpu(rde->ful_name->f_namelen);
        des_de->ful_name->f_namelen = cpu_to_le64(plen);
        strcat(name, "/");
        strcat(name, cur_de->name);
        memcpy(des_de->ful_name->f_name, name, plen);

        /*record pos in hash table*/
        eno = le64_to_cpu(par_ze->dz_no);
        par_ei = DAFS_GET_EI(sb, eno);
        hn = BKDRHash(name, plen);
        record_pos_htable(sb, par_ei->ht_head, hn, plen, f_pos, 1);

        /*热度*/
        old_hn = BKDRHash(cur_de->ful_name->f_name, le64_to_cpu(cur_de->ful_name->f_namelen));
        old_rf = radix_tree_lookup(&cur_ei->rf_root, old_hn);
        new_rf = kzalloc(sizeof(struct rf_entry),GFP_KERNEL);
        new_rf->r_f = old_rf->r_f;
        new_rf->sub_s = old_rf->sub_s;
        new_rf->f_s = old_rf->f_s;
        new_rf->prio = LEVEL_0;
        new_rf->hash_name = hn;
        radix_tree_insert(&par_ei->rf_root, hn); 

        /*状态表*/
        bitpos = fpos*2+1;
        test_and_set_bit_le(bitpos+1,par_p->statemap);
        
        bitpos = cur_pos*2;
        test_and_clear_bit_le(bitpos, cur_p->statemap);
        bitpos++;
        test_and_clear_bit_le(bitpos, cur_p->statemap);

        /*par dir sub_num and sub_pos*/
        subnum = le64_to_cpu(rde->sub_num);
        sub_num++;
        rde->sub_num = cpu_to_le64(sub_num);
        rde->sub_pos[sub_num] = cpu_to_le64(cur_pos);

    } else {
        /*migrate dir*/  
        fpos = find_invalid_id(par_p, fpos);
        des_de = des_ze->dentry[fpos];
        des_de->entry_type = cur_de->entry_type;
        des_de->name_len = cur_de->name_len;
        des_de->file_type = cur_de->file_type;
        des_de->links_count = cur_de->links_count;
        des_de->mtime = CURRENT_TIME_SEC.tv_sec;
        des_de->vroot = cur_de->vroot;
        des_de->ino = cur_de->ino;
        des_de->par_ino = cur_de->par_ino;
        des_de->size = cur_de->size;
        des_de->dzt_hn = cur_de->dzt_hn;
        des_de->sub_num = 0;
        des_de->sub_pos[NR_DENTRY_IN_ZONE]={0};
        memcpy(des_de->name, cur_de->name, le64_to_cpu(cur_de->name_len));
        plen = le64_to_cpu(cur_de->ful_name->f_namelen)+le64_to_cpu(rde->ful_name->f_namelen);
        des_de->ful_name->f_namelen = cpu_to_le64(plen);
        strcat(name, "/");
        strcat(name, cur_de->name);
        memcpy(des_de->ful_name->f_name, name, plen);

        /*record pos in hash table*/
        eno = le64_to_cpu(par_ze->dz_no);
        par_ei = DAFS_GET_EI(sb, eno);
        hn = BKDRHash(name, plen);
        record_pos_htable(sb, par_ei->ht_head, hn, plen, f_pos, 1);

        /*热度*/
        old_hn = BKDRHash(cur_de->ful_name->f_name, le64_to_cpu(cur_de->ful_name->f_namelen));
        old_rf = radix_tree_lookup(&cur_ei->rf_root, old_hn);
        new_rf = kzalloc(sizeof(struct rf_entry),GFP_KERNEL);
        new_rf->r_f = old_rf->r_f;
        new_rf->sub_s = old_rf->sub_s;
        new_rf->f_s = old_rf->f_s;
        new_rf->prio = LEVEL_0;
        new_rf->hash_name = hn;
        radix_tree_insert(&par_ei->rf_root, hn); 

        /*状态表*/
        bitpos = fpos*2+1;
        test_and_set_bit_le(bitpos+1,par_p->statemap);
        
        bitpos = cur_pos*2;
        test_and_clear_bit_le(bitpos, cur_p->statemap);
        bitpos++;
        test_and_clear_bit_le(bitpos, cur_p->statemap);

        /*par dir sub_num and sub_pos*/
        subnum = le64_to_cpu(rde->sub_num);
        sub_num++;
        rde->sub_num = cpu_to_le64(sub_num);
        rde->sub_pos[sub_num] = cpu_to_le64(cur_pos);

        /*sub files*/
        f_num = le64_to_cpu(cur_de->sub_num);
        for(i=0;i<f_num;i++){
            pos = le64_to_cpu(cur_de->sub_pos[i]);
            ret = __merge_dentry(sb, cur_ei, pos, des_de);
        }
    }
    kfree(name);
    return ret;
}

/*find root par_dir hn*/
u64 get_par_hn(const char *name, u64 hash_name, u64 *len)
{
    char *ph, *tem, *pname;
    u64 namelen, temlen, hn;
    
    namelen = strlen(name);
    ph = kzalloc(namelen*sizeof(char), GFP_KERNEL);
    pname = kzalloc(namelen*sizeof(char),GFP_KERNEL);
    memcpy(pname, name, namelen);
    tem = strrchr(name, "/");
    templen = namelen - strlen(tem);
    //memset(ph, 0, temlen);
    //memcpy(ph, name, temlen);
    //hn = BKDRHash(ph, temlen);
    while(!temlen) {
        memcpy(ph, pname, temlen);
        memcpy(ph+temlen, "\0", 1);
        hn = BKDRHash(ph, temlen);
        if(hn == hash_name){
            hn = BKDRHash(pname, namelen);
            *len = namelen;
            break;
        }

        memcpy(pname, ph, temlen+1);
        namelen = strlen(pname);
        tem = strrchr(pname, "/");
        temlen = namelen - strlen(tem);
    }
    
    kfree(pname);
    kfree(ph);

    if(temlen ==0)
        return -EINVAL;

    return hn;
}

/*cpy merge
* 向上回溯*/
int merge_dentry(struct super_block *sb, struct dzt_entry_info *cur_ei)
{
    struct zone_ptr *cur_p;
    struct dafs_zone_entry *par_ze;
    struct dafs_zone_entry *cur_ze;
    struct hash_table *cur_ht, *par_ht;
    struct hash_entry *he;
    struct dafs_dentry *de, *rde;
    struct dzt_entry_info *des_ei;
    u64 bitpos, filepos = 0, rde_pos;
    char *name = kzalloc(DAFS_PATH_LEN*sizeof(char), GFP_KERNEL);
    char *tem;
    u64 nlen,plen,hn, len, eno;
    unsigned long pos;
    int ret = 0;

    cur_ze = (struct dafs_zone_entry *)nova_get_block(sb, cur_ei->dz_addr);
    par_ze = (struct dafs_zone_entry *)nova_get_block(sb, cur_ei->pdz_addr);

    rde_pos = cur_ei->rde_pos;
    rde = par_ze->dentry[rde_pos];
    
    make_zone_ptr(&cur_p, cur_ze);

    bitpos = 0;
    while(bitpos<z_p->zone_max){
        bitpos++;
        if(test_bit_le(bitpos, cur_p->statemap)){
            de = cur_ze->dentry[filepos];
            plen = de->ful_name->f_namelen;
            nlen = plen - le64_to_cpu(de->name_len); 
            memcpy(name, de->ful_name->f_name, nlen);
            memcpy(name+plen, "\0", 1);
            hn = BKDRHash(name, nlen);
            if(hn == cur_ei->hash_name){
                pos = filepos;
                __merge_dentry(sb, cur_ei, pos, rde);
            } else {
                hn = get_par_hn(name, cur_ei->hash_name, &len);
                if(!hn)
                    nova_err(sb, "can not find par dir");
                ret = lookup_in_hashtable(cur_ei->ht_head, hn, len, 1, &pos);
                __merge_dentry(sb, cur_ei, pos, rde);

            }
        }
        bitpos++;
        filepos++;
    }
    

    kfree(name);
    return ret;
}

int __inherit_dentry(struct super_block *sb, struct dzt_entry_info *cur_ei, u64 cur_pos,\
                    struct dafs_dentry *rde, const char *iname)
{
    struct dafs_zone_entry *des_ze, *cur_ze;
    struct zone_ptr *par_p, *cur_p;
    struct dafs_dentry *cur_de, *des_de;
    struct dzt_entry_info *par_ei;
    struct rf_entry *old_rf, *new_rf;
    u64 bitpos = 0, fpos = 0, plen， hn, eno, old_hn, subnum, pos, f_num, inamelen, len;
    u64 phash;
    int i, ret =0, re;
    char *name = kzalloc(DAFS_PATH_LEN*sizeof(char), GFP_KERNEL);
    char *tem, *pname;

    inamelen = strlen(iname);
    tem = kzalloc((inamelen+1)*sizeof(char), GFP_KERNEL);

    des_ze = (struct dafs_zone_entry *)nova_get_block(sb, cur_ei->pdz_addr);
    cur_ze = (struct dafs_zone_entry *)nova_get_block(sb, cur_ei->dz_addr);

    cur_de = cur_ze->dentry[cur_pos];
    
    memcpy(tem, cur_de->ful_name->f_name, inamelen);
    len = le64_to_cpu(cur_de->ful_name->f_namelen);
    re = strcmp(iname, tem);

    /*this is subfile of inherit dentry*/
    if(inamelen!=len && tem==0){
        return ret;
    }

    memcpy(name, rde->ful_name->f_name, le64_to_cpu(rde->ful_name->f_namelen)+1);

    make_zone_ptr(&par_p, des_ze);

    if(cur_de->file_type == ROOT_DIRECTORY || cur_de->file_type == NORMAL_FILE){
        fpos = find_invalid_id(par_p, fpos);
        des_de = des_ze->dentry[fpos];
        des_de->entry_type = cur_de->entry_type;
        des_de->name_len = cur_de->name_len;
        des_de->file_type = cur_de->file_type;
        des_de->links_count = cur_de->links_count;
        des_de->mtime = CURRENT_TIME_SEC.tv_sec;
        des_de->vroot = cur_de->vroot;
        des_de->ino = cur_de->ino;
        des_de->par_ino = cur_de->par_ino;
        des_de->size = cur_de->size;
        des_de->dzt_hn = cur_de->dzt_hn;
        des_de->sub_num = 0;
        des_de->sub_pos[NR_DENTRY_IN_ZONE]={0};
        memcpy(des_de->name, cur_de->name, le64_to_cpu(cur_de->name_len));
        plen = le64_to_cpu(cur_de->ful_name->f_namelen)+le64_to_cpu(rde->ful_name->f_namelen);
        des_de->ful_name->f_namelen = cpu_to_le64(plen);
        strcat(name, "/");
        strcat(name, cur_de->name);
        memcpy(des_de->ful_name->f_name, name, plen);

        /*record pos in hash table*/
        eno = le64_to_cpu(par_ze->dz_no);
        par_ei = DAFS_GET_EI(sb, eno);
        hn = BKDRHash(name, plen);
        record_pos_htable(sb, par_ei->ht_head, hn, plen, f_pos, 1);

        /*copy rf_entry
        * delete old rf
        * free rf*/
        old_hn = BKDRHash(cur_de->ful_name->f_name, le64_to_cpu(cur_de->ful_name->f_namelen));
        old_rf = radix_tree_delete(&cur_ei->rf_root, old_hn);
        new_rf = kzalloc(sizeof(struct rf_entry),GFP_KERNEL);
        new_rf->r_f = old_rf->r_f;
        new_rf->sub_s = old_rf->sub_s;
        new_rf->f_s = old_rf->f_s;
        new_rf->prio = LEVEL_0;
        new_rf->hash_name = hn;
        radix_tree_insert(&par_ei->rf_root, hn); 
        kfree(old_rf);

        /*状态表
        * set and clear*/
        bitpos = fpos*2+1;
        test_and_set_bit_le(bitpos+1,par_p->statemap);
        
        bitpos = cur_pos*2;
        test_and_clear_bit_le(bitpos, cur_p->statemap);
        bitpos++;
        test_and_clear_bit_le(bitpos, cur_p->statemap);

        /*clear hashtale*/
        make_invalid_htable(cur_ei->ht_head, old_hn, len, 1);

        /*par dir sub_num and sub_pos*/
        subnum = le64_to_cpu(rde->sub_num);
        sub_num++;
        rde->sub_num = cpu_to_le64(sub_num);
        rde->sub_pos[sub_num] = cpu_to_le64(cur_pos);

    } else if(cur_de->file_type == NORMAL_DIRECTORY){
        /*migrate dir*/  
        fpos = find_invalid_id(par_p, fpos);
        des_de = des_ze->dentry[fpos];
        des_de->entry_type = cur_de->entry_type;
        des_de->name_len = cur_de->name_len;
        des_de->file_type = cur_de->file_type;
        des_de->links_count = cur_de->links_count;
        des_de->mtime = CURRENT_TIME_SEC.tv_sec;
        des_de->vroot = cur_de->vroot;
        des_de->ino = cur_de->ino;
        des_de->par_ino = cur_de->par_ino;
        des_de->size = cur_de->size;
        des_de->dzt_hn = cur_de->dzt_hn;
        des_de->sub_num = 0;
        des_de->sub_pos[NR_DENTRY_IN_ZONE]={0};
        memcpy(des_de->name, cur_de->name, le64_to_cpu(cur_de->name_len));
        plen = le64_to_cpu(cur_de->ful_name->f_namelen)+le64_to_cpu(rde->ful_name->f_namelen);
        des_de->ful_name->f_namelen = cpu_to_le64(plen);
        strcat(name, "/");
        strcat(name, cur_de->name);
        memcpy(des_de->ful_name->f_name, name, plen);

        /*record pos in hash table*/
        eno = le64_to_cpu(par_ze->dz_no);
        par_ei = DAFS_GET_EI(sb, eno);
        hn = BKDRHash(name, plen);
        record_pos_htable(sb, par_ei->ht_head, hn, plen, f_pos, 1);

        /*热度*/
        old_hn = BKDRHash(cur_de->ful_name->f_name, len);
        old_rf = radix_tree_delete(&cur_ei->rf_root, old_hn);
        new_rf = kzalloc(sizeof(struct rf_entry),GFP_KERNEL);
        new_rf->r_f = old_rf->r_f;
        new_rf->sub_s = old_rf->sub_s;
        new_rf->f_s = old_rf->f_s;
        new_rf->prio = LEVEL_0;
        new_rf->hash_name = hn;
        radix_tree_insert(&par_ei->rf_root, hn); 
        kfree(old_rf);

        /*状态表*/
        bitpos = fpos*2+1;
        test_and_set_bit_le(bitpos+1,par_p->statemap);
        
        bitpos = cur_pos*2;
        test_and_clear_bit_le(bitpos, cur_p->statemap);
        bitpos++;
        test_and_clear_bit_le(bitpos, cur_p->statemap);

        /*clear hashtale*/
        make_invalid_htable(cur_ei->ht_head, old_hn, len, 1);
        
        /*par dir sub_num and sub_pos*/
        subnum = le64_to_cpu(rde->sub_num);
        sub_num++;
        rde->sub_num = cpu_to_le64(sub_num);
        rde->sub_pos[sub_num] = cpu_to_le64(cur_pos);

        /*sub files*/
        f_num = le64_to_cpu(cur_de->sub_num);
        for(i=0;i<f_num;i++){
            pos = le64_to_cpu(cur_de->sub_pos[i]);
            ret = __inherit_dentry(sb, cur_ei, pos, des_de, iname);
        }
    } else{
        fpos = find_invalid_id(par_p, fpos);
        des_de = des_ze->dentry[fpos];
        des_de->entry_type = cur_de->entry_type;
        des_de->name_len = cur_de->name_len;
        des_de->file_type = ROOT_DIRECTORY;
        des_de->links_count = cur_de->links_count;
        des_de->mtime = CURRENT_TIME_SEC.tv_sec;
        des_de->vroot = 1;
        des_de->ino = cur_de->ino;
        des_de->par_ino = cur_de->par_ino;
        des_de->size = cur_de->size;
        /*for new root*/
        des_de->dzt_hn = cur_ei->hash_name;
        des_de->sub_num = 0;
        des_de->sub_pos[NR_DENTRY_IN_ZONE]={0};
        memcpy(des_de->name, cur_de->name, le64_to_cpu(cur_de->name_len));
        plen = le64_to_cpu(cur_de->ful_name->f_namelen)+le64_to_cpu(rde->ful_name->f_namelen);
        des_de->ful_name->f_namelen = cpu_to_le64(plen);
        strcat(name, "/");
        strcat(name, cur_de->name);
        memcpy(des_de->ful_name->f_name, name, plen);

        /*record pos in hash table*/
        eno = le64_to_cpu(par_ze->dz_no);
        par_ei = DAFS_GET_EI(sb, eno);
        hn = BKDRHash(name, plen);
        record_pos_htable(sb, par_ei->ht_head, hn, plen, f_pos, 1);

        /*copy rf_entry
        * delete old rf
        * free rf*/
        old_hn = BKDRHash(cur_de->ful_name->f_name, len);
        old_rf = radix_tree_delete(&cur_ei->rf_root, old_hn);
        add_rf_entry(par_ei, hn);
        kfree(old_rf);

        /*状态表
        * set and clear*/
        bitpos = fpos*2+1;
        test_and_set_bit_le(bitpos+1,par_p->statemap);
        
        bitpos = cur_pos*2;
        test_and_clear_bit_le(bitpos, cur_p->statemap);
        bitpos++;
        test_and_clear_bit_le(bitpos, cur_p->statemap);

        /*clear hashtale*/
        make_invalid_htable(cur_ei->ht_head, old_hn, len, 1);

        /*par dir sub_num and sub_pos*/
        subnum = le64_to_cpu(rde->sub_num);
        sub_num++;
        rde->sub_num = cpu_to_le64(sub_num);
        rde->sub_pos[sub_num] = cpu_to_le64(cur_pos);

        /*change cur_ei*/
        cur_ei->rden_pos = fpos;
        
        if(par_ei->eno!=1){
            /*reuse len*/
            len = (u64)(par_ei->root_len) + plen;
            pname = kzalloc(sizeof(char)*len, GFP_KERNEL);
            get_zone_path(sb, par_dei, pname, des_de->ful_name->f_name);
            if(strlen(pname)!=len){
                nova_err(sb, "wrong name");
                goto end;
            }
            phash = BKDRHash(pname, len);
            new_dzt_ei->root_len =(u32) len;
            new_dzt_ei->hash_name = phash;
            kfree(pname);
        } else {
            new_dzt_ei->root_len = (u32)plen;
            new_dzt_ei->hash_name = hn;
        }
            
    }
    kfree(name);
    kfree(tem);
    return ret;
}

/*inherit dentry
* make inherit dir invalid*/
void inherit_dentry(struct super_block *sb, struct dzt_entry_info *cur_ei, unsigned long inhe_pos)
{
    struct dafs_zone_entry *cur_ze, *par_ze;
    struct dafs_dentry *inhe_de, *rde, *de;
    struct zone_ptr *cur_p;
    char *iname, *name, *tem;
    u64 namelen;
    u64 bitpos = 0, rde_pos, phlen, nlen, hn, filepos=0, len;
    unsigned long pos;
    int re;

    cur_ze = (struct dafs_zone_entry *)nova_get_block(sb, cur_ei->dz_addr);
    inhe_de = cur_ze->dentry[inhe_pos];
    namelen = le64_to_cpu(inhe_de->ful_name->f_namelen);
    iname = kzalloc((namelen+1)*sizeof(char), GFP_KERNEL);
    memcpy(iname, inhe_de->ful_name->f_name, namelen);

    par_ze = (struct dafs_zone_entry *)nova_get_block(sb, cur_ei->pdz_addr);
    rde_pos = cur_ei->rde_pos;
    rde = par_ze->dentry[rde_pos];
    make_zone_ptr(&cur_p, cur_ze);

    name = kzalloc(DAFS_PATH_LEN*sizeof(char), GFP_ATOMIC);
    tem = kzalloc((namelen+1)*sizeof(char),GFP_ATOMIC);

    while(bitpos<z_p->zone_max){
        bitpos++;
        if(test_bit_le(bitpos, z_p->statemap)){
            de = cur_ze->dentry[filepos];
            plen = de->ful_name->f_namelen;
            nlen = plen - le64_to_cpu(de->name_len); 
            memcpy(name, de->ful_name->f_name, nlen);
            memcpy(name+plen, "\0", 1);
            /*special for inherit dentry*/
            if(plen!=namelen ){
                memcpy(tem, name, namelen);
                re = strcmp(tem,iname);
                /*not equal then continue*/
                if(re){
                    hn = BKDRHash(name, nlen);
                    if(hn == cur_ei->hash_name){
                        pos = filepos;
                        __inherit_dentry(sb, cur_ei, pos, rde);
                    } else {
                        hn = get_par_hn(name, cur_ei->hash_name, &len);
                        if(!hn)
                            nova_err(sb, "can not find par dir");
                        ret = lookup_in_hashtable(cur_ei->ht_head, hn, len, 1, &pos);
                        __inherit_dentry(sb, cur_ei, pos, rde);
                    }
                }
            }
        }
        bitpos++;
        filepos++;
    }
    kfree(iname);
    kfree(tem);
    kfree(name);

}

/*find invalid dentry in zone
* start pos = start dentry id*/
static unsigned long find_invalid_id(struct zone_ptr *z_p, unsigned long start_id)
{
    struct dafs_dentry *dafs_de;
    unsigned long bitpos = start_id*2;
    while(bitpos<z_p->zone_max){
        if(test_bit_le(bitpos, z_p->statemap)){
            bitpos+=2;
            start_id++;
            continue;
        }else{
            bitpos++;
            if(test_bit_le(bitpos, z_p->statemap)){
                bitpos++;
                start_id++;
            }else{
                break;
            }
        }
    }

    return start_id;
}



/*====================================== self adaption strategy==============================================*/

/*
* record mean frequency 
* bring reference(&) in*/
int dafs_rec_mf(struct dzt_entry_info *ei)
{
    struct rf_entry *rf_e;
    struct rf_entry *entries[NR_DENTRY_IN_ZONE];
    int nr,i,rcount=0;
    int mean = 0;

    nr = radix_tree_gang_lookup(&ei->rf_root, (void **)entries, 0, NR_DENTRY_IN_ZONE);
    for(i=0; i<nr; i++){
        rf_e = entries[i];
        rcount+=rf_e->r_f;
    }

    mean = rcount/(nr);
    return mean;
}


/*
* 2012/09/12
* change zone
* conditions for self-adaption within zones*/
int dafs_change_condition(struct super_block *sb)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
}

/*
* set state in statemap for each zone*/
int zone_set_statemap(struct super_block *sb, struct dafs_zone_entry *ze)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    //struct dafs_zone_entry *ze;
    struct zone_ptr *z_p;
    struct dafs_dentry *dafs_de;
    struct dafs_dzt_entry *dzt_e;
    struct dzt_entry_info *par_ei;
    unsigned long bitpos = 0;
    int mean;
    int statement;
    int id = 0;
    int ret = 0;
    u64 par_eno;

    par_eno = le64_to_cpu(ze->dz_no);
    par_ei = DAFS_GET_EI(sb, par_eno);

    make_zone_ptr(&z_p, ze);

    //mean = dafs_rec_mf(par_ei);

    while(bitpos < z_p->zone_max){
        if((!test_bit_le(bitpos, z_p->statemap)) && (!test_bit_le(bitpos+1, z_p->statemap))){
            bitpos+=2;
            id++;

        }else{      
            dafs_de = ze->dentry[id];
            statement = set_dentry_state(dafs_de, par_ei);
            
            if(statement == STATEMAP_COLD){
                test_and_clear_bit_le(bitpos, z_p->statemap);
                bitpos++;
                test_and_set_bit_le(bitpos, z_p->statemap);
                bitpos++;

            }else if(statement == STATEMAP_WARM){
                test_and_set_bit_le(bitpos, z_p->statemap);
                bitpos++:
                test_and_clear_bit_le(bitpos, z_p->statemap);
                bitpos++;

            }else if(statement == STATEMAP_HOT){
                test_and_set_bit_le(bitpos, z_p->statemap);
                bitpos++:
                test_and_set_bit_le(bitpos, z_p->statemap);
                bitpos++;

            }
            id++;

        }    
        
    }

    return ret;
    
}

/*
* set dentry state
* return statemap value*/
unsigned long set_dentry_state(struct dafs_dentry *dafs_de, struct dzt_entry_info *ei)
{
    struct rf_entry *rf_e;
    unsigned long statement = STATEMAP_COLD;
    int mean;
    int st_sub = STARDARD_SUBFILE_NUM;
    int rcount;
    int sub_s=0;
    int f_s;
    u64 sub_num, hashname, name_len;
    

    if(dafs_de->file_type==ROOT_DIRECTORY){
        return statement;
    }

    mean = dafs_rec_mf(ei);

    name_len = le64_to_cpu(dafs_de->ful_name->f_namelen);
    hashname = BKDRHash(dafs_de->ful_name->f_name, name_len);
    rf_e = radix_tree_lookup(&ei->rf_root, hashname);
    rcount = rf_e->r_f;
    //rcount = le64_to_cpu(dafs_de->rcount);
    
    /*check and set frequency state and subfiles state*/
    if(dafs_de->file_type == NORMAL_DIRECTORY ){            
        sub_num = le64_to_cpu(dafs_de->sub_num);
        if(sub_num < NR_ZONE_FILES)
            sub_s = NUMBER_OF_SUBFILES_FEW;         //not decided,few=1,large=2,none=0
        else 
            sub_s = NUMBER_OF_SUBFILES_LARGE;
        rf_e->sub_s = sub_s;
    }

    //rf_e->sub_s = sub_s;

    //sub_s = le64_to_cpu(dafs_de->sub_s);
    //f_s = le64_to_cpu(dafs_de->f_s);

    if(rf_e->f_s!=DENTRY_FREQUENCY_WRITE)
    {
        if(rcount < mean){
            f_s = DENTRY_FREQUENCY_COLD;
            //dafs_de->f_s = cpu_to_le64(f_s);
        }else{
            f_s = DENTRY_FREQUENCY_WARM;
            //dafs_de->f_s = cpu_to_le64(f_s);
        }
        rf_e->f_s = f_s;
    }

    /*sub_s=0 =>is a file, or . ..
    * sub =1, 2 => is NORMAL_DIRECTORY */
    if(sub_s){
        if(sub_s==NUMBER_OF_SUBFILES_FEW && f_s!= DENTRY_FREQUENCY_WRITE){

            statement = STATEMAP_COLD;
            rf_e->prio = LEVEL_1;
            //dafs_de->prio = LEVEL_1;

        }else if(sub_s==NUMBER_OF_SUBFILES_LARGE && f_s==DENTRY_FREQUENCY_COLD){
            
            statement = STATEMAP_WARM;
            rf_e->prio = LEVEL_2;
            //dafs_de->prio = LEVEL_2;

        }else if(sub_s==NUMBER_OF_SUBFILES_FEW && f_S==DENTRY_FREQUENCY_WRITE){
            
            statement = STATEMAP_WARM;
            rf_e->prio = LEVEL_2;
            //dafs_de->prio = LEVEL_2;

        }else if(sub_s==NUMBER_OF_SUBFILES_LARGE && f_s==DENTRY_FREQUENCY_WARM){
            
            statement = STATEMAP_HOT;
            rf_e->prio = LEVEL_3;
            //dafs_de->prio = LEVEL_3;

        }else if(sub_s==NUMBER_OF_SUBFILES_LARGE && f_s==DENTRY_FREQUENCY_WRITE){
            statement = STATEMAP_HOT;
            rf_e->prio = LEVEL_4;
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

/*
* check if zone directory size is large for merge and inherit */
static void check_zone_rlarge(struct super_block *sb, struct dzt_entry_info *cur_ei)
{
    struct dafs_dentry *dafs_rde;
    struct dafs_zone_entry *par_ze;
    unsigned long sub_s;

    par_ze = (struct dafs_zone_entry *)nova_get_block(sb, cur_ei->pdz_addr);
    dafs_rde = par_ze->dentry[cur_ei->rden_pos];

    sub_s = le64_to_cpu(dafs_rde->sub_s);
    return sub_s;
}

/*
* check zones
* 1. positive split
* 2. negtive split
* 3. merge
* 4. inherit*/
int dafs_check_zones(struct super_block *sb, struct dzt_entry_info *dzt_ei)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dafs_zone_entry *z_e;
    struct zone_ptr *z_p;
    struct dafs_dentry *dafs_de;
    unsigned long bitpos = 0;
    uint64_t prio = NULL;
    int hot_num = 0;
    int cold_num = 0;
    int warm_num = 0;
    int id = 0;
    int cd_no = NULL;          /**/
    //int hd = 0;                /* counter for positive split*/
    int hd_no[NR_DENTRY_IN_ZONE] = NULL;          /* hot dentry NO, not decided how many */
    int ret = 0;
    unsigned long sp_id = 0;      /* impossible for pos_0 */
    int i;
    unsigned long inh_id = 0;

    /*not decided*/
    z_e = (struct dafs_zone_entry *)nova_get_block(sb, dzt_ei->dz_addr);
    make_zone_ptr(&z_p, z_e);

    while(bitpos < z_p->zone_max){
        if((!test_bit_le(bitpos, z_p->statemap))){
            bitpos++;
            if(!test_bit_le(bitpos, z_p->statemap)){
                bitpos++;
                id++;
            }else{
                bitpos++;
                cold_num++;
                id++;
            }

        }else{
            bitpos++;
            if(!test_bit_le(bitpos, z_p->statemap)){
                bitpos++;
                warm_num++;
                id++;
            }else{
                bitpos++;
                hd_no[hot_num] = id;
                hot_num++;
                id++;
            }

        }
    }
    if(warm_num == 0 && hot_num ==1){
        if(check_zone_rlarge(sb, dzt_ei)!= NUMBER_OF_SUBFILES_LARGE)
            inh_id = hd_np[0];
            dafs_inh_zone(sb, dzt_ei, inh_id, z_e);
    
    } else if(hot_num == 0){
        if(check_zone_rlarge(sb, dzt_ei)!=NUMBER_OF_SUBFILES_LARGE)
            dafs_merge_zone(sb, dzt_ei, z_e);           /* not decided*/

    }else if(hd!=0){
        for(i=0;i<hot_num;i++){
            sp_id = hd_no[i];
            dafs_de = z_e->dentry[sp_id];
            prio = le_to_cpu(dafs_de->prio);
            if(prio == LEVEL_4){
                dafs_split_zone(sb, dzt_ei, z_e, sp_id, POSITIVE_SPLIT);     /*not decided*/
                /*每次只分裂一次,避免子和父文件夹冲突 not decided*/
                goto RET;
            }
            //dafs_split_zone(sb, dzt_ei, z_e, id, POSITIVE_SPLIT);     /*not decided*/
        }
        if(prio == LEVEL_3){
            dafs_split_zone(sb, dzt_ei, z_e, sp_id, POSITIVE_SPLIT);     /*not decided*/
            /*每次只分裂一次,避免子和父文件夹冲突 not decided*/
            goto RET;
        }
    }

RET: 
    return ret;
}


/*
* split zone 
* s_pos split pos
* sp_id split id*/
int dafs_split_zone(struct super_block *sb, struct dzt_entry_info *par_dzt_ei,\
                    struct dafs_zone_entry *par_ze, unsigned long sp_id, int SPLIT_TYPE)
{
    struct zone_ptr *z_p;
    //struct dafs_dentry *dafs_rde;
    struct dzt_entry_info *new_dzt_ei;
    struct dafs_zone_entry *new_ze;
    struct rf_e;
    int bitpos = 0;
    int ret = 0;
    int ne_id = 0;
    u64 name_len, hashname;

    if(SPLIT_TYPE == POSITIVE_SPLIT){
        //dafs_rde = par_ze->dentry[sp_id];
        new_dzt_ei = add_dzt_entry(sb, par_dzt_ei, sp_id);
        new_dzt_e = append_dzt_entry(sb, new_dzt_ei);
        new_ze = alloc_mi_zone(sb, new_dzt_e, new_dzt_ei, sp_id);
        goto ret;

    }else if(SPLIT_TYPE == NEGTIVE_SPLIT){
        make_zone_ptr(&z_p, par_ze);
        /* could split one time */
        while(bitpos<z_p->zone_max){
            if(test_bit_le(bitpos, z_p->statemap)){
                bitpos++;
                if(test_bit_le(bitpos, z_p->statemap)){
                    dafs_de = par_ze->dentry[ne_id];
                    name_len = le64_to_cpu(dafs_de->ful_name->f_namelen);
                    hashname = BKDRHash(dafs_de->ful_name->f_name, name_len);
                    rf_e = radix_tree_lookup(&par_dzt_ei->rf_root, hashname);
                    if(rf_e->prio==LEVEL_3 || rf_e->prio==LEVEL_4){
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
                neg_id++;
            }
        }
        
    }

ret:
    /*reset statemap in detail*/

    return ret;
}


/*
*2017/09/12
* merge zone
* 1.small zone or cold zone will merge together
* 2.subdirectory has more files will take place of parent dir to be root dir**/
int dafs_merge_zone(struct super_block *sb, struct dzt_entry_info *cur_rdei, struct dafs_zone_entry *cur_ze)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dzt_manager *dzt_m = sbi->dzt_m_info;
    struct dafs_dentry *dafs_orde, *dafs_nrde;
    struct dafs_zone_entry *par_ze;
    struct hash_table *ht;
    //struct zone_ptr *src_p, *des_p;
    struct dzt_ptr *dzt_p;
    unsigned long hash_name, ch_pos, or_pos;
    u64 tail, tem, eno;

    /*delete entry info
    * delete dzt on nvm*/
    hash_name = cur_rdei->hash_name;
    radix_tree_delete(&dzt_m->dzt_root, hash_name);
    make_dzt_ptr(sbi, &dzt_p);
    ch_pos = cur_rdei->dzt_eno;
    test_and_clear_bit_le(ch_pos, dzt_p->bitmap);

    /* find and modify old_root dentry*/
    par_ze = (struct dafs_zone_entry *)nova_get_block(sb, cur_rdei->pdz_addr);
    or_pos = cur_rdei->rden_pos;
    dafs_orde = par_ze->dentry[or_pos];
    dafs_orde->file_type = NORMAL_DIRECTORY;
    dafs_orde->mtime = CURRENT_TIME_SEC.tv_sec;
    dafs_orde->vroot = 0;
    dafs_orde->dzt_hn = 0;

    /*merge, cur_rdei is not used*/
    merge_dentry(sb, cur_rdei);
    
    /*delete rf tree*/
    delete_rf_tree(cur_rdei);

    /* kfree redi
     * free hash table
     * free zone
    *  */

    tail = le64_to_cpu(cur_rdei->ht_head);
    while(tail){
        ht = (struct hash_table *)tail;
        tem = le64_to_cpu(ht->hash_tail);
        dafs_free_htable_blocks(sb, HTABLE_SIZE, tail>>PAGE_SHIFT, 1);
        tail = tem;
    }
    dafs_free_zone_blocks(sb, cur_rdei, cur_rdei->dz_addr >> PAGE_SHIFT, 1);
    kfree(cur_rdei);
    
    return 0;

}

/*
 * inherit zone
 * when parent is not stranger than childs 
 * nr_pos >> new root pos
 * or_pos >> old root pos*/
int dafs_inh_zone(struct super_block *sb, struct dzt_entry_info *cur_rdei, struct unsigned long *nr_pos,
                 struct dafs_zone_entry *cur_ze)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dzt_manager *dzt_m = sbi->dzt_m_info;
    struct dafs_zone_entry *par_ze;
    struct dafs_dentry *dafs_orde, *dafs_nrde;
    struct dzt_ptr *dzt_p;
    //struct zone_ptr *z_cp, *z_pp;
    unsigned long hash_name, cur_namelen;
    unsigned long ch_pos, or_pos;

    /*delete eni from radix tree*/
    make_dzt_ptr(sbi, &dzt_p);
    ch_pos = cur_rdei->dzt_eno;
    hash_name = cur_rdei->hash_name;
    radix_tree_delete(&dzt_m->dzt_root, hash_name);
    test_and_clear_bit(ch_pos, dzt_p->bitmap);

    /*find old root dentry and modify*/
    par_ze = (struct dafs_zone_entry *)nova_get_block(sb, cur_rdei->pdz_addr);
    or_pos = cur_rdei->rden_pos;
    dafs_orde = par_ze->dentry[or_pos];
    dafs_orde->file_type = NORMAL_DIRECTORY;
    dafs_orde->mtime = CURRENT_TIME_SEC.tv_sec;
    dafs_orde->vroot = 0;
    dafs_orde->dzt_hn = 0;
    

    /*modify new root dentry, atomic finished*/
    dafs_nrde = cur_ze->dentry[nr_pos];
    dafs_nrde->file_type = INHE_ROOT_DIRECTORY;
    
    /*merge for inherit*/
    inherit_dentry(sb, cur_r_dei, nr_pos);

    /* insert cur_rdei and make dirty*/
    radix_tree_insert(&dzt_m->dzt_root, cur_rdei->hash_name, cur_rdei);
    radix_tree_tag_set(&dzt_m->dzt_root, cur_rdei->hash_name, 1);

    /* make valid*/
    test_and_set_bit_le(ch_pos, dzt_p->bitmap);

}
==============================================free zone======================================================
void free_zone_area(struct super_block *sb, struct dzt_entry_info *dzt_ei)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dzt_ptr *dzt_p;
    u64 tail, tem, eno;
    struct hash_table *ht;

    /*make dzt invalid*/
    eno = dzt_ei->dzt_eno;
    make_dzt_ptr(sbi, *dzt_p);
    test_and_clear_bit_le(eno, dzt_p->bitmap);

    /*delete rf tree*/
    delete_rf_tree(dzt_ei);

    /* kfree redi
     * free hash table
     * free zone
    *  */

    tail = le64_to_cpu(dzt_ei->ht_head);
    while(tail){
        ht = (struct hash_table *)tail;
        tem = le64_to_cpu(ht->hash_tail);
        dafs_free_htable_blocks(sb, HTABLE_SIZE, tail>>PAGE_SHIFT, 1);
        tail = tem;
    }
    dafs_free_zone_blocks(sb, dzt_ei, dzt_ei->dz_addr >> PAGE_SHIFT, 1);
    kfree(dzt_ei);
}
