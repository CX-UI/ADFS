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
    int ret = 0;

    /*init linux root directory '/' 
    * dir zone no is pos in bitmap*/
    dzt_block = dafs_get_dzt_block(sbi);
    dzt_block-> dzt_entry[0].root_len = 1;
    dzt_block-> dzt_entry[0].dzt_eno = 0;
    dzt_block-> dzt_entry[0].dz_no = 0;
    dzt_block-> dzt_entry[0].dz_addr = ROOT_ZONE_ADDR;            //not decided yet
    dzt_block-> dzt_entry[0].hash_name = NULL;                  //not decided yet
    dzt_block-> dzt_entry[0].child_dzt_addr = NULL;            // init NULL
    // dzt_block-> dzt_entry[0].path_name = "/";    
    dzt_block->dzt_bitmap[0] = (1 << 0) | (1 << 1); 

    /*alloc zone area*/
    dafs_alloc_dir_zone(sbi, dzt_block->dzt_entry[0].dz_addr);
    
    /*init dir_zone*/
    /*append . and .. into new zone*/
    dafs_init_dir_zone(sbi, dzt_block->dzt_entry[0].path_name);
    
    /*build radix search tree*/ 
    dafs_build_dzt(sbi, dzt_block->dzt_entry[0]);

    return ret;
}

/*
* 2017/09/12
* init dir_zone*/
int dafs_init_dir_zone(struct super_block *sb, struct dafs_dzt_entry *dzt_e, \
                       char *root_path, uint64_t parent_ino, uint64_t size)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dafs_zone_entry *zone_entry;
    struct zone_ptr *z_p;
    unsigned long bitpos = 0;
    int i;

    
    zone_entry->zone_blk_type = DAFS_BLOCK_TYPE_512K;         /* not decided */
    //zone_entry->root_len = dzt_e-> root_len;
    //zone_entry->log_head = NULL;               /*not decided*/
    zone_entry->dz_no = dzt_e->dzt_eno;
    //zone_entry->dz_size = DAFS_DEF_ZONE_SIZE;        /*default size is 512K*/
    zone_entry->root_path = root_path;

    /*sub  file "."*/
    zone_entry->dentry[0].entry_type = DIRECTORY;      /*default file type*/
    zone_entry->dentry[0].name_len = 1;
    zone_entry->dentry[0].links_count = 1;
    zone_entry->dentry[0].mtime = CURRENT_TIME_SEC.tv_sec;
    zone_entry->dentry[0].vroot = 0;
    //zone_entry->dentry[0].path_len = 0;         //besides file name length and root dir
    //zone_entry->dentry[0].size = DAFS_DEF_ZONE_ENTRY_SIZE;
    zone_entry->dentry[0].zone_no = dzt_e->dzt_eno;          //not decided
    //zone_entry->dentry[0].subpos = NULL;
    zone_entry->dentry[0].path = root_path;         /*not decided*/
    zone_entry->dentry[0].name = ".";

    /*sub file ".."*/
    zone_entry->dentry[1].entry_type = DIRECTORY;      /*default file type*/
    zone_entry->dentry[1].name_len = 2;
    zone_entry->dentry[1].links_count = 2;
    zone_entry->dentry[1].mtime = CURRENT_TIME_SEC.tv_sec;
    zone_entry->dentry[1].vroot = 0;
    zone_entry->dentry[1].path_len = 0;         //besides file name length and root dir, not decided
    zone_entry->dentry[1].ino = parent_ino;
    //zone_entry->dentry[1].size = DAFS_DEF_ZONE_ENTRY_SIZE;
    zone_entry->dentry[1].zone_no = NULL;          //not decided
    //zone_entry->dentry[1].subpos = NULL;
    zone_entry->dentry[1].path = NULL;
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
static inline void make_zone_ptr(struct zone_ptr *z_p, struct dafs_zone_entry *z_e){

    z_p->statemap = z_e->zone_statemap;
    z_p->zone_max = NR_DENTRY_IN_ZONE * 2;
    z_p->z_entry = z_e->dentry;
}


/*
* alloc zone action
* 1.big enough direcotries will becomes a new zone
* 2.hot enough e.g frequently renames & chmod dir will becomes new zone*/
int dafs_alloc_dir_zone(struct super_block *sb, struct dafs_dzt_entry *dzt_e,\
                        struct dzt_entry_info *dzt_ei, char *root_path)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    //struct dafs_dzt_entry *dzt_e;
    //struct dzt_entry_info *dzt_ei;
    struct dzt_manager *dzt_m = sbi->dzt_manager;
    unsigned long zone_type = dzt_e->zone_blk_type;
    unsigned long blocknr;
    uint64_t hash_name;
    u64 block;
    int i;
    int allocated;
    unsigned long bp;
    int ret = 0;

    allocated = nova_new_zone_blocks(sb, dzt_e, &blocknr, 1, 1);
    nova_dbg_verbose("%s: allocate zone @ 0x%lx\n", __func__,
							blocknr);
    if(allocated != 1 || blocknr == 0)
        return -ENOMEM;

    block = nova_get_block_off(sb, blocknr, DAFS_BLOCK_TYPE_512K);
    
    /*get zone address*/
    bp = (unsigned long)nova_get_block(sb, block);
    //hash_name = le64_to_cpu(z_entry->dz_root_hash);
    dzt_e->dz_addr = cpu_to_le32(bp);
    dzt_e->dz_log_head = cpu_to_le64(block);
    dzt_ei->dz_log_head = block;
    dzt_ei->dz_addr = bp;
    //not decided
   
    /*not decided set root path and dz_no for new zone*/

    make_dzt_entry_valid(sbi, dzt_e->dzt_eno);

    radix_tree_insert(&dzt_m->dzt_root, dzt_ei->hash_name, dzt_ei);
    
    dafs_init_dir_zone(sb, dzt_e, root_path, );        //not decided

    PERSISTENT_BARRIER();
    return ret;
}   

/*===================================build dzt when start up system ===========================================*/

/* 
* make dzt bitmap pointer*/
void make_dzt_ptr(struct nova_sb_info *sbi, struct dzt_ptr *dzt_p)
{
    struct dafs_dzt_block *dzt_blk;
    //struct dzt_ptr *dzt_p;

    dzt_blk = dafs_get_dzt_block(sbi);

    dzt_p->bitmap = dzt_blk->dzt_bitmap;
    dzt_p->max = DAFS_DZT_ENTRIES_IN_BLOCK;
    dzt_p->dzt_entry = dzt_blk->dzt_entry;
}

/*
 * make dzt entry valid*/
void set_dzt_entry_valid(struct nova_sb_info *sbi, unsigned long bitpos)
{
    //struct dafs_dzt_block *dzt_blk;
    struct dzt_ptr *dzt_p;
    int ret = 0;

    make_dzt_ptr(sbi, dzt_p);

    test_and_set_bit(bitpos, dzt_p->bitmap);

}

/*
* build dzt b-tree*/
int dafs_build_dzt(struct super_block *sb, struct dafs_dzt_entry \
                     *dafs_dzt_entry)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dzt_entry_info *entry_info;
    struct dzt_manager *dzt_m;
    int ret = 0;
    //struct dzt_entry *dzt_entry;

    /*take into acount when to destroy this entry*/
    //entry_info = kzalloc(sizeof(struct dzt_entry_info), GFP_KERNEL);  //move dzt entry into DRAM B-tree
    
    if(!dzt_entry)
        return -ENOMEM;
    entry_info->root_len = le32_to_cpu(dafs_dzt_entry->root_len);
    entry_info->dzt_eno = le64_to_cpu(dafs_dzt_entry->dzt_eno);
    entry_info->dz_no = le64_to_cpu(dafs_dzt_entry->dz_no);
    entry_info->dz_addr = le64_to_cpu(dafs_dzt_entry->dz_addr);
    entry_info->hash_name = le64_to_cpu(dafs_dzt_entry->hash_name);

    INIT_LIST_HEAD(&entry_info->child_list);

    dzt_m = kzalloc(sizeof(struct dzt_manager), GFP_KERNEL);

    if(!dzt_m)
        return -ENOMEM;
    
    INIT_RADIX_TREE(&dzt_m->dzt_root);

    make_dzt_tree(entry_info);
    
    return ret;
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

        make_dzt_tree(dzt_ei);
    }

    return ret;
}

/*
 * make radix tree by inserting*/
int make_dzt_tree(struct nova_sb_info *sbi, struct dzt_entry_info *dzt_ei)
{
    struct dzt_entry_info *dzt_entry_info;
    struct dzt_manager *dzt_m = sbi->dzt_manager;
    int ret = 0;

    dzt_entry_info = kzalloc(sizeof(struct dzt_entry_info), GFP_KERNEL);
    dzt_entry_info->root_len = dzt_ei->root_len;
    dzt_entry_info->dzt_eno = dzt_ei->dzt_eno;
    dzt_entry_info->dz_no = dzt_ei->dz_no;
    dzt_entry_info->dz_addr = dzt_ei->dz_addr;
    dzt_entry_info->hash_name = dzt_ei->hash_name;

    radix_tree_insert(&dzt_m->dzt_root, dzt_entry_info->hash_name, dzt_entry_info);

    return ret;
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

/*========================================== dzt adaption ===================================================*/

/*
* add dzt entries in DRAM*/
int add_dzt_entry(struct super_block *sb, struct dzt_entry_info *par_dei,\
                 struct dafs_dentry *dafs_de, dafs_zone_entry *par_ze)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dafs_dzt_entry *dzt_e;
    struct dzt_entry_info *dzt_ei;
    struct dzt_manager *dzt_m = sbi->dzt_manager;
    //struct dafs_dzt_block *dzt_blk;
    //struct dzt_ptr *dzt_p;
    uint32_t name_len;
    unsigned long eno_pos; 
    char root_path[DAFS_PATH_LEN];
    int ret = 0;

    
    eno_pos = alloc_dzt_entry(sb);

    if(!eno_pos)
        got ERR;             //not decided
    /* modify dzt_eno, dz_log_head, dz_addr */
    
    
    memcpy(root_path[0],par_ze->root_path, par_dei->root_len);
    memcpy(root_path[root_len+1], dafs_de->name, dafs_de->name_len);
    name_len = strlen(root_path);

    dzt_ei = kzalloc(sizeof(struct dzt_entry_info), GFP_KERNEL);
    dzt_ei->zone_blk_type = DAFS_BLOCK_TYPE_512K;
    dzt_ei->name_len = name_len;
    dzt_ei->dzt_eno = eno_pos;
    dzt_ei->hash_name = dafs_hash(root_path,name_len);       //not decided
    
    /*dzt_blk = dafs_get_dzt_block(sbi);
    dzt_e = dzt_blk->dzt_entry[bitpos];
    dzt_e->zoon_blk_type = cpu_to_le64(dzt_ei->zoon_blk_type);
    dzt_e->root_len = cpu_to_le64(dzt_ei->root_len);
    dzt_e->dzt_eno = cpu_to_le64(dzt_ei->dzt_eno);
    dzt_e->dz_sf = cpu_to_le64(dzt_ei->dz_sf);*/

    /* add entry in parent child list make par dirty, seriously not decided*/



    /* DRAM 中新建entry的时候一定是split zone的时候，不需要condition验证*/
    ret = append_dzt_entry(sb, dzt_ei, root_path, SPLIT_ZONE);

    return ret;

ERR: 
    return err;
}

/*
*alloc dzt_entry
* 1. append at tail 
* 2. scan bitmap */
uint64_t alloc_dzt_entry(struct super_block *sb)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);  
    struct dafs_dzt_block *dzt_blk;
    struct dzt_ptr *dzt_p;
    unsigned long tail_pos;
    unsigned long bitpos;
    unsigned long i;
    
    dzt_blk = dafs_get_dzt_block(sbi);
    tail_pos = le64_to_cpu(dzt_blk->dzt_tail_pos);

    make_dzt_ptr(sbi, dzt_p);
    if(!test_bit(tail_pos, dzt_p->bitmap)){
        // not decided  清空
        i = tail_pos;
        i++;
        dzt_blk->dzt_tail_pos = cpu_to_le64(i);      //not decided 原子性
        return tail_pos;
    }
    while(bitpos < dzt_p->max){
        if(!test_bit(bitpos, dzt_p->bitmap))
        {
            //not decided 清空
            break;
        }
        else
            bitpos++;
    }
    if(bitpos==dzt_p->max)
        goto FULL;                            //not decided, dzt is full
    
    return bitpos;


FULL:
    return NULL;
}

/*
* append dzt_entry in NVM
* set append condition to decide whether alloc zones*/
int append_dzt_entry(struct super_block *sb, struct dzt_entry_info *dzt_ei,\
                    char *path_name, int AP_CON)
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
    dzt_e->dz_sf = cpu_to_le64(dzt_ei->dz_sf);
    dzt_e->hash_name = cpu_to_le64(dzt_ei->hash_name);
    /* not decided sub files */
    
    if(AP_CON == SPLIT_ZONE){
        ret = dafs_alloc_dir_zone(sb, dzt_e, dzt_ei, path_name);
    }

    return ret;
}

/*
* hash algrithm*/
uint64_t dafs_hash(){
    //not decided
}

/*
* migrate zone entries */
int migrate_zone_entry(struct zone_ptr *z_p, unsigned long ch_pos, struct dafs_dzt_entry *dzt_ne\
                      struct dafs_zone_entry *old_z_e, struct dafs_zone_entry *new_z_e)
{
    //struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dafs_dentry *dafs_nde, *dafs_ode, *dafs_rde;
    unsigned long old_id, ch_len, old_namelen, sub_no;
    unsigned long ch_no[NR_DENTRY_IN_ZONE];
    unsigned long sub_pos[NR_DENTRY_IN_ZONE];
    unsigned long bitpos = 0;
    unsigned long new_id = 0;
    int i = 0;
    int oi = 0;
    int ret = 0;
    
    dafs_rde = old_z_e->dentry[ch_pos];
    /*clear statemap of new zone*/
    memset(new_z_e->statemap, 0, SIZE_DZT_BITMAP);
    //new_z_e->dz_no = dzt_ne->dzt_eno;
    //old_namelen = dafs_rde->name_len;

    memcpy(ch_no[0],dafs_rde->sub_pos, dafs_rde->sub_num);
    ch_len = dafs_rde->sub_num;

    /*递归*/

    cpy_new_zentry(z_p, new_z_e, old_z_e, dafs_rde, ch_no, 0);
    
    /* modify root dentry */
    dafs_rde->file_type = ROOT_DIRECTORY;
    dafs_rde->vroot = 1;
    dafs_rde->zoon_no = dzt_ne->dzt_eno;
    dafs_rde->sub_pos = NULL;
    return ret;
}

/*
*copy andd get new zone_dentry 
*递归*/
static inline void cpy_new_zentry(struct zone_ptr *z_p,\
                                  struct dafs_zone_entry *new_z_e, struct dafs_zone_dentry *old_z_e,\
                                 struct dafs_dentry *r_ze, unsigned long *ch_no, unsigned long ch_pos)
{
    struct dafs_dentry *new_ze, *old_ze;
    unsigned long old_len = r_ze->name_len;
    char name[NOVA_NAME_LEN]; 
    unsigned long  i,j,k,old_id;
    unsigned long ch_len;
    unsigned long new_id = ch_pos;  /* ch_pos initalized as 0*/

    ch_len = r_ze->sub_num;
    for(i=0;i<ch_len;i++){
        old_id = ch_pos[i];
        old_ze = old_z_e->dentry[old_id];
        new_ze = new_z_e->dentry[new_id];
        if(old_ze->file_type == NORMAL_FILE){
            new_ze->entry_type = old_ze->entry_type;
            new_ze->name_len = old_ze->name_len-old_len-1;
            new_ze->file_type = old_ze->file_type;
            new_ze->links_count = old_ze ->links_count;
            new_ze->mtime = CURRENT_TIME_SEC.tv_sec;
            new_ze->vroot = old_ze->vroot;
            new_ze->path_len = old_ze->path_len-old_len;
            new_ze->ino = old_ze->ino;
            new_ze->par_ino = old_ze->par_ino;
            new_ze->size = old_ze->size;
            new_ze->prio = LEVEL_0;
            new_ze->d_f = 0;
            //new_ze->sub_s = old_ze->sub_s;
            new_ze->f_s = DENTRY_FREQUENCY_COLD;

            for(k = 0;k<new_ze->name_len;k++){
                old_len++;
                new_ze->name[k] = old_ze->name[old_len];
            }
            /*atomic*/
            set_bit_le(new_id, z_p->statemap);
            new_id++;

        }else if(old_ze->file_type == ROOT_DIRECTORY){
            new_ze->entry_type = old_ze->entry_type;
            new_ze->name_len = old_ze->name_len-old_len-1;
            new_ze->file_type = old_ze->file_type;
            new_ze->links_count = old_ze ->links_count;
            new_ze->mtime = CURRENT_TIME_SEC.tv_sec;
            new_ze->vroot = old_ze->vroot;
            new_ze->path_len = old_ze->path_len-old_len;
            new_ze->ino = old_ze->ino;
            new_ze->par_ino = old_ze->par_ino;
            new_ze->size = old_ze->size;
            new_ze->zone_no = old_ze->zone_no;
            new_ze->prio = LEVEL_0;
            new_ze->d_f = 0;
            new_ze->sub_s = old_ze->sub_s;
            new_ze->f_s = DENTRY_FREQUENCY_COLD;
            new_ze->sub_num = old_ze->sub_num;

            for(k = 0;k<new_ze->name_len;k++){
                old_len++;
                new_ze->name[k] = old_ze->name[old_len];
            }
            
            set_bit_le(new_id,z_p->statemap);
            new_id++;

        }else if(old_ze->file_type == NORMAL_DIRECTORY){
                    
            new_ze->entry_type = old_ze->entry_type;
            new_ze->name_len = old_ze->name_len-old_len-1;
            new_ze->file_type = old_ze->file_type;
            new_ze->links_count = old_ze ->links_count;
            new_ze->mtime = CURRENT_TIME_SEC.tv_sec;
            new_ze->vroot = old_ze->vroot;
            new_ze->path_len = old_ze->path_len-old_len;
            new_ze->ino = old_ze->ino;
            new_ze->par_ino = old_ze->par_ino;
            new_ze->size = old_ze->size;
            new_ze->prio = LEVEL_0;
            new_ze->d_f = 0;
            new_ze->sub_s = old_ze->sub_s;
            new_ze->f_s = DENTRY_FREQUENCY_COLD;
            new_ze->sub_num = old_ze->sub_num;
            
            for(j=0;j<new_ze->sub_num;j++){
                new_ze->sub_pos[j] = new_id + j + 1;
            }
            
            for(k = 0;k<new_ze->name_len;k++){
                old_len++;
                new_ze->name[k] = old_ze->name[old_len];
            }
            
            set_bit_le(new_id,z_p->statemap);
            new_id++;
            
            memcpy(sub_no[0],old_ze->sub_pos,old_ze->sub_num);
            cpy_new_zentry(z_p, new_z_e, old_z_e, r_ze, sub_no, new_id);

        }

    } 
    
}

/*
* reset statemap*/
void reset_statemap(struct super_block *sb, struct zone_ptr *z_p, struct dafs_zone_entry *z_e,\
                  struct dzt_entry_info *dzt_par_ei,  unsigned long ch_pos)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dafs_dentry *dafs_de;
    unsigned long bitpos = 0;
    unsigned long ch_no[NR_DENTRY_IN_ZONE];
    unsigned long ch_len;
    unsigned long id;
    int i;

    dafs_de = z_e->dentry[ch_pos];

    /* not change at root dir entry*/
    // ch_no[0] = ch_pos;
    memcpy(ch_no[0], dafs_de->sub_pos, sub_num);
    ch_len = sub_num;
    //ch_len = strlen(ch_no);
    
    for(i=0;i<ch_len;i++){
        bitpos = ch_no[i];
        dzt_par_ei->dz_sf -= z_e->dentry[bitpos]->d_f;
        test_and_clear_bit_le(bitpos, z_p->statemap);
        bitpos++;
        test_and_clear_bit_le(bitpos, z_p->statemap);
    }
   
    for(bitpos<z_p->zone_max){
        if((!test_bit_le(bitpos, z_p->zone_max))&&(!test_bit_le(bitpos+1, z_p->zone_max))){
            bitpos+=2;
            id++;
        }else{
            set_dentry_state(z_e, dzt_par_ei, z_e->dentry[id]);
            id++;
        }
    }

}

/*====================================== self adaption strategy==============================================*/

/*
* record mean frequency 
* bring reference(&) in*/
uint64_t dafs_rec_mf(struct dafs_zone_entry *z_e, struct dzt_entry_info *ei)
{
    struct zone_ptr *z_p;
    unsigned long bitpos = 0;
    uint64_t sum = ei->dz_sf;
    uint64_t mean;
    int i=0;

    make_zone_ptr(z_p, z_e);
    while(bitpos < z_p->zone_max){
        if(!test_bit_le(bitpos, z_p->statemap)){
            bit_pos++;
            if(test_bit_le(bitpos, z_p->statemap)){
                bitpos++;
                i++;
            }else
                bitpos++;
        }else{
            bitpos+=2;
            i++;
        }
    }
    
    mean = sum/i;

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
int zone_set_statemap(struct super_block *sb, struct dzt_entry_info *dzt_ei,\ 
                   struct dafs_zone_entry *z_e)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    //struct dafs_zone_entry *z_e;
    struct zone_ptr *z_p;
    struct dafs_dentry *dafs_de;
    struct dafs_dzt_entry *dzt_e;
    //struct dzt_entry_info *dzt_ei;
    unsigned long bitpos = 0;
    uint64_t mean;
    int statement;
    int id = 0;
    int ret = 0;

    make_zone_ptr(z_p, z_e);

    mean = dafs_rec_mf(z_e, dzt_ei);

    while(bitpos < z_p->zone_max){
        if((!test_bit_le(bitpos, z_p->statemap)) && (!test_bit_le(bitpos+1, z_p->statemap))){
            bitpos+=2;
            id++;

        }else{      
            dafs_de = z_e->dentry[id];
            statement = set_dentry_state(z_e, dzt_ei, dafs_de);
            
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
int set_dentry_state(struct dafs_zone_entry *z_e, struct dzt_entry_info dzt_ei,\
                     struct dafs_dentry *dafs_de)
{
    int statement = STATEMAP_COLD;
    uint64_t mean;
    uint64_t st_sub = STARDARD_SUBFILE_NUM;
    uint64_t d_f;
    uint64_t sub_s;
    uint64_t f_s;
    uint64_t sub_num;

    mean = dafs_rec_mf(z_e, dzt_ei); 
    d_f = le64_to_cpu(dafs_de->d_f);
    
    if(dafs_de->file_type == NORMAL_DIRECTORY ){                   //not decided, not including . and ..
        sub_num = le64_to_cpu(dafs_de->sub_num);
    }
    else
        sub_num = NULL;

    if(!sub_num){
        if(sub_num < st_sub)
            sub_s = NUMBER_OF_SUBFILES_FEW;         //not decided
        else 
            sub_s = NUMBER_OF_SUBFILES_LARGE;
    }
    else
        sub_s = NULL;

    //sub_s = le64_to_cpu(dafs_de->sub_s);
    //f_s = le64_to_cpu(dafs_de->f_s);

    if(d_f < mean){
        f_s = DENTRY_FREQUENCY_COLD;
        dafs_de->f_s = cpu_to_le64(f_s);
    }else{
        f_s = DENTRY_FREQUENCY_WARM;
        dafs_de->f_s = cpu_to_le64(f_s);
    }
    
    if(!sub_s){
        if(sub_s==NUMBER_OF_SUBFILES_FEW && f_s!= DENTRY_FREQUENCY_WRITE){

            statement = STATEMAP_COLD;
            dafs_de->prio = LEVEL_1;

        }else if(sub_s==NUMBER_OF_SUBFILES_LARGE && f_s==DENTRY_FREQUENCY_COLD){
            
            statement = STATEMAP_WARM;
            dafs_de->prio = LEVEL_2;

        }else if(sub_s==NUMBER_OF_SUBFILES_FEW && f_S==DENTRY_FREQUENCY_WRITE){
            
            statement = STATEMAP_WARM;
            dafs_de->prio = LEVEL_2;

        }else if(sub_s==NUMBER_OF_SUBFILES_LARGE && f_s==DENTRY_FREQUENCY_WARM){
            
            statement = STATEMAP_HOT;
            dafs_de->prio = LEVEL_3;

        }else if(sub_s==NUMBER_OF_SUBFILES_LARGE && f_s==DENTRY_FREQUENCY_WRITE){
            statement = STATEMAP_HOT;
            dafs_DE->prio = LEVEL_4;
        }
    }else{
        dafs_de->prio = LEVEL_0;
        if (f_s==DENTRY_FREQUENCY_COLD)
            statemap = STATEMAP_COLD;
        else if (f_s==DENTRY_FREQUENCY_WARM)
            statemap = STATEMAP_WARM;
        else if (f_s==DENTRY_FREQUENCY_WRITE)
            statemap = STATEMAP_HOT;
    }   
    
    return statemap;
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
    int sp_id = 0;      /* impossible for pos_0 */
    int i;


    z_e = dzt_ei->dz_addr;
    make_zone_ptr(z_p, z_e);

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
    if(warm_num = 0)
        dafs_inh_zone();

    else if(hot_num = 0){
        if(check_zone_root())
            dafs_merge_zone();           /* not decided*/

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
            dafs_split_zone(sb, dzt_ei, z_e,sp_id, POSITIVE_SPLIT);     /*not decided*/
            /*每次只分裂一次,避免子和父文件夹冲突 not decided*/
            goto RET;
        }
    }

RET: 
    return ret;
}

/*
* split zone 
* s_pos split pos*/
int dafs_split_zone(struct super_block *sb, struct dzt_entry_info *dzt_ei,\
                    struct dafs_zone_entry *z_e, int id, int SPLIT_TYPE)
{
    struct zone_ptr *z_p;
    struct dafs_dentry *dafs_de;
    int bitpos = 0;
    int ret = 0;
    int ne_id = 0;

    if(SPLIT_TYPE == POSITIVE_SPLIT){
        dafs_de = z_e->dentry[id];
        ret = add_dzt_entry(sb, dzt_ei, dafs_de, z_e);
        goto ret;

    }else if(SPLIT_TYPE == NEGTIVE_SPLIT){
        make_zone_ptr(z_p, z_e);
        /* could split one time */
        while(bitpos<z_p->zone_max){
            if(test_bit_le(bitpos, z_p->statemap)){
                bitpos++;
                if(test_bit_le(bitpos, z_p->statemap)){
                    dafs_de = z_e->dentry[ne_id];
                    if(dafs_de->prio==LEVEL_3 || dafs_de->prio==LEVEL_4){
                        ret = add_dzt_entry(sb, dzt_ei, dafs_de, z_e);
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
* reset statemap*/
void reset_statemap(struct super_block *sb, struct zone_ptr *z_p, struct dafs_zone_entry *z_e,\
                   unsigned long ch_pos )
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dafs_dentry *dafs_de;
    unsigned long bitpos;

    dafs_de = z_e->dentry[ch_pos];
}
/*
*2017/09/12
* merge zone
* 1.small zone or cold zone will merge together
* 2.subdirectory has more files will take place of parent dir to be root dir**/
int dafs_merge_zone(struct super_block *sb)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);

}

/*
 * inherit zone
 * when parent is not stranger than childs */
int dafs_inh_zone(struct super_block *sb)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
}
