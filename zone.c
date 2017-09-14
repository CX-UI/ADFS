/*************************************************************************
	> File Name: zone.c
	> Author:CX
	> Mail: tianfangmmr@126.com
	> Created Time: 2017年09月14日 星期四 13时20分34秒
 ************************************************************************/

#include <stdio.h>
#include "nova.h"


/*
* dafs get dir_zonet_table
* put dir zone table block addresss after journal block*/
static inline
struct dafs_dzt_block *dafs_get_dzt_block(struct super_block *sb)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);

    return (struct dafs_dzt_block *)((char *)nova_get_block(sb,
         NOVA_DEF_BLOCK_SIZE_4K * 2));
}

/*
*init dir zone table */
int dafs_init_dzt(struct super_block *sb)
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
    dzt_block-> dzt_entry[0].child_dzt_addr = NULL;            // init NULL
    dzt_block-> dzt_entry[0].path_name = "/";    
    dzt_block->dzt_bitmap[0] = (1 << 0) | (1 << 1); 

    /*alloc zone area*/
    dafs_alloc_dir_zone(sbi, dzt_block->dzt_entry[0].dz_addr);
    
    /*init dir_zone*/
    /*append . and .. into new zone*/
    dafs_init_dir_zone(sbi, dzt_block->dzt_entry[0].path_name);
    
    /*build b-tree*/ 
    dafs_new_dir_zone(sbi, dzt_block->dzt_entry[0]);

    return ret;
}

/*
* 2017/09/12
* init dir_zone*/
int dafs_init_dir_zone(struct super_block *sb, char *root_path, uint32_t path_len, uint64_t parent_ino)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dafs_dir_zone_entry *zone_entry;
    
    zone_entry->root_len = path_len;
    zone_entry->log_head = NULL;               /*not decided*/
    zone_entry->dz_no = NULL;
    zone_entry->dz_size = DAFS_DEF_ZONE_SIZE;        /*default size is 512K*/
    zone_entry->root_path = root_path;

    /*sub  file "."*/
    zone_entry->dentry[0].entry_type = DIRECTORY;      /*default file type*/
    zone_entry->dentry[0].name_len = 1;
    zone_entry->dentry[0].links_count = 1;
    zone_entry->dentry[0].mtime = CURRENT_TIME_SEC.tv_sec;
    zone_entry->dentry[0].vroot = 0;
    zone_entry->dentry[0].path_len = 0;         //besides file name length and root dir
    zone_entry->dentry[0].size = DAFS_DEF_ZONE_ENTRY_SIZE;
    zone_entry->dentry[0].zone,no = NULL;          //not decided
    zone_entry->dentry[0].subpos = NULL;
    zone_entry->dentry[0].path = NULL;
    zone_entry->dentry[0].name = ".";

    /*sub file ".."*/
    zone_entry->dentry[1].entry_type = DIRECTORY;      /*default file type*/
    zone_entry->dentry[1].name_len = 2;
    zone_entry->dentry[1].links_count = 2;
    zone_entry->dentry[1].mtime = CURRENT_TIME_SEC.tv_sec;
    zone_entry->dentry[1].vroot = 0;
    zone_entry->dentry[1].path_len = 0;         //besides file name length and root dir
    zone_entry->dentry[1].ino = parent_ino;
    zone_entry->dentry[1].size = DAFS_DEF_ZONE_ENTRY_SIZE;
    zone_entry->dentry[1].zone_no = NULL;          //not decided
    zone_entry->dentry[1].subpos = NULL;
    zone_entry->dentry[1].path = NULL;

    /*change 2-bitmap*/
    
}
/*
*2017/09/12
* merge zone
* 1.small zone or cold zone will merge together
* 2.subdirectory has more files will take place of parent dir to be root dir**/
int dafs_merge_dir_zone(struct super_block *sb)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);

}

/*
* 2017/09/12
* alloc zone
* 1.big enough direcotries will becomes a new zone
* 2.hot enough e.g frequently renames & chmod dir will becomes new zone*/
int dafs_alloc_dir_zone(struct super_block *sb)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
}

/*
* build dzt b-tree*/
int dafs_build_dzt(struct super_block *sb, struct dafs_dzt_entry \
                     *dafs_dzt_entry)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dzt_entry_info *entry_info;
    struct dzt_entry *dzt_entry;

    dzt_entry = kzalloc(sizeof(struct dzt_entry), GFP_KERNEL);  //move dzt entry into DRAM B-tree
    
    if(!dzt_entry)
        return -ENOMEM;
    entry_info->root_len = le32_to_cpu(dafs_dzt_entry->root_len);
    entry_info->dzt_eno = le64_to_cpu(dafs_dzt_entry->dzt_eno);
    entry_info->dz_no = le64_to_cpu(dafs_dzt_entry->dz_no);
    entry_info->dz_addr = le64_to_cpu(dafs_dzt_entry->dz_addr);
    
}

/*
* 2012/09/12
* change zone
* conditions for self-adaption within zones*/
int dafs_change_condition(struct super_block *sb)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
}

