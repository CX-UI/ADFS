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
}

/*
* 2017/09/12
* init dir_zone*/
int dafs_init_dir_zone(struct super_block *sb)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct dafs_dir_zone *dir_zone;
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
* new zone
* 1.big enough direcotries will becomes a new zone
* 2.hot enough e.g frequently renames & chmod dir will becomes new zone*/
int dafs_new_dir_zone(struct super_block *sb)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
}

/*
* 2012/09/12
* change zone
* conditions for self-adaption within zones*/
int dafs_change_condition(struct super_block *sb)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
