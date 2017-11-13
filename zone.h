/*************************************************************************
	> File Name: zone.h
	> Author: CX
	> Mail: tianfangmmr@126.com
	> Created Time: 2017年09月16日 星期六 16时02分43秒
 ************************************************************************/

#ifndef _ZONE_H
#define _ZONE_H

#include <linux/rbtree.h>
#include <linux/types.h>
#endif

#include "nova_def.h"
#include "nova.h"

#define DIR_RENAME 0
#define DIR_RMDIR  1
#define DIR_CREATE 2

/*
 * struct dir_zone
 * learn in f2fs*/
struct dafs_zone_entry{
    //u8 zone_blk_type;         /* record in dzt*/
    u8 zone_statemap[SIZE_OF_ZONE_BITMAP];         /* state and validity for zone dentries*/
    //u8 cpu_id;               /* not decided */
    //__le32 dz_n;             /* not used */
    //__le32 root_len;       /* record in dzt */ 
    //__le64 zone_bitmap[SIZE_OF_ZONE_BITMAP];         /* state and validity for zone dentries*/
    //__le64 log_head;         /*logical address*/
    __le64 dz_no;           /*directory zone NO*/
    //__le64 hash_head;
    //__le64 dz_sf;           /* sum of frequency*/
    //__le64 bm_head;         /*zone bit map address*/
    //__le64 dz_root_hash;         /*root directory of this zone*/
    //__le64 dz_size;         /*zone size*/
    //char root_path[DAFS_PATH_LEN];      /*root path name not decided*/
    struct dafs_dentry dentry[NR_DENTRY_IN_ZONE];	
    // next is same attributes in this zone
}__attribute((__packed__));

/*
 * zone ptr to find response */
struct zone_ptr {
    const void *statemap; /*pointer to 2-bit map*/
    unsigned long zone_max;
    struct dafs_dentry *z_entry;
};


/*
 * dafs dir_struct*/
struct dafs_dentry{
    u8 entry_type;          
    u8 name_len;            /*length of the dentry name*/
    u8 file_type;           /* file type */
    // u8 invalid;             /* invalid or? not used here */
    __le16 links_count;         /* links */
    __le16 de_len;
    //__le16 de_len;          /* length of this dentry. not used here */
    __le32 mtime;
    __le32 vroot;           /* root dir or ? */
    //__le32 path_len;        /* length of the dir path */
    __le64 ino;             /* inode number*/
    __le64 par_ino;         /* parent inode_ino */
    __le64 size;            /* inode_size */
    __le64 dzt_hn;          /* hashname od dzr if root dir*/
    //__le64 zone_no;         /* root dir records zone number */
    //__le64 par_z_no;        /* parent zone ino */
    //__le64 prio;            /* level of priority to new a zone */
    //__le64 d_f;             /* dentry frenquency */
    //__le64 sub_s;           /* subfile number state */
    //__le64 f_s;             /* frequency statement */
    __le64 sub_num;         /* the number of subfiles */
    __le64 sub_pos[NR_DENTRY_IN_ZONE];         /* sub file position*/
    //char path[DAFS_PATH_LEN+1];          /* partial path name for lookup*/
    char name[NOVA_NAME_LEN+1];          /* file name*/
    struct fulname ful_name;

}__attribute((__packed__));

struct fulname{
    __le64 f_namelen;
    char f_name[NOVA_NAME_LEN+1];
}


/*dir behavior log*/
struct direntry_log {
    u8 type_d;     /*record dir behavior type*/
    __le64 src_dz_no;  /* record src dz hashname*/
    __le64 src_hashname;  /* record src dentry hashname*/
    __le64 des_dz_no;
    __le64 des_hashname;
};

/*
 * 2017/09/13
 * zone entries in directory zone table block
 * 是不是应该在dram中保留一份*/
struct dafs_dzt_block{
    __u8 dzt_bitmap[SIZE_DZT_BITMAP];               /*not decided the size of bitmap*/
    __u8 reserved[SIZE_OF_RESERVED];
    //__le64 dzt_tail_pos;
    struct direntry_log dlog;
    struct dafs_dzt_entry dzt_entry[DAFS_DZT_ENTRIES_IN_BLOCK];      /*128-1 entries in BT block*/
}__attribute((__packed__));

/*
 * 2017/09/12 
 * directory zone table entry in DRAM
 * learn in betrfs*/
 struct dafs_dzt_entry {
     //__u8 invalid;          /* invalid or not */ 
     __u8 zone_blk_type;
     __le32 root_len;         /*root diretory name length*/
     //__le32 dzt_amount;       /*number of entries been taken*/
     __le64 dzt_eno;          /*dzt entry Id */	
     //__le64 dz_no;            /* zone number */
     //__le64 dz_log_head        /* logical start addr*/
     __le64 dz_addr;          /* zone addr */
     __le64 ht_head;       /*record hash table head*/
     //__le64 dz_size;
     __le64 pdz_addr;      /* parent zone address*/
     __le64 rden_pos;      /* root dentry */
    // __le64 dz_sf;         /* newly added dir zone sum frequency */
     __le64 hash_name;
     //__le64 child_dzt_eno[CHILD_PER_DZT_ENTRY];     /*child dzt number in this table */      
     //char path_name[DAFS_PATH_LEN];
 }__attribute(__packed__);

struct hash_table{
    __u8 hash_map[NR_HASH_ENTRIES]; /*hash table bit map*/
    //__u8 hash_key;            /* not necessary*/
    __le64 hash_tail;        /* hash tail for next hash table address max is four*/
    struct hash_entry hash_entry[NR_HASH_ENTRIES]; /*dentry name-pos pairs*/
};

struct ht_ptr{
    const void *hash_map;
    unsigned long  hash_max;
    struct hash_entry *he;
}

struct hash_entry{
    __le64 hd_name;         /* hash dafs_dentry name*/
    __le64 name_len;
    __le64 hd_pos;          /* dentry pos in zone*/
};

/*rf_entry read frequence entry
 * */
struct rf_entry {
    u32 r_f;         /*read frequency*/
    u32 sub_s;       /*sub files number state*/
    u32 f_s;         /*frequency state*/
    u32 prio;        /*prio level*/  
    u64 hash_name;   /*hashname for record dentry it belongs*/

};

/*
* 2017/09/13
* zone entries for copy-on-write Btree*/
struct dzt_entry_info{
    u8 zone_blk_type;
    uint32_t root_len;
    uint64_t dzt_eno;
    //uint64_t dz_no;
    //uint64_t dz_log_head;
    uint64_t dz_addr;
    uint64_t ht_head;
    //uint64_t dz_size;
    uint64_t pdz_addr;
    uint64_t rden_pos;
    //uint64_t dz_sf;
    uint64_t hash_name;
    struct radix_tree_root rf_tree;    /*read frequence root*/
    //struct list_head child_list;
    //uint64_t child_dzt_eno[CHILD_PER_DZT_ENTRY];
    //uint64_t hash_path_name;
    //char root_path[DAFS_PATH_LEN];
};

/*
* 2017/09/13
* directory zone entry Btree list*/
struct dzt_entry {
    //struct list_head list;           /*for B-tree lists*/
    uint64_t hash_path_name;
    struct dzt_entry_info *d_entry_info;
};

/*
 * dzt manager for radix_tree in DRAM */
struct dzt_manager {
    struct radix_tree_root dzt_root;
};

/* use for dzt_block operations */
struct dzt_ptr {
    const void *bitmap;
    unsinged long max;
    struct dafs_dzt_entry *dzt_entry;
};
