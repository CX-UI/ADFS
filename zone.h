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

/*dzt_block*/
#define SIZE_DZT_BITMAP ((DAFS_DZT_ENTRIES_IN_BLOCK + 1 + BITS_PER_BYTE -1)/BITS_PER_BYTE)
#define DAFS_DZT_ENTRIES_IN_BLOCK 72
#define SIZE_OF_RESERVED 53

/*zone_entry */
#define SIZE_OF_ZONE_BITMAP ((NR_DENTRY_IN_ZONE*2 + BITS_PER_BYTE-1)/BITS_PER_BYTE)
#define NR_DENTRY_IN_ZONE 4088

/*dafs_dentry*/
#define SMALL_NAME_LEN 39
#define LARGE_NAME_LEN 112
#define DAFS_NAME_LEN 255
#define DAFS_DEF_DENTRY_SIZE 128
#define DAFS_DZT_SIZE 56


/*
 * struct dir_zone
 * learn in f2fs*/
struct dafs_zone_entry{
    __u8 zone_statemap[SIZE_OF_ZONE_BITMAP];         /* state and validity for zone dentries*/
    __u8 reserved[3];
    __le32 dz_no;           /*directory zone NO*/
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

struct name_ext {
    __u8 reserved[4];
    __le32  ext_pos;
    struct name_ext *next;
    char name[LARGE_NAME_LEN+1];
};


/*
 * dafs dir_struct
 * ext_flag->0 not ext
 * ->1 name ext
 * ->2 only fulname ext*/
struct dafs_dentry{
    __u8 entry_type;          
    __u8 name_len;            /*length of the dentry name*/
    __u8 file_type;           /* file type */
    __u8  isr_sf;           /* root subfile or not*/
    __le16 ext_flag;     /* need extension or not*/
    __le16 links_count;         /* links */
    __le32 mtime;
    __le32 par_pos;
    __le64 fname_len
    __le64 ino;             /* inode number*/
    __le64 size;            /* inode_size */
    union{
        __le64 hname;      /*if not root dir record hashname*/
        __le64 dzt_hn;      /*if root dir record dzt hn*/
    };
    union {
        struct name_ext *next;
        char name[SMALL_NAME_LEN+1];     /*file name*/
    };
    
    struct fulname ful_name;

}__attribute((__packed__));

struct fulname{
    //__le64 f_namelen;
    union {
        struct name_ext *fn_ext;
        char f_name[SMALL_NAME_LEN+1];
    };
};


/*dir behavior log
* 32Byte*/
struct direntry_log {
    __u8 type_d;     /*record dir behavior type*/
    __u8 reserved[7];
    __le32 src_dz_no;  /* record src dz hashname*/
    __le32 des_dz_no;
    __le64 des_hashname;
    __le64 src_hashname;  /* record src dentry hashname*/
}__attribute((__packed__));

/*
 * 2017/09/13
 * zone entries in directory zone table block
 * 是不是应该在dram中保留一份
 * 4KB*/
struct dafs_dzt_block{
    __u8 dzt_bitmap[SIZE_DZT_BITMAP];               /*not decided the size of bitmap*/
    __u8 reserved[DZT_BLK_RESERVED];
    //__le64 dzt_tail_pos;
    struct direntry_log dlog;
    struct dafs_dzt_entry dzt_entry[DAFS_DZT_ENTRIES_IN_BLOCK];      /*128-1 entries in BT block*/
}__attribute((__packed__));

/*
 * 2017/09/12 
 * directory zone table entry in DRAM
 * learn in betrfs
 * 56Byte*/
 struct dafs_dzt_entry {
    __u8 zone_blk_type;
    //__le32 root_len;         /*root diretory name length*/
    __u8 reserved[7];
    __le32 dzt_eno;          /*dzt entry Id */	
    __le32 rden_pos;         /*root dir entry pos in zone*/
    __le64 root_len;        /*root direntory name length*/
    __le64 dz_addr;          /* zone addr */
    __le64 ht_head;       /*record hash table head*/
    __le64 pdz_addr;      /* parent zone address*/
    __le64 hash_name;
 }__attribute(__packed__);

struct hash_table{
    __u8 hash_map[NR_HASH_ENTRIES]; /*hash table bit map*/
    __u8 reserved[7]; 
    //__u8 hash_key;            /* not necessary*/
    __le64 hash_tail;        /* hash tail for next hash table address max is four*/
    struct hash_entry hash_entry[NR_HASH_ENTRIES]; /*dentry name-pos pairs*/
};

struct ht_ptr{
    const void *hash_map;
    unsigned long  hash_max;
    struct hash_entry *he;
};

struct hash_entry{
    __le64 hd_name;         /* hash dafs_dentry name*/
    __le64 name_len;
    __le32 hd_pos;          /* dentry pos in zone*/
    __le32 reserved;
};

/*rf_entry read frequence entry
 *
struct rf_entry {
    u16 r_f;         /*read frequency*/
    u16 sub_s;       /*sub files number state*/
    u16 f_s;         /*frequency state*/
    u16 prio;        /*prio level*/  
    u64 hash_name;   /*hashname for record dentry it belongs*/

};*/

/* list memebers in list 
 * record position*/
struct file_p {
    struct list_head list;
    u32 pos;
}__attribute__(packed);

/*record dir subfile info*/
/*
struct dir_sf_info {
    int sub_num;
    u64 dir_hash;
    struct list_head sub_file;
    //unsinged short sub_pos[NR_DENTRY_IN_ZONE];
};*/

/*record dir frequecy ,info and subfile list*/
struct dir_info {
    u8 r_f;
    u8 sub_s;
    u8 f_s;
    u8 prio;
    u32 sub_num;
    u64 dir_hash;
    struct list_head sub_file;
};

/*
* 2017/09/13
* zone entries for copy-on-write Btree*/
struct dzt_entry_info{
    u8 zone_blk_type;
    u8 reserve[7];
    u32 dzt_eno;
    u32 rden_pos;
    u64 dz_addr;
    u64 ht_head;
    u64 pdz_addr;
    u64 root_len;
    u64 hash_name;
    struct radix_tree_root dir_tree;   /*record frequency and dir info */
    //struct radix_tree_root rf_tree;    /*read frequence root*/
    //struct radix_tree_root sub_tree;   /*for dir infor in this root*/
};

/*
* 2017/09/13
* directory zone entry Btree list*/
struct dzt_entry {
    u64 hash_path_name;
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
    unsigned long max;
    struct dafs_dzt_entry *dzt_entry;
};
