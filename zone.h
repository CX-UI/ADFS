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
//#include "nova.h"

#define DIR_RENAME 0
#define DIR_RMDIR  1
#define DIR_CREATE 2

/*dzt_block*/
#define SIZE_DZT_BITMAP ((DAFS_DZT_ENTRIES_IN_BLOCK + BITS_PER_BYTE -1)/BITS_PER_BYTE)
#define DAFS_DZT_ENTRIES_IN_BLOCK 72
#define DZT_BLK_RESERVED 55

/*zone_entry 
* 8MB size
* 16KB statemap
* 64K-1 128B entries
* 128B for reserve and id*/
#define SIZE_OF_ZONE_BITMAP ((NR_DENTRY_IN_ZONE*2 + BITS_PER_BYTE-1)/BITS_PER_BYTE)
#define NR_DENTRY_IN_ZONE 32768

/*dafs_dentry*/
#define SMALL_NAME_LEN 167
#define LARGE_NAME_LEN 240
#define DAFS_NAME_LEN 255
#define DAFS_PATH_LEN 1024
#define DAFS_DEF_DENTRY_SIZE 256
#define DAFS_DZT_SIZE 56

/*hash table*/
#define NR_HASH_ENTRIES_L1  (65536-1)*4
#define NR_HASH_ENTRIES_L2  (32768-1)*4
#define NR_HASH_ENTRIES_L3  (16384-1)*4
#define NR_HASH_ENTRIES_L4  (8192-1)*4
#define NR_HASH_ENTRIES_L5  4096

/*block size*/
#define DAFS_DEF_DENTRY_SIZE 256
/*zone movement*/
#define POSITIVE_SPLIT 1
#define NEGTIVE_SPLIT  0

/*statement*/
enum dafs_statement{
    STATEMAP_COLD = 0,
    STATEMAP_WARM,
    STATEMAP_HOT
};


enum dafs_dir_size {
    NUMBER_OF_SUBFILES_FEW = 0,
    NUMBER_OF_SUBFILES_LARGE,
    NUMBER_OF_ZONE_SUBFILES_FEW,
    NUMBER_OF_ZONE_SUBFILES_LARGE
};

enum dir_frequence {
    DENTRY_FREQUENCY_COLD = 0,
    DENTRY_FREQUENCY_WARM,
    DENTRY_FREQUENCY_WRITE
};

enum dir_t {
    NORMAL_FILE = 0,
    NORMAL_DIRECTORY,
    ROOT_DIRECTORY,
    INHE_ROOT_DIRECTORY
};

enum dir_level {
    LEVEL_0 = 0,
    LEVEL_1,
    LEVEL_2,
    LEVEL_3,
    LEVEL_4
};
#define NR_DIR_FILES 50
#define NR_ZONE_FILES 500


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

struct fulname{
    //__le64 f_namelen;
    union {
        struct name_ext *fn_ext;
        char f_name[SMALL_NAME_LEN+1];
    };
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
    __u8 isr_sf;           /* root subfile or not*/
    __le16 mode;           /* file type */
    __le16 reser;
    __le16 ext_flag;     /* need extension or not*/
    __le16 links_count;         /* links */
    __le32 size;
    __le32 mtime;
    __le32 par_pos;
    __le64 fname_len;
    __le64 ino;             /* inode number*/
    //__le32 size;            /* inode_size */
    union{
        __le64 hname;      /*if not root dir record hashname*/
        __le64 dzt_hn;      /*if root dir record dzt hn*/
    };
    union {
        struct name_ext *next;
        char name[SMALL_NAME_LEN+1];     /*file name*/
    };
    
    struct fulname ful_name;

};

/*
 * struct dir_zone
 * learn in f2fs*/
struct dafs_zone_entry{
    __u8 zone_statemap[SIZE_OF_ZONE_BITMAP];         /* state and validity for zone dentries*/
    __u8 reserved[124];
    __le32 dz_no;           /*directory zone NO*/
    struct dafs_dentry dentry[NR_DENTRY_IN_ZONE];	
    // next is same attributes in this zone
}__attribute((__packed__));

/*dir behavior log
 * the last dzt_entry
* 40Byte*/
struct direntry_log {
    __u8 type_d;     /*record dir behavior type*/
    __u8 reserved[7];
    __le64 src_dz_hn;  /* record src dz hashname*/
    __le64 des_dz_hn;
    __le64 des_hashname;
    __le64 src_hashname;  /* record src dentry hashname*/
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
 }__attribute((__packed__));

/*
 * 2017/09/13
 * zone entries in directory zone table block
 * 是不是应该在dram中保留一份
 * 4KB*/
struct dafs_dzt_block{
    __u8 dzt_bitmap[SIZE_DZT_BITMAP];               /*not decided the size of bitmap*/
    __u8 reserved[DZT_BLK_RESERVED];
    __le64 dzt_head;
    //__le64 dzt_tail_pos;
    //struct direntry_log dlog;
    struct dafs_dzt_entry dzt_entry[DAFS_DZT_ENTRIES_IN_BLOCK];      /*128-1 entries in BT block*/
}__attribute((__packed__));

/*
struct hash_entry{
    __le64 hd_name;         // hash dafs_dentry name
    __le64 name_len;
    __le32 hd_pos;          // dentry pos in zone
    __le32 reserved;
};*/

/*16Byte*/
struct hash_entry {
    u8 reserved[3];
    u8 invalid;
    __le32 hd_pos;        /*dentry pos*/
    __le64 hd_name;      /*dentry name*/
};

/* 4M
 * first level*/
struct hash_table {
    u8 reserved[56];
    __le64 hash_tail;
    struct hash_entry hash_entry[NR_HASH_ENTRIES_L1];
};

/*2M*/
struct hash_table_ls {
    u8 reserved[56];
    __le64 hash_tail;
    struct hash_entry hash_entry[NR_HASH_ENTRIES_L2];
};

/*1M*/
struct hash_table_lt {
    u8 reserved[56];
    __le64 hash_tail;
    struct hash_entry hash_entry[NR_HASH_ENTRIES_L3];
};

/*512K*/
struct hash_table_lf {
    u8 reserved[56];
    __le64 hash_tail;
    struct hash_entry hash_entry[NR_HASH_ENTRIES_L4];
};

/*256k
 * level end*/
struct hash_table_le {
    struct hash_entry hash_entry[NR_HASH_ENTRIES_L5];
};

/*
struct hash_table{
    __u8 hash_map[SIZE_HASH_BITMAP]; //hash table bit map
    __u8 reserved[24]; 
    //__u8 hash_key;            // not necessary
    __le64 hash_tail;        // hash tail for next hash table address max is four
    struct hash_entry hash_entry[NR_HASH_ENTRIES]; //dentry name-pos pairs
};*/

struct ht_ptr{
    const void *hash_map;
    unsigned long  hash_max;
    struct hash_entry *he;
};


/*rf_entry read frequence entry
 *
struct rf_entry {
    u16 r_f;         //read frequency
    u16 sub_s;       //sub files number state
    u16 f_s;         //frequency state
    u16 prio;        //prio level
    u64 hash_name;   //hashname for record dentry it belongs

};*/

/* list memebers in list 
 * record position*/
struct file_p {
    struct list_head list;
    u32 pos;
}__attribute__((__packed__));

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
    struct list_head sub_file;
    u8 r_f;
    u8 sub_s;
    u8 f_s;
    u8 prio;
    u32 dir_pos;
    u64 sub_num;
    u64 dir_hash;
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
    struct zone_ptr *ztr;
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
/*struct dzt_manager {
    struct radix_tree_root dzt_root;
};*/

/* use for dzt_block operations */
struct dzt_ptr {
    const void *bitmap;
    unsigned long max;
    struct dafs_dzt_entry *dzt_entry;
};


/*zone.c*/
struct dafs_dzt_block *dafs_get_dzt_block(struct super_block *sb);
void make_dzt_ptr(struct super_block *sb, struct dzt_ptr **dzt_p);
void make_zone_ptr(struct zone_ptr **z_p, struct dafs_zone_entry *z_e);
u32 find_invalid_id(struct super_block *sb, struct dzt_entry_info *dzt_ei, struct zone_ptr *z_p, u32 start_id);
int dafs_split_zone(struct super_block *sb, struct dzt_entry_info *par_dzt_ei,\
                    unsigned long sp_id, int SPLIT_TYPE);
void free_zone_area(struct super_block *sb, struct dzt_entry_info *dzt_ei);
int zone_set_statemap(struct super_block *sb, struct dzt_entry_info *ei);
int dafs_check_zones(struct super_block *sb, struct dzt_entry_info *dzt_ei);
int check_thread_func(void *data);
int start_cz_thread(struct super_block *sb);
int stop_cz_thread(struct super_block *sb);
int dzt_flush_dirty(struct super_block *sb);
int dafs_init_dzt_block(struct super_block *sb);
int dafs_build_zone(struct super_block *sb);
int dafs_init_zone(struct super_block *sb);
