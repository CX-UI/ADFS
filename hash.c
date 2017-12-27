/*************************************************************************
	> File Name: hash.c
	> Author:CX
	> Mail: tianfangmmr@126.com
	> Created Time: 2017年10月18日 星期三 16时27分27秒
    > Discription: hash table for zone
 ************************************************************************/

//#include "zone.h"
#include "nova.h"

/*allocate htable blocks and get h_addr*/
int  get_hash_table(struct super_block *sb, u8 hlevel,  u64 *h_addr)
{
    unsigned long blocknr;
    int allocated;
    u64 block;
    unsigned short btype = 0;

    //nova_dbg("dafs allocate hash table");
    switch(hlevel) {
        case 1:
            btype = HTABLE_DEF_SIZE;
            break;
        case 2:
            btype = HTABLE_LS_SIZE;
            break;
        case 3:
            btype = HTABLE_LT_SIZE;
            break;
        case 4:
            btype = HTABLE_LF_SIZE;
            break;
        case 5:
            btype = HTABLE_LE_SIZE;
            break;
    }
    allocated = nova_new_blocks(sb, &blocknr, 1, btype, 1, HTABLE);

    //nova_dbg("%s: allocate zone @ 0x%lx\n", __func__,
	//						blocknr);
    if(allocated != 1 || blocknr == 0)
        return -ENOMEM;

    block = nova_get_block_off(sb, blocknr, btype); 
    //bp = (unsigned long)nova_get_block(sb, block);
    /*偏移量*/
    *h_addr = block;

    PERSISTENT_BARRIER();
    return 0;
}

/*make ptr of hash table */
/*
void make_ht_ptr(struct ht_ptr **ht_p, struct hash_table *ht)
{
    struct ht_ptr *p;
    p->hash_map = ht->hash_map;
    //entries num is settled, bucket not
    p->hash_max = NR_HASH_ENTRIES;
    p->he = ht->hash_entry;
    *ht_p = p;
}*/


/* record dentry-pos pairs in hash table
 * ht_addr comes from last level*/
int record_pos_htable_le(struct super_block *sb, u64 block, u64 hashname,\
         u32 pos, u8 hlevel)
{
    struct hash_table_le *ht;
    struct hash_entry *he;
    u32 h_pos;
    //u64 tail;
    int i =0;
    //int offset, buckets;
    u8 valid_flag;
    //u8 level = hlevel;

    ht = (struct hash_table_le *)nova_get_block(sb, block);  
    if(!ht)
        return -EINVAL;

    h_pos = 0;

    while(i<NR_HASH_ENTRIES_L5){
        he = &ht->hash_entry[h_pos];
        valid_flag = he->invalid;
        if(!valid_flag)
            goto fill_he;
        i++;
        h_pos ++;
    }

fill_he:
    //he = &ht->hash_entry[h_pos];
    he->hd_name = cpu_to_le64(hashname);
    he->hd_pos = cpu_to_le32(pos);
    he->invalid = 1;
    nova_flush_buffer(he, sizeof(struct hash_entry),0);
    return 0;
}

/* record dentry-pos pairs in hash table
 * ht_addr comes from last level*/
int record_pos_htable_lf(struct super_block *sb, u64 block, u64 hashname,\
         u32 pos, u8 hlevel)
{
    struct hash_table_lf *ht;
    struct hash_entry *he;
    u32 h_pos;
    u64 tail;
    int i =0;
    int offset, buckets;
    u8 valid_flag;
    u8 level = hlevel;

    buckets = 511;
    offset = 4;
    ht = (struct hash_table_lf *)nova_get_block(sb, block);  
    if(!ht)
        return -EINVAL;

    h_pos = ((hashname % buckets)-1) * offset;

    while(i<offset){
        he =  &ht->hash_entry[h_pos];
        valid_flag = he->invalid;
        if(!valid_flag)
            goto fill_he;
        i++;
        h_pos ++;
    }

    tail = le64_to_cpu(ht->hash_tail);
    if(!tail){
        //nova_dbg("%s %d extend",__func__, hlevel);
        level ++;
        get_hash_table(sb, hlevel, &tail);
        ht->hash_tail = cpu_to_le64(tail);
        record_pos_htable_le(sb, tail, hashname, pos, level);
        goto out;
    } else {
        level ++;
        record_pos_htable_le(sb, tail, hashname,  pos, level);
        goto out;
    }

fill_he:
    //he = &ht->hash_entry[h_pos];
    he->hd_name = cpu_to_le64(hashname);
    he->hd_pos = cpu_to_le32(pos);
    he->invalid = 1;
    nova_flush_buffer(he, sizeof(struct hash_entry),0);
    
out:
    return 0;
}
/* record dentry-pos pairs in hash table
 * ht_addr comes from last level*/
int record_pos_htable_lt(struct super_block *sb, u64 block, u64 hashname,\
         u32 pos, u8 hlevel)
{
    struct hash_table_lt *ht;
    struct hash_table_lf *htf;
    struct hash_entry *he;
    u32 h_pos;
    u64 tail;
    int i =0;
    int offset, buckets;
    u8 valid_flag;
    u8 level = hlevel;

    buckets = 1023;
    offset = 4;
    ht = (struct hash_table_lt *)nova_get_block(sb, block);  
    if(!ht)
        return -EINVAL;

    h_pos = ((hashname % buckets)-1) * offset;

    while(i<offset){
        he =  &ht->hash_entry[h_pos];
        valid_flag = he->invalid;
        if(!valid_flag)
            goto fill_he;
        i++;
        h_pos ++;
    }

    tail = le64_to_cpu(ht->hash_tail);
    if(!tail){
        //nova_dbg("%s %d extend",__func__, hlevel);
        level ++;
        get_hash_table(sb, hlevel, &tail);
        htf = (struct hash_table_lf *)nova_get_block(sb, tail);
        htf->hash_tail = 0;
        ht->hash_tail = cpu_to_le64(tail);
        record_pos_htable_lf(sb, tail, hashname, pos, level);
        goto out;
    } else {
        level ++;
        record_pos_htable_lf(sb, tail, hashname,  pos, level);
        goto out;
    }

fill_he:
    //he = &ht->hash_entry[h_pos];
    he->hd_name = cpu_to_le64(hashname);
    he->hd_pos = cpu_to_le32(pos);
    he->invalid = 1;
    nova_flush_buffer(he, sizeof(struct hash_entry),0);
    
out:
    return 0;
}

/* record dentry-pos pairs in hash table
 * ht_addr comes from last level*/
int record_pos_htable_ls(struct super_block *sb, u64 block, u64 hashname,\
        u32 pos, u8 hlevel)
{
    struct hash_table_ls *ht;
    struct hash_table_lt *htt;
    struct hash_entry *he;
    u32 h_pos;
    u64 tail;
    int i =0;
    int offset, buckets;
    u8 valid_flag;
    u8 level = hlevel;

    buckets = 2047;
    offset = 4;
    ht = (struct hash_table_ls *)nova_get_block(sb, block);  
    if(!ht)
        return -EINVAL;

    h_pos = ((hashname % buckets)-1) * offset;

    while(i<offset){
        he =  &ht->hash_entry[h_pos];
        valid_flag = he->invalid;
        if(!valid_flag)
            goto fill_he;
        i++;
        h_pos ++;
    }

    tail = le64_to_cpu(ht->hash_tail);
    if(!tail){
        //nova_dbg("%s %d extend",__func__, hlevel);
        level ++;
        get_hash_table(sb, hlevel, &tail);
        htt = (struct hash_table_lt *)nova_get_block(sb, tail);
        htt->hash_tail = 0;
        ht->hash_tail = cpu_to_le64(tail);
        record_pos_htable_lt(sb, tail, hashname, pos, level);
        goto out;
    } else {
        level ++;
        record_pos_htable_lt(sb, tail, hashname, pos, level);
        goto out;
    }

fill_he:
    //he = &ht->hash_entry[h_pos];
    he->hd_name = cpu_to_le64(hashname);
    he->hd_pos = cpu_to_le32(pos);
    he->invalid = 1;
    nova_flush_buffer(he, sizeof(struct hash_entry),0);
    
out:
    return 0;
}
/* record dentry-pos pairs in hash table
 * ht_addr comes from dzt_ei*/
int record_pos_htable(struct super_block *sb, u64 block, u64 hashname,\
         u32 pos, u8 hlevel)
{
    struct hash_table *ht;
    struct hash_table_ls *hts;
    //struct ht_ptr *ht_p;
    struct hash_entry *he;
    u32 h_pos;
    u64 tail;
    int i =0;
    int offset, buckets;
    u8 valid_flag;

    //nova_dbg("dafs record pos in hash table address is %llu", block);
    buckets = 4095; 
    offset = 4;
    ht = (struct hash_table *)nova_get_block(sb, block);  
    if(!ht)
        return -EINVAL;

    h_pos = ((hashname % buckets)-1) * offset;

    while(i<offset){
        he =  &ht->hash_entry[h_pos];
        valid_flag = he->invalid;
        if(!valid_flag)
            goto fill_he;
        i++;
        h_pos ++;
    }

    tail = le64_to_cpu(ht->hash_tail);
    if(!tail){
        //nova_dbg("%s %d extend",__func__, hlevel);
        hlevel ++;
        get_hash_table(sb, hlevel, &tail);
        hts = (struct hash_table_ls *)nova_get_block(sb, tail);
        hts->hash_tail = 0;
        ht->hash_tail = cpu_to_le64(tail);
        record_pos_htable_ls(sb, tail, hashname,  pos, hlevel);
        goto out;
    } else {
        hlevel ++;
        record_pos_htable_ls(sb, tail, hashname, pos, hlevel);
        goto out;
    }

fill_he:
    //he = &ht->hash_entry[h_pos];
    he->hd_name = cpu_to_le64(hashname);
    he->invalid = 1;
    he->hd_pos = cpu_to_le32(pos);
    nova_flush_buffer(he, sizeof(struct hash_entry),0);
    
out:
    //nova_dbg("dafs finish recording pos in hash table");
    return 0;
}

int lookup_ht_le(struct super_block *sb, u64 block, u64 hashname, u8 hlevel, u32 *pos)
{
    struct hash_table_le *ht;
    struct hash_entry *he;
    u32 h_pos;
    //u64 tail;
    int  ret=0;
    u64 h_name;
    u8 valid_flag;

    //block = nova_get_block_off(sb, blocknr, HTABLE_SIZE);
    ht = (struct hash_table_le *)nova_get_block(sb, block);  

    h_pos = 0;

    while(h_pos< NR_HASH_ENTRIES_L5) {
        he = &ht->hash_entry[h_pos];
        valid_flag = ht->hash_entry[h_pos].invalid;
        if(!valid_flag){
            h_pos++;
            continue;
        }
        /*found valid pos*/
        h_name = le64_to_cpu(he->hd_name);
        if(h_name==hashname){
            *pos = le32_to_cpu(he->hd_pos);
            ret = 1;
            goto out;
        } else {
            h_pos++;
        }
    }

out: 
    return ret;
}

int lookup_ht_lf(struct super_block *sb, u64 block, u64 hashname, u8 hlevel, u32 *pos)
{
    struct hash_table_lf *ht;
    struct hash_entry *he;
    u32 h_pos, buckets, offset, s_pos = 0;
    u64 tail;
    int i = 0, ret=0;
    u64 h_name;
    u8 valid_flag;

    //block = nova_get_block_off(sb, blocknr, HTABLE_SIZE);
    ht = (struct hash_table_lf *)nova_get_block(sb, block);  
    buckets = 511;
    offset = 4;

    h_pos = ((hashname % buckets)-1) * offset;

    while(i < offset) {
        he = &ht->hash_entry[h_pos];
        valid_flag = ht->hash_entry[h_pos].invalid;
        if(!valid_flag){
            i++;
            h_pos++;
            continue;
        }
        /*found valid pos*/
        h_name = le64_to_cpu(he->hd_name);
        if(h_name==hashname){
            *pos = le32_to_cpu(he->hd_pos);
            ret = 1;
            goto out;
        } else {
            i++;
            h_pos++;
        }
    }

    /*not found pos*/
    tail = le64_to_cpu(ht->hash_tail);
    if(tail) {
        hlevel++;
        ret = lookup_ht_le(sb, tail, hashname, hlevel, &s_pos);
        *pos = s_pos;
    }
out: 
    return ret;
}

int lookup_ht_lt(struct super_block *sb, u64 block, u64 hashname, u8 hlevel, u32 *pos)
{
    struct hash_table_lt *ht;
    struct hash_entry *he;
    u32 h_pos, buckets, offset, s_pos = 0;
    u64 tail;
    int i = 0, ret=0;
    u64 h_name;
    u8 valid_flag;

    //block = nova_get_block_off(sb, blocknr, HTABLE_SIZE);
    ht = (struct hash_table_lt *)nova_get_block(sb, block);  
    buckets = 1023;
    offset = 4;

    h_pos = ((hashname % buckets)-1) * offset;

    while(i < offset) {
        he = &ht->hash_entry[h_pos];
        valid_flag = ht->hash_entry[h_pos].invalid;
        if(!valid_flag){
            i++;
            h_pos++;
            continue;
        }
        /*found valid pos*/
        h_name = le64_to_cpu(he->hd_name);
        if(h_name==hashname){
            *pos = le32_to_cpu(he->hd_pos);
            ret = 1;
            goto out;
        } else {
            i++;
            h_pos++;
        }
    }

    /*not found pos*/
    tail = le64_to_cpu(ht->hash_tail);
    if(tail) {
        hlevel++;
        ret = lookup_ht_lf(sb, tail, hashname, hlevel, &s_pos);
        *pos = s_pos;
    }
out: 
    return ret;
}

/*look up hashname in hash table for right position
 * &pos for position of dentry
 * hlevel for hash table level 
 * return 1 for found*/
int lookup_ht_ls(struct super_block *sb, u64 block, u64 hashname, u8 hlevel, u32 *pos)
{
    struct hash_table_ls *ht;
    struct hash_entry *he;
    u32 h_pos, buckets, offset, s_pos = 0;
    u64 tail;
    int i = 0, ret=0;
    u64 h_name;
    u8 valid_flag;

    //block = nova_get_block_off(sb, blocknr, HTABLE_SIZE);
    ht = (struct hash_table_ls *)nova_get_block(sb, block);  
    buckets = 2047;
    offset = 4;

    h_pos = ((hashname % buckets)-1) * offset;

    while(i < offset) {
        he = &ht->hash_entry[h_pos];
        valid_flag = ht->hash_entry[h_pos].invalid;
        if(!valid_flag){
            i++;
            h_pos++;
            continue;
        }
        /*found valid pos*/
        h_name = le64_to_cpu(he->hd_name);
        if(h_name==hashname){
            *pos = le32_to_cpu(he->hd_pos);
            ret = 1;
            goto out;
        } else {
            i++;
            h_pos++;
        }
    }

    /*not found pos*/
    tail = le64_to_cpu(ht->hash_tail);
    if(tail) {
        hlevel++;
        ret = lookup_ht_lt(sb, tail, hashname, hlevel, &s_pos);
        *pos = s_pos;
    }
out: 
    return ret;
}
/*look up hashname in hash table for right position
 * &pos for position of dentry
 * hlevel for hash table level 
 * return 1 for found*/
int lookup_in_hashtable(struct super_block *sb, u64 block, u64 hashname, u8 hlevel, u32 *pos)
{
    struct hash_table *ht;
    struct hash_entry *he;
    //struct ht_ptr *ht_p;
    u32 h_pos, buckets, offset, s_pos=0;
    u64 tail;
    int i = 0, ret=0;
    u64 h_name;
    u8 valid_flag;

    //block = nova_get_block_off(sb, blocknr, HTABLE_SIZE);
    //nova_dbg("%s start",__func__);
    BUG_ON(block==0);
    ht = (struct hash_table *)nova_get_block(sb, block);  

    buckets = 4095;
    offset = 4;

    h_pos = ((hashname % buckets)-1) * offset;

    while(i < offset) {
        he = &ht->hash_entry[h_pos];
        valid_flag = ht->hash_entry[h_pos].invalid;
        if(!valid_flag){
            i++;
            h_pos++;
        }else{
            /*found valid pos*/
            h_name = le64_to_cpu(he->hd_name);
            if(h_name==hashname){
                *pos = le32_to_cpu(he->hd_pos);
                ret = 1;
                goto out;
            } else {
                i++;
                h_pos++;
            }
        }
    }

    //nova_dbg("%s:not find pos",__func__);
    tail = le64_to_cpu(ht->hash_tail);
    if(tail) {
        //nova_dbg("%s need to find in next hashtable 0x%llu",__func__,tail);
        hlevel++;
        ret = lookup_ht_ls(sb, tail, hashname, hlevel, &s_pos);
        *pos = s_pos;

    } else
        nova_dbgv("%s:not find pos",__func__);

out: 
    //nova_dbg("dafs finish lookup in hash table");
    return ret;
}

int make_invalid_ht_le(struct super_block *sb, u64 block, u64 hashname, u8 hlevel)
{
    struct hash_table_le *ht;
    struct hash_entry *he;
    u32 h_pos;
    //u64 tail;
    int ret=0;
    u64 h_name;
    u8 valid_flag;

    ht = (struct hash_table_le *)nova_get_block(sb, block);  

    h_pos = 0;

    while(h_pos< NR_HASH_ENTRIES_L5) {
        he = &ht->hash_entry[h_pos];
        valid_flag = ht->hash_entry[h_pos].invalid;
        if(!valid_flag){
            h_pos++;
        }
        /*found valid pos*/
        h_name = le64_to_cpu(he->hd_name);
        if(h_name==hashname){
           he->invalid = 0;
            ret = 1;
            goto out;
        } else {
            h_pos++;
        }
    }
out:
    return ret;
}

int make_invalid_ht_lf(struct super_block *sb, u64 block, u64 hashname, u8 hlevel)
{
    struct hash_table_lf *ht;
    struct hash_entry *he;
    u32 h_pos, buckets, offset;
    u64 tail;
    int i = 0, ret=0;
    u64 h_name;
    u8 valid_flag;

    //block = nova_get_block_off(sb, blocknr, HTABLE_SIZE);
    ht = (struct hash_table_lf *)nova_get_block(sb, block);  
    buckets = 511;
    offset = 4;

    h_pos = ((hashname % buckets)-1) * offset;

    while(i < offset) {
        he = &ht->hash_entry[h_pos];
        valid_flag = ht->hash_entry[h_pos].invalid;
        if(!valid_flag){
            i++;
            h_pos++;
        }
        /*found valid pos*/
        h_name = le64_to_cpu(he->hd_name);
        if(h_name==hashname){
            he->invalid = 0;
            ret = 1;
            goto out;
        } else {
            i++;
            h_pos++;
        }
    }

    /*not found pos*/
    tail = le64_to_cpu(ht->hash_tail);
    if(tail) {
        hlevel++;
        ret = make_invalid_ht_le(sb, tail, hashname, hlevel);
    }
out: 
    return ret;
}

int make_invalid_ht_lt(struct super_block *sb, u64 block, u64 hashname, u8 hlevel)
{
    struct hash_table_lt *ht;
    struct hash_entry *he;
    u32 h_pos, buckets, offset;
    u64 tail;
    int i = 0, ret=0;
    u64 h_name;
    u8 valid_flag;

    //block = nova_get_block_off(sb, blocknr, HTABLE_SIZE);
    ht = (struct hash_table_lt *)nova_get_block(sb, block);  
    buckets = 1023;
    offset = 4;

    h_pos = ((hashname % buckets)-1) * offset;

    while(i < offset) {
        he = &ht->hash_entry[h_pos];
        valid_flag = ht->hash_entry[h_pos].invalid;
        if(!valid_flag){
            i++;
            h_pos++;
        }
        /*found valid pos*/
        h_name = le64_to_cpu(he->hd_name);
        if(h_name==hashname){
            he->invalid = 0;
            ret = 1;
            goto out;
        } else {
            i++;
            h_pos++;
        }
    }

    /*not found pos*/
    tail = le64_to_cpu(ht->hash_tail);
    if(tail) {
        hlevel++;
        ret = make_invalid_ht_lf(sb, tail, hashname, hlevel);
    }
out: 
    return ret;
}

int make_invalid_ht_ls(struct super_block *sb, u64 block, u64 hashname, u8 hlevel)
{
    struct hash_table_ls *ht;
    struct hash_entry *he;
    u32 h_pos, buckets, offset;
    u64 tail;
    int i = 0, ret=0;
    u64 h_name;
    u8 valid_flag;

    //block = nova_get_block_off(sb, blocknr, HTABLE_SIZE);
    ht = (struct hash_table_ls *)nova_get_block(sb, block);  
    buckets = 2047;
    offset = 4;

    h_pos = ((hashname % buckets)-1) * offset;

    while(i < offset) {
        he = &ht->hash_entry[h_pos];
        valid_flag = ht->hash_entry[h_pos].invalid;
        if(!valid_flag){
            i++;
            h_pos++;
        }
        /*found valid pos*/
        h_name = le64_to_cpu(he->hd_name);
        if(h_name==hashname){
            he->invalid = 0;
            ret = 1;
            goto out;
        } else {
            i++;
            h_pos++;
        }
    }

    /*not found pos*/
    tail = le64_to_cpu(ht->hash_tail);
    if(tail) {
        hlevel++;
        ret = make_invalid_ht_lt(sb, tail, hashname, hlevel);
    }
out: 
    return ret;
}

/*make invalid 
 * return 1 for invalid successfully
 * return 0 for fail invalid*/
int make_invalid_htable(struct super_block *sb, u64 block, u64 hashname, u8 hlevel)
{
    struct hash_table *ht;
    struct hash_entry *he;
    //struct ht_ptr *ht_p;
    u32 h_pos, buckets, offset;
    u64 tail;
    int i = 0, ret=0;
    u64 h_name;
    u8 valid_flag;

    //nova_dbg("%s start",__func__);
    //block = nova_get_block_off(sb, blocknr, HTABLE_SIZE);
    ht = (struct hash_table *)nova_get_block(sb, block);  

    buckets = 4095;
    offset = 4;

    h_pos = ((hashname % buckets)-1) * offset;

    while(i < offset) {
        he = &ht->hash_entry[h_pos];
        valid_flag = ht->hash_entry[h_pos].invalid;
        if(!valid_flag){
            i++;
            h_pos++;
        }
        /*found valid pos*/
        h_name = le64_to_cpu(he->hd_name);
        if(h_name==hashname){
            he->invalid =0;
            ret = 1;
            goto out;
        } else {
            i++;
            h_pos++;
        }
    }

    /*not found pos*/
    tail = le64_to_cpu(ht->hash_tail);
    if(tail) {
        hlevel++;
        ret = make_invalid_ht_ls(sb, tail, hashname, hlevel);
    }
out:
    //nova_dbg("%s end",__func__);
    return ret;
}

int free_htable(struct super_block *sb, u64 ht_addr, u8 hlevel)
{
    struct hash_table *ht;
    struct hash_table_ls *hts;
    struct hash_table_lt *htt;
    struct hash_table_lf *htf;
    struct hash_table_le *hte;
    u64 tail, tem;
    unsigned short btype;

    //nova_dbg("%s start",__func__);
    tail = ht_addr;
    while(tail){
        //nova_dbg("%s hash table addr %llu",__func__,tail);
        switch (hlevel) {
            case 1:
                ht = (struct hash_table *)nova_get_block(sb, tail);
                tem = le64_to_cpu(ht->hash_tail);
                btype = HTABLE_DEF_SIZE;
                hlevel = 2;
                dafs_free_htable_blocks(sb, btype, tail>>PAGE_SHIFT,1);
                BUG_ON(tem == 0);
                tail = tem;
                continue;
            case 2:
                hts = (struct hash_table_ls *)nova_get_block(sb, tail);
                tem = le64_to_cpu(hts->hash_tail);
                btype = HTABLE_LS_SIZE;
                hlevel = 3;
                dafs_free_htable_blocks(sb, btype, tail>>PAGE_SHIFT, 1);
                BUG_ON(tem == 0);
                tail = tem;
                continue;
            case 3:
                htt = (struct hash_table_lt *)nova_get_block(sb, tail);
                tem = le64_to_cpu(htt->hash_tail);
                btype = HTABLE_LT_SIZE;
                hlevel = 4;
                dafs_free_htable_blocks(sb, btype,tail>>PAGE_SHIFT, 1);
                BUG_ON(tem == 0);
                tail = tem;
                continue;
            case 4:
                htf = (struct hash_table_lf *)nova_get_block(sb, tail);
                tem = le64_to_cpu(htf->hash_tail);
                btype = HTABLE_LF_SIZE;
                hlevel = 5;
                dafs_free_htable_blocks(sb, btype, tail>>PAGE_SHIFT, 1);
                BUG_ON(tem == 0);
                tail = tem;
                continue;
            case 5:
                hte = (struct hash_table_le *)nova_get_block(sb, tail);
                tem = 0;
                btype = HTABLE_LE_SIZE;
                dafs_free_htable_blocks(sb, btype, tail>>PAGE_SHIFT, 1);
                tail = tem;
                continue;
            default:
                nova_dbg("%s wrong free",__func__);
        }
    }

    //nova_dbg("%s end",__func__);
    return 0;
}
