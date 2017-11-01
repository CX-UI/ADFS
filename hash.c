/*************************************************************************
	> File Name: hash.c
	> Author:CX
	> Mail: tianfangmmr@126.com
	> Created Time: 2017年10月18日 星期三 16时27分27秒
    > Discription: hash table for zone
 ************************************************************************/

#include "zone.h"
#include "nova.h"

/*allocate htable blocks and get h_addr*/
int  get_hash_table(struct super_block *sb, u64 *h_addr)
{
    unsigned long blocknr, bp;
    int allocated;
    u64 block;

    /*not decideds HTABLE_TYPE
     * HTABLE_TYPE 8 blks*/
    allocated = nova_new_blocks(sb, &blocknr, 1, HTABLE_SIZE, 1, HASH_TABLE);

    nova_dbg_verbose("%s: allocate zone @ 0x%lx\n", __func__,
							blocknr);
    if(allocated != 1 || blocknr == 0)
        return -ENOMEM;

    block = nova_get_block_off(sb, blocknr, HTABLE_SIZE); 
    //bp = (unsigned long)nova_get_block(sb, block);
    /*偏移量*/
    h_addr = block;

    PERSISTENT_BARRIER();
    return 0;
}

/*make ptr of hash table */
void make_ht_ptr(struct ht_ptr **ht_p, struct hash_table *ht)
{
    struct ht_ptr *p;
    p->hash_map = ht->hash_map;
    /*entries num is settled, bucket not*/
    p->hash_max = NR_HASH_ENTRIES;
    p->he = ht->hash_entry;
    *ht_p = p;
}

/* record dentry-pos pairs in hash table
 * ht_addr comes from dzt_ei*/
int record_pos_htable(struct super_block *sb, u64 block, u64 hashname,\
        u64 namelen, u64 pos, int nr_table)
{
    struct hash_table *ht;
    struct ht_ptr *ht_p;
    struct hash_entry *he;
    //u64 bitpos;
    u64 h_pos, tail;
    //int nr_table = 1;
    int key, i, offset;
    int buckets;
    //unsigned long ht_addr;


    //block = nova_get_block_off(sb, blocknr, HTABLE_SIZE);
    ht = (struct hash_table *)nova_get_block(sb, block);  
    //ht_addr = dzt_ei->ht_head;
    //ht = (struct hash_table *)ht_addr;
    if(!ht)
        return -EINVAL;
    make_ht_ptr(&ht_p, ht);

    switch(nr_table){
        case 1:
            offset = 4;
            break;
        case 2:
            offset = 3;
            break;
        case 3:
            offset = 2;
            break;
        case 4:
            offset = 1;
            break;
        case 5:
            offset = 0;
    }
    key = nr_table << offset;
    buckets = NR_HASH_ENTRIES / key;
    h_pos = hashname % key;

    for(i = 0; i<buckets; i++){
        if(!test_bit_le(h_pos, ht_p->hash_map))
            goto fill_he;
        h_pos ++;
    }

    tail = le64_to_cpu(ht->hash_tail);
    if(!tail){
        get_hash_table(sb, &tail);
        ht->hash_tail = cpu_to_le64(tail);
        nr_table ++;
        record_pos_htable(sb, tail, hashname, namelen, pos, nr_table);
        goto out;
    } else {
        nr_table ++;
        record_pos_htable(sb, tail, hashname, namelen, pos, nr_table);
        goto out;
    }

fill_he:
    he = ht->hash_entry[h_pos];
    he->hd_name = cpu_to_le64(hashname);
    he->name_len = cpu_to_le64(namelen);
    he->hd_pos = cpu_to_le64(pos);
    test_and_set_bit_le(h_pos, ht_p->hash_map);
    nova_flush_buffer(he, size(struct hash_entry),0);
out:
    return 0;
}

/*look up hashname in hash table for right position
 * &pos for position of dentry
 * nr_table for hash table level 
 * return 1 for found*/
int lookup_in_hashtable(u64 block, u64 hashname, u64 namelen, int nr_table, int pos)
{
    struct hash_table *ht;
    struct hash_entry *he;
    struct ht_ptr *ht_p;
    u64 h_pos, tail;
    int key, i, ret=0;
    u64 h_name, h_len;

    //block = nova_get_block_off(sb, blocknr, HTABLE_SIZE);
    ht = (struct hash_table *)nova_get_block(sb, block);  
    make_ht_ptr(&ht_p, ht);

    switch(nr_table){
        case 1:
            offset = 4;
            break;
        case 2:
            offset = 3;
            break;
        case 3:
            offset = 2;
            break;
        case 4:
            offset = 1;
            break;
        case 5:
            offset = 0;
    }
    key = nr_table << offset;
    buckets = NR_HASH_ENTRIES / key;
    h_pos = hashname % key;

    for(i = 0; i < buckets; i++) {
        if(!test_bit_le(h_pos, ht_p->hash_map)){
            h_pos++;
            continue;
        }
        /*found valid pos*/
        he = ht->hash_entry[h_pos];
        h_name = le64_to_cpu(he->hd_name);
        h_len = le64_to_cpu(he->name_len);
        if(h_name==hashname && h_len==namelen){
            pos = le64_to_cpu(he->hd_pos);
            ret = 1;
            goto out;
        } else {
            continue;
        }
    }
    /*not found pos*/
    tail = le64_to_cpu(ht->hash_tail);
    if(tail) {
        nr_table++;
        ret = lookup_in_hashtable(tail, hashname, namelen, nr_table, &pos);
    }
out: 
    return ret;
}

/*make invalid 
 * return 1 for invalid successfully
 * return 0 for fail invalid*/
int make_invalid_htable(u64 block, u64 hashname, u64 namelen, int nr_table)
{
    struct hash_table *ht;
    struct hash_entry *he;
    struct ht_ptr *ht_p;
    u64 h_pos, tail;
    int key, i, ret=0;
    u64 h_name, h_len;

    //block = nova_get_block_off(sb, blocknr, HTABLE_SIZE);
    ht = (struct hash_table *)nova_get_block(sb, block);  
    make_ht_ptr(&ht_p, ht);

    switch(nr_table){
        case 1:
            offset = 4;
            break;
        case 2:
            offset = 3;
            break;
        case 3:
            offset = 2;
            break;
        case 4:
            offset = 1;
            break;
        case 5:
            offset = 0;
    }
    key = nr_table << offset;
    buckets = NR_HASH_ENTRIES / key;
    h_pos = hashname % key;

    for(i = 0; i < buckets; i++) {
        if(!test_bit_le(h_pos, ht_p->hash_map)){
            h_pos++;
            continue;
        }
        /*found valid pos*/
        he = ht->hash_entry[h_pos];
        h_name = le64_to_cpu(he->hd_name);
        h_len = le64_to_cpu(he->name_len);
        if(h_name==hashname && h_len==namelen){
            clear_bit_le(h_pos, ht_p->hash_map);
            ret = 1;
            goto out;
        } else {
            continue;
        }
    }
    /*not found pos*/
    tail = le64_to_cpu(ht->hash_tail);
    if(tail) {
        nr_table++;
        ret = make_invalid_htable(tail, hashname, namelen, nr_table);
    }
out: 
    return ret;
}
