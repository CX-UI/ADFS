#!/bin/bash
sudo insmod nova.ko
sudo mount -t NOVA -o init /dev/pmem0 /mnt/ramdisk 
watch -n 2 "dmesg|tail -70"
