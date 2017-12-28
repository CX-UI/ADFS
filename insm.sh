#!/bin/bash
sudo insmod nova.ko
sudo sh ../../mount/mount.sh 
watch -n 1 "dmesg|tail -50"
