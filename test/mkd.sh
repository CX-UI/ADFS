#!/bin/sh
cd /mnt/ramdisk/
#cd ~/test/test/
for i in $(seq 1 1000)
do
   mkdir ${i}
done
