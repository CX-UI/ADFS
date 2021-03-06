#
# Makefile for the linux NOVA filesystem routines.
#

obj-m += nova.o

nova-y := balloc.o bbuild.o dax.o file.o inode.o ioctl.o journal.o stats.o super.o symlink.o sysfs.o wprotect.o zone.o dafs_dir.o dafs_namei.o hash.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=`pwd`

clean:
	make -C /lib/modules/$(shell uname -r)/build M=`pwd` clean
