# This Repository is Deprecated

Current development and releases of ADAM-NOVA will be through https://github.com/CX-UI/ADFS/.

# ADAM-NOVA is a directory accessed mechanism built on NOVA. 
The full name of ADAM is adaptive directory access mechanismm, which utilizes the strength of both multi-level directory namespace and full name direcotry namespace mechanisms. Besides, we considered the read/write states and size of direcotries as the factor of namespace evolving, which makes the system maintain a consistent performence during system runtime.

## NOVA: NOn-Volatile memory Accelerated log-structured file system

## Introduction
NOVA is a log-structured file system designed for byte-addressable non-volatile memories, developed by
the [Non-Volatile Systems Laboratory][NVSL], University of California, San Diego.

NOVA extends ideas of LFS to leverage NVMM, yielding a simpler, high-performance file system that supports fast and efficient garbage collection and quick recovery from system failures.
NOVA has passed the [Linux POSIX test suite][POSIXtest], and existing applications need not be modified to run on NOVA. NOVA bypasses the block layer and OS page cache, writes to NVM directly and reduces the software overhead.

NOVA provides strong data consistency guanrantees:

* Atomic metadata update: each directory operation is atomic.
* Atomic data update; for each `write` operation, the file data and the inode are updated in a transactional way.
* DAX-mmap: NOVA supports DAX-mmap which maps NVMM pages directly to the user space.

With atomicity guarantees, NOVA is able to recover from system failures and restore to a consistent state.

For more details about the design and implementation of NOVA, please see this paper:

**NOVA: A Log-structured File system for Hybrid Volatile/Non-volatile Main Memories**<br>
[PDF](http://cseweb.ucsd.edu/~swanson/papers/FAST2016NOVA.pdf)<br>
*Jian Xu and Steven Swanson, University of California, San Diego*<br>
Published in FAST 2016

## Building NOVA
NOVA works on the 4.3 version of x86-64 Linux kernel.

To build NOVA, simply run a

~~~
#make
~~~

command.

## Running ADAM-NOVA
ADAM-NOVA runs on a physically contiguous memory region that is not used by the Linux kernel, and relies on the kernel NVDIMM support.

To run ADAM-NOVA, first build up your kernel with NVDIMM support enabled (`CONFIG_BLK_DEV_PMEM`), and then you can
reserve the memory space by booting the kernel with `memmap` command line option.

For instance, adding `memmap=16G!8G` to the kernel boot parameters will reserve 16GB memory starting from 8GB address, and the kernel will create a `pmem0` block device under the `/dev` directory.

After the OS has booted, you can initialize a NOVA instance with the following commands:


~~~
#sudo sh insm.sh
~~~
