#!/bin/bash

MODNAME="dm-tx_mod"
NAME="dm-tx"
META_FILE="/tmp/dmtx-meta"
TXR_FILE="/tmp/dmtx-txr"

if [ $# -ne 7 -a $# -ne 8 ]; then
	echo "Usage $0 <init-from-persistent-store (1=true | 0=false)> segment size in block (e.g. 4096) layout (linear | raid1 | raid0) <number of stripes> cache layout (tailonly | tailnbody | shared) cache policy (fifo | lru)"
	exit 1
fi

PERSIST=$1
BLKDEV_LAYOUT=$2

STRIPES=$3

SEG_SIZE_MB=$4

SSD_CACHE_POLICY=$5
SSD_CACHE_SIZE_MB=$6

MEM_CACHE_POLICY=$7
MEM_CACHE_SIZE_MB=$8

if [ $BLKDEV_LAYOUT != "gecko" -a $BLKDEV_LAYOUT != "linear" ]; then
	echo "Invalid layout $BLKDEV_LAYOUT"
	exit 1
fi

if [ $SSD_CACHE_POLICY != "none" -a $SSD_CACHE_POLICY != "lru_rd" -a $SSD_CACHE_POLICY != "lru_rdwr" ]; then
	echo "Invalid cache policy $SSD_CACHE_POLICY"
	exit 1
fi

if [ $MEM_CACHE_POLICY != "none" -a $MEM_CACHE_POLICY != "lru_rd" -a $MEM_CACHE_POLICY != "lru_rdwr" ]; then
	echo "Invalid cache policy $SSD_CACHE_POLICY"
	exit 1
fi

sudo insmod "./${MODNAME}.ko"

DEV_SIZE=0
DEV_SIZE_MB=0
NUM_BLKDEVS=0
BLKDEV_LIST=""

for i in b c d; do
	DEV_NAME="/dev/sd${i}"
	BLKDEV_SIZE=`sudo blockdev --getsz $DEV_NAME`
	BLKDEV_SIZE_MB=`echo "$BLKDEV_SIZE * 512 / 1024 / 1024" | bc`
	DEV_SIZE=`echo "$DEV_SIZE + $BLKDEV_SIZE" | bc`
	DEV_SIZE_MB=`echo "$DEV_SIZE_MB + $BLKDEV_SIZE_MB" | bc`
	echo "$DEV_NAME: $BLKDEV_SIZE sectors ($BLKDEV_SIZE_MB MB); total: $DEV_SIZE sectors ($DEV_SIZE_MB MB)"
	BLKDEV_LIST="$BLKDEV_LIST $DEV_NAME"
	let NUM_BLKDEVS="$NUM_BLKDEVS+1"
done
echo "- Total size: $DEV_SIZE sectors ($DEV_SIZE_MB MB)"
echo "- Internal SSD cache (type: $SSD_CACHE_POLICY) size: $SSD_CACHE_SIZE_MB MB"
echo "- Internal memory cache (type: $MEM_CACHE_POLICY) size: $MEM_CACHE_SIZE_MB MB"
echo "- Logging segment size: $SEG_SIZE_MB MB"


echo sudo dmsetup create target startaddr endaddr target persist metafilepath txrfilepath blkdevlayout numblkdevs blkdevlist segsize ssdcachepolicy ssdpath ssdcachesizemb memcachepolicy memcachesizemb
echo sudo dmsetup create $NAME 0 $DEV_SIZE dm-tx $PERSIST $META_FILE $TXR_FILE $BLKDEV_LAYOUT $NUM_BLKDEVS $BLKDEV_LIST $SEG_SIZE_MB $SSD_CACHE_POLICY /dev/sde $SSD_CACHE_SIZE_MB $MEM_CACHE_POLICY $MEM_CACHE_SIZE_MB 

echo 0 ${DEV_SIZE} dm-tx $PERSIST $META_FILE $TXR_FILE $BLKDEV_LAYOUT $NUM_BLKDEVS $BLKDEV_LIST $SEG_SIZE_MB \
	$SSD_CACHE_POLICY /dev/sde $SSD_CACHE_SIZE_MB $MEM_CACHE_POLICY $MEM_CACHE_SIZE_MB \
	| sudo dmsetup create "${NAME}"
