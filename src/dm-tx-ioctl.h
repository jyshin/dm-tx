#ifndef __DM_TX_IOCTL_H__
#define __DM_TX_IOCTL_H__

#include <linux/ioctl.h>

#define DM_TX_IOCTL_TYPE 0xFE

/*
 * S means "Set" through a ptr,
 * T means "Tell" directly with the argument value
 * G means "Get": reply by setting through a pointer
 * Q means "Query": response is on the return value
 * X means "eXchange": switch G and S atomically
 * H means "sHift": switch T and Q atomically
 */

#define DM_TX_IOC_G_GETCURVER _IOR(DM_TX_IOCTL_TYPE, 3, unsigned int)
#define DM_TX_IOC_G_GETOLDESTVER _IOR(DM_TX_IOCTL_TYPE, 4, unsigned int)
#define DM_TX_IOC_SQ_SETOLDESTVER _IOW(DM_TX_IOCTL_TYPE, 5, unsigned int)

// TX 
#define DM_TX_IOC_Q_BEGINFTX _IO(DM_TX_IOCTL_TYPE, 14)
#define DM_TX_IOC_Q_ABORTFTX _IO(DM_TX_IOCTL_TYPE, 16)
#define DM_TX_IOC_GQ_ENDFTX _IOR(DM_TX_IOCTL_TYPE, 25, unsigned int)

// Pinned caching
#define DM_TX_IOC_SQ_SETCACHEDRANGE _IOW(DM_TX_IOCTL_TYPE, 17, unsigned int)
#define DM_TX_IOC_SQ_SETCACHEDBLOCK _IOW(DM_TX_IOCTL_TYPE, 18, unsigned int)
#define DM_TX_IOC_SQ_SETDIRTYBITS _IOW(DM_TX_IOCTL_TYPE, 19, unsigned int)

// TX hand over 
#define DM_TX_IOC_GQ_RELEASETX _IOR(DM_TX_IOCTL_TYPE, 20, unsigned int)
#define DM_TX_IOC_SQ_TAKEOVERTX _IOW(DM_TX_IOCTL_TYPE, 21, unsigned int)

#define DM_TX_IOC_G_GETPID _IOR(DM_TX_IOCTL_TYPE, 22, unsigned int)

// For weakly consistent reads
#define DM_TX_IOC_SQ_OPENVER _IOW(DM_TX_IOCTL_TYPE, 6, unsigned int)
#define DM_TX_IOC_TGQ_GETCOST _IOW(DM_TX_IOCTL_TYPE, 23, unsigned int)
#define DM_TX_IOC_TGQ_GETVERLIMIT _IOW(DM_TX_IOCTL_TYPE, 24, unsigned int)

#define DM_TX_IOC_NR_ID_BITS 7
#define DM_TX_IOC_NR_SIZE_BITS 5
#define DM_TX_IOC_NR_START_BITS 12
#define DM_TX_IOC_NR_CNT_BITS 8

#define DM_TX_IOC_ID_MASK ((1 << DM_TX_IOC_NR_ID_BITS)-1)
#define DM_TX_IOC_SIZE_MASK ((1 << DM_TX_IOC_NR_SIZE_BITS)-1)
#define DM_TX_IOC_START_MASK ((1 << DM_TX_IOC_NR_START_BITS)-1)
#define DM_TX_IOC_CNT_MASK ((1 << DM_TX_IOC_NR_CNT_BITS)-1)

#define DM_TX_IOC_CNT_SHIFT 0
#define DM_TX_IOC_START_SHIFT (DM_TX_IOC_CNT_SHIFT	\
					+ DM_TX_IOC_NR_CNT_BITS)
#define DM_TX_IOC_SIZE_SHIFT (DM_TX_IOC_START_SHIFT	\
					+ DM_TX_IOC_NR_START_BITS)
#define DM_TX_IOC_ID_SHIFT (DM_TX_IOC_SIZE_SHIFT		\
				+ DM_TX_IOC_NR_SIZE_BITS)

// This macro generated command is used for DM_TX_IOC_SQ_SETDIRTYBITS ioctl calls.
// This ioctl call actually sets accessed bits: it not only works for write but
// also for reads. 
//
// id: I/O sequence number within a TX.
// size: subblock size (= 2 ^ (size))
// start: start position in subblock granularity
// cnt: number of subblocks from start
//
// e.g. 5th write within a TX accessed two 512B subblocks within a 4KB block which are 
// the fourth and the fifth subblocks. 
// DM_TX_ENCODE_EXTAB_CODE(5, 9, 3, 2);
#define DM_TX_ENCODE_EXTAB_CODE(id, size, start, cnt)\
	(((id) << DM_TX_IOC_ID_SHIFT) |			\
		((size) << DM_TX_IOC_SIZE_SHIFT) |		\
		((start) << DM_TX_IOC_START_SHIFT) |		\
		((cnt) << DM_TX_IOC_CNT_SHIFT))

#define DM_TX_EXTAB_ID(code) (((code) >> DM_TX_IOC_ID_SHIFT)  & \
					DM_TX_IOC_ID_MASK)

#define DM_TX_EXTAB_SIZE(code) (((code) >> DM_TX_IOC_SIZE_SHIFT)  & \
					DM_TX_IOC_SIZE_MASK)

#define DM_TX_EXTAB_START(code) (((code) >> DM_TX_IOC_START_SHIFT)  & \
					DM_TX_IOC_START_MASK)

#define DM_TX_EXTAB_CNT(code) (((code) >> DM_TX_IOC_CNT_SHIFT)  & \
					DM_TX_IOC_CNT_MASK)

#define DM_TX_COST_QUERY_LIMIT 7

struct addr_size {
	unsigned int addr;
	unsigned int size;
};

struct addr_versions {
	unsigned int addr;
	unsigned int versions[DM_TX_COST_QUERY_LIMIT];
};

struct addr_version {
	unsigned int addr;
	unsigned int version;
};

#endif
