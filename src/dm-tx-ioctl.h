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

#define DM_TX_IOC_Q_BEGINTX _IO(DM_TX_IOCTL_TYPE, 1)
#define DM_TX_IOC_Q_ENDTX _IO(DM_TX_IOCTL_TYPE, 2)
#define DM_TX_IOC_G_GETCURVER _IOR(DM_TX_IOCTL_TYPE, 3, unsigned int)
#define DM_TX_IOC_G_GETOLDESTVER _IOR(DM_TX_IOCTL_TYPE, 4, unsigned int)
#define DM_TX_IOC_SQ_SETOLDESTVER _IOW(DM_TX_IOCTL_TYPE, 5, unsigned int)

//#define DM_TX_IOC_Q_CLOSE _IO(DM_TX_IOCTL_TYPE, 7)
//#define DM_TX_IOC_SQ_BEGINSTALEREAD _IOW(DM_TX_IOCTL_TYPE, 8, unsigned int)
//#define DM_TX_IOC_Q_ENDSTALEREAD _IO(DM_TX_IOCTL_TYPE, 9)
//#define DM_TX_IOC_Q_BEGINSTX _IO(DM_TX_IOCTL_TYPE, 10)
//#define DM_TX_IOC_Q_ENDSTX _IO(DM_TX_IOCTL_TYPE, 11)
//#define DM_TX_IOC_Q_ABORTTX _IO(DM_TX_IOCTL_TYPE, 12)
//#define DM_TX_IOC_Q_ABORTSTX _IO(DM_TX_IOCTL_TYPE, 13)

// TX 
#define DM_TX_IOC_Q_BEGINFTX _IO(DM_TX_IOCTL_TYPE, 14)
//#define DM_TX_IOC_Q_ENDFTX _IO(DM_TX_IOCTL_TYPE, 15)
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


#define DM_TX_ENCODE_EXTDB_CODE(id, size, start, end)\
	(((id) << DM_TX_IOC_ID_SHIFT) |			\
		((size) << DM_TX_IOC_SIZE_SHIFT) |		\
		((start) << DM_TX_IOC_START_SHIFT) |		\
		((end) << DM_TX_IOC_CNT_SHIFT))

#define DM_TX_EXTDB_ID(code) (((code) >> DM_TX_IOC_ID_SHIFT)  & \
					DM_TX_IOC_ID_MASK)

#define DM_TX_EXTDB_SIZE(code) (((code) >> DM_TX_IOC_SIZE_SHIFT)  & \
					DM_TX_IOC_SIZE_MASK)

#define DM_TX_EXTDB_START(code) (((code) >> DM_TX_IOC_START_SHIFT)  & \
					DM_TX_IOC_START_MASK)

#define DM_TX_EXTDB_CNT(code) (((code) >> DM_TX_IOC_CNT_SHIFT)  & \
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
