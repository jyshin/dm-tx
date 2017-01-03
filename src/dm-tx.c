#include <asm/atomic.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/device-mapper.h>
#include <linux/dm-io.h>
#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/hash.h>
#include <linux/highmem.h>
#include <linux/hrtimer.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/mempool.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/pagemap.h>
#include <linux/percpu.h>
#include <linux/random.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/threads.h>
#include <linux/version.h>
#include <linux/workqueue.h>
#include <scsi/sg.h>

#include "dm-tx-ioctl.h"
#include "lru-cache.h"

#define MAX_U32		0xFFFFFFFF
#define MAX_U16		0xFFFF
#define MAX_U8		0xFF

#define POW_OF_2(number) (((number != 0) && (number & (number - 1))) == 0)

#define MIN_JOBS_IN_POOL	1024
#define MIN_PROCS_IN_POOL       128
#define DM_TX_GC_COPY_PAGES	512
#define DM_TX_MAX_STRIPES	32
#define MIN_GC_CONCURRENT_REQ   4
#define GC_CONCURRENT_REQ       64
#define MAX_GC_CONCURRENT_REQ   DM_TX_GC_COPY_PAGES

#define GC_DEFAULT_LOW_WATERMARK		0
#define GC_DEFAULT_HIGH_WATERMARK		3
#define DM_TX_CRITICAL_WATERMARK		1024
#define DM_TX_CRITICAL_WATERMARK_HARD	8

#define TX_NO_VERSION		MAX_U32
#define TX_READ_NO_VERSION	(MAX_U32 - 1)
#define TX_WRITE_NO_VERSION	(MAX_U32 - 2)
#define MAX_VERSION		(MAX_U32 - 3)

#define NUM_TX_IO_LIMIT 256


#define DM_TX_PREFIX "dm-tx: "
#define DM_TX_DEBUG 0
#if DM_TX_DEBUG
#define DPRINTK( s, arg... ) printk(DM_TX_PREFIX s "\n", ##arg)
#else
#define DPRINTK( s, arg... )
#endif

#define DM_TX_IOCTL_DEBUG 0
#if DM_TX_IOCTL_DEBUG
#define IOCPRINTK( s, arg... ) printk(DM_TX_PREFIX "IOCTL: " s "\n", ##arg)
#else
#define IOCPRINTK( s, arg... )
#endif

/* blocks the size of pages: PAGE_SHIFT 12 
 * sector size: SECTOR_SHIFT 9
 */
#define GECKO_BLOCK_SHIFT PAGE_SHIFT
#define GECKO_BLOCK_SIZE (1UL << GECKO_BLOCK_SHIFT)
#define GECKO_SECTOR_SIZE (1UL << SECTOR_SHIFT)

#define GECKO_SECTOR_TO_BLOCK_SHIFT (GECKO_BLOCK_SHIFT - SECTOR_SHIFT)
#define GECKO_SECTOR_TO_BLOCK_MASK ((1UL << GECKO_SECTOR_TO_BLOCK_SHIFT) - 1)
#define GECKO_SECTORS_PER_BLOCK (1UL << GECKO_SECTOR_TO_BLOCK_SHIFT)

#define GECKO_SECTOR_PER_BLOCK (1UL << GECKO_SECTOR_TO_BLOCK_SHIFT)
#define GECKO_SECTOR_DIRTY_BITS MAX_U8

#define GECKO_MB_TO_BLOCK_SHIFT (8)
#define NUM_EXT_DIRTY_BITS (GECKO_BLOCK_SIZE >> 4)
#define NUM_EXT_DIRTY_BYTES (NUM_EXT_DIRTY_BITS >> 3)

#define DMTX_CREATE_CMD "dmsetup create [dm-name] [start_addr] [end_addr]" \
	"[dev-name] [persist: 0|1] [meta file path] " \
	"[blkdev layout: gecko] [# blkdev] " \
	"[blkdev paths: as many as # blkdev]+ " \
	"[segment size (MB): power of 2] " \
	"[ssd cache policy: none|lru_rd|lru_rdwr] " \
	"[ssd cache path] [ssd cache size (MB): power of 2] " \
	"[memory cache policy: none|lru_rd|lru_rdwr] " \
	"[memory cache size (MB): power of 2] "

/* Hashtable for pending IO operations indexed by block number */
#define HASH_TABLE_BITS 12
#define HASH_TABLE_SIZE (1UL << HASH_TABLE_BITS)

#define YOGURT_WRITE_WEIGHT	100


/*****************************************************************************\
 * Global variables:
 * Global memory cache and pools.
 * Workqueue and related lists to interface between Gecko and isotope. 
\*****************************************************************************/

static struct kmem_cache *io_job_cache, *d_map_entry_cache, *proc_info_cache,
			 *tx_record_cache, *tx_io_cache;
static mempool_t *io_job_mempool, *d_map_entry_mempool, *proc_info_mempool,
		 *tx_record_mempool, *tx_io_mempool;


/* Interfaces between Gecko and Isotope */
static struct workqueue_struct *io_finish_work_queue = NULL;
static struct work_struct io_finish_work;

static LIST_HEAD(finished_io_list);
static DEFINE_SPINLOCK(finished_io_list_lock);

static struct list_head *outstanding_io_job_list_map;
static DEFINE_SPINLOCK(outstanding_io_job_list_map_lock);


/*****************************************************************************\
 * Gecko related structs.
\*****************************************************************************/

struct d_map_entry {
	u32 phy_addr;
	u32 version;
	void *page;
	struct list_head list;
};

struct r_map_entry {
	u32 virt_addr;
	u32 version;
};

 /* TODO explicitly support segments */
struct dm_dev_info {
	struct list_head list;
	int idx;          /* only used for debugging purposes */
	sector_t start;   /* offset in sectors */
	sector_t len;     /* len in sectors */
	struct dm_dev *ddev;
	struct work_struct work;
	atomic_t outstanding_writes;
	atomic_t outstanding_reads;
	sector_t tail;
	sector_t head;
};

struct phy_dev_map {
	sector_t len;                /* total linear length in sectors */
	int cnt;                     /* number of blk devs */
	struct list_head dm_dev_info_list;
};

struct gc_ctrl {
	u32 low_watermark;
	u32 high_watermark;
};

struct dm_gecko_stats {
	unsigned long long reads, writes, gc, discards, empty_barriers,
		      gc_recycle, rw_clash, rw_gc_clash, gc_clash, gc_rw_clash,
		      ww_clash, read_empty, read_err, write_err;
};

enum {  // dm_gecko->flags bit positions
	DM_TX_GC_FORCE_STOP,
	DM_TX_FINAL_SYNC_METADATA,
	DM_TX_GC_STARTED,
	DM_TX_INDEPENDENT_GC,
	DM_TX_SYNCING_METADATA,
};

struct dm_gecko {
	u32 curr_ver;
	u32 oldest_ver;

	spinlock_t lock;

	struct list_head *d_list_map;
	struct r_map_entry *r_map;

	struct lru_cache *lru_mem_cache;
	u32 lru_cache_size_blk;

	volatile unsigned long *cached_v_block_map;

	u32 tail;
	u32 head;
	u32 size;	// size of the addr space in number of blocks

	u32 available_blocks;		// Should be > 1
	u32 free_blocks;		// total number of free blocks
	struct dm_dev_info *curr_dev;
	volatile unsigned long flags;
	int gc_req_in_progress;
	int max_gc_req_in_progress;
	struct phy_dev_map dev_map;

	u32 seg_size_blk;

	struct dm_io_client *io_client;
	struct gc_ctrl gc_ctrl;
	struct work_struct gc_work;
	wait_queue_head_t free_space_wait_queue;
	unsigned long tail_wrap_around;
	unsigned long head_wrap_around;

	struct dm_gecko_stats *stats;
};


/*****************************************************************************\
 * Isotope related structs.
\*****************************************************************************/

struct tx_io {
	int rw;
	u32 v_block;
	u32 l_block;

	volatile unsigned char *data_bits;
	volatile unsigned char *accessed_bits;

	u16 accessed_start; // start of accessed subblock
	u16 accessed_cnt;   // number of accessed subblocks

	void *page; /* data block or page storing write data */

	struct list_head io_list; /* hook to io_list in tx_record */
};

struct tx_record {
	u32 start_ver;
	u32 end_ver; /* latest I/O version num in the tx */

	int nest_count;

	int nr_reads;
	int nr_writes;

	int nr_tx_to_wait;

	u32 nr_accessed_bytes;	// nr bytes to maintain accessed bits for a whole block
				// using the granularity below
	u16 granularity;	// number of bytes that a single accessed bit represents

	struct list_head io_list; /* list of I/Os performed during tx */

	u8 success; /* whether tx succeeded or not */
	u8 fail_all_successors;

	struct list_head record_list; /* hook to finished tx record list */

	int state; /* 0 default
		    * state 0 — blank state given when tx begins
		    * state 1 — endtx call started but we don't know the decision for tx commit 
		    * state 2 — we know the decision I/O not written to dev
		    * state 3 — we have written the data blocks, but not tx record
		    * state 4 — tx record is written, mapping is updated and done
		    */
	wait_queue_head_t prior_tx_wait_queue;

	spinlock_t lock;
};

enum {  // proc_info->flags bit positions
	PROC_INFO_TRANSACTION = 0,
	PROC_INFO_STALEREAD = 1,
};

struct proc_info {
	pid_t pid;

	int nest_count;
	volatile unsigned long flags; /* used to indicate time travel,
				       * stale read, transaction status. */

	u32 ver_opened;			/* used for time travel */
	u32 ver_limit;			/* used for stale read */

	struct tx_record *txr;

	atomic_t nr_outstanding_io;	// Number of outstanding I/O
	wait_queue_head_t tx_io_wait_queue;

	struct list_head pi_list; /* hook to dmi->proc_info_list_map */
	struct list_head tt_list; /* hook to dmi->tx_proc_info_list */
};

struct dm_isotope_stats {
	unsigned long long tx_reads, subblock_reads, tx_writes, subblock_writes,
		      readwrite_tx, writeonly_tx, readonly_tx,
		      tx_success, tx_failure, tx_abort;
};

struct dm_isotope {
	atomic_t nr_outstanding_io;	// Number of outstanding I/O
	wait_queue_head_t io_finish_wait_queue;

	u32 request_id;		// Used for tagging I/O requests

	u64 curr_ver;		// Currently visible version to users 
	u64 outstanding_ver;	// Latest version that is being committed
	u64 oldest_ver;		// Oldest available version (GC limit)

	struct list_head tx_record_list;	// Completed tx records
	struct list_head tx_proc_info_list;	// List of proc_info doing tx

	struct list_head *proc_info_list_map;	// Chained hashmap for all
						// proc_info
	u32 nr_proc;		// Number of items in proc_info_list_map

	struct list_head *tmp_proc_info_list_map; // Chained hashmap for
						  // proc_info that is released
						  //  and waiting to be
						  // taken over
	u32 nr_tmp_proc;	// Number of items in tmp_proc_info_list_map

	spinlock_t request_id_lock;
	spinlock_t version_lock;	// locks curr_ver, outstanding_ver
					// and oldest_ver

	spinlock_t tx_record_list_lock;		// locks tx_record_list,
						// txr->success, txr->state,
						// and, txr->end_ver.
	spinlock_t tx_proc_info_list_lock;	// locks tx_proc_info_list
	spinlock_t proc_info_list_map_lock;	// locks proc_info_list_map, 
						// and nr_proc
	spinlock_t tmp_proc_info_list_map_lock; // locks tmp_proc_info_list_map
						// and nr_tmp_proc
	struct dm_isotope_stats *stats;
};


/*****************************************************************************\
 * Dm-tx related structs.
\*****************************************************************************/

#define IO_JOB_READ_MODIFY_WRITE	0x01
#define IO_JOB_SUBBLOCK_READ		0x02
#define IO_JOB_TX			0x04
#define IO_JOB_GC			0x08

struct io_job {
	struct dm_tx *dmtx;
	struct dm_isotope *dmi;
	struct dm_gecko *dmg;

	u32 id;
	volatile u8 type;
	int rw;				// READ or WRITE:

	struct bio *bio;		// if NULL this is a gc IO or tx write
	sector_t v_block;		// virtual block 
	u32 version;

	void *page;			// for read-modify-update cycles

	struct proc_info *pi;
	struct tx_io *txio;		// This points to corresponding
					// I/O record in the transaction record 

	struct list_head finished_job_list;	// hook to io finish queue 
						// between front and back end
	struct list_head hash_list;		// hook to hash list by id

	// Used by gecko
	sector_t l_block;			// linear block 
	sector_t old_l_block;			// old linear block for gc
	int err;
};

// Currently not used
struct dm_tx_stats {
	unsigned long long flushes, discards, reads, subblock_reads,
		      writes, subblock_writes, read_err, write_err;
};

struct ctr_args {
	int persistent;
	char *meta_filename;

	char *blkdev_layout;
	int nr_blkdevs;
	char *blkdev_paths[DM_TX_MAX_STRIPES];

	// for gecko use only
	int seg_size_mb;

	char *ssd_cache_policy;
	char *ssd_cache_path;
	int ssd_cache_size_mb;

	char *mem_cache_policy;
	int mem_cache_size_mb;
};

enum {
	BLKDEV_LAYOUT_GECKO,
	BLKDEV_LAYOUT_LINEAR,
};

struct dm_tx {
	struct dm_isotope *dmi;
	struct dm_gecko *dmg;

	volatile unsigned long flags;
	int persistent;
	char *meta_filename;
	int blkdev_layout;
	struct dm_tx_stats *stats;
};


/*****************************************************************************\
 * Sector and block operations
\*****************************************************************************/

static inline sector_t sector_to_block(sector_t sector)
{
	return (sector >> GECKO_SECTOR_TO_BLOCK_SHIFT);
}

static inline sector_t block_to_sector(sector_t sector)
{
	return (sector << GECKO_SECTOR_TO_BLOCK_SHIFT);
}

static inline int sector_at_block_boundary(sector_t sector)
{
	return ((sector & GECKO_SECTOR_TO_BLOCK_MASK) == 0x0);
}

static inline int bio_start_at_block_boundary(struct bio *bio)
{
	return sector_at_block_boundary(bio->bi_sector);
}

static inline int bio_end_at_block_boundary(struct bio *bio)
{
	return sector_at_block_boundary(bio->bi_sector +
					to_sector(bio->bi_size));
}

static inline int bio_at_block_boundary(struct bio *bio)
{
	return bio_start_at_block_boundary(bio)
		&& bio_end_at_block_boundary(bio);
}

static inline int bio_single_block_at_block_boundary(struct bio *bio)
{
	return (bio->bi_size == GECKO_BLOCK_SIZE)
		&& bio_at_block_boundary(bio);
}


/*****************************************************************************\
 * io_job type operations
\*****************************************************************************/

static inline void set_io_job_read_modify_write(struct io_job *io)
{
	io->type |= IO_JOB_READ_MODIFY_WRITE;
}

static inline void set_io_job_subblock_read(struct io_job *io)
{
	io->type |= IO_JOB_SUBBLOCK_READ;
}

static inline void set_io_job_tx(struct io_job *io)
{
	io->type |= IO_JOB_TX;
}

static inline void set_io_job_gc(struct io_job *io)
{
	io->type |= IO_JOB_GC;
	io->bio = NULL;
}

static inline int is_io_job_read_modify_write(struct io_job *io)
{
	return (io->type & IO_JOB_READ_MODIFY_WRITE);
}

static inline int is_io_job_subblock_read(struct io_job *io)
{
	return (io->type & IO_JOB_SUBBLOCK_READ);
}

static inline int is_io_job_tx(struct io_job *io)
{
	return (io->type & IO_JOB_TX);
}

static inline int is_io_job_gc(struct io_job *io)
{
	return (io->type & IO_JOB_GC);
}

/*****************************************************************************\
 * Utility functions
\*****************************************************************************/

static inline int list_is_only_item(struct list_head *item,
				    struct list_head *head)
{
	return ((item->next == head) && (item->prev == head));
}

static void memcpy_bio_into_page(struct io_job *io)
{
	int i;
	struct bio_vec *bvec;
	struct bio *bio = io->bio;
	char *addr = io->page
		+ to_bytes(bio->bi_sector & GECKO_SECTOR_TO_BLOCK_MASK);
	bio_for_each_segment(bvec, bio, i) {
		unsigned long flags;
		char *bio_addr = bvec_kmap_irq(bvec, &flags);
		memcpy(addr, bio_addr, bvec->bv_len);
		bvec_kunmap_irq(bio_addr, &flags);
		addr += bvec->bv_len;
	}
}

static void memcpy_page_into_bio(struct io_job *io)
{
	int i;
	struct bio_vec *bvec;
	struct bio *bio = io->bio;
	char *addr = io->page
		+ to_bytes(bio->bi_sector & GECKO_SECTOR_TO_BLOCK_MASK);
	bio_for_each_segment(bvec, bio, i) {
		unsigned long flags;
		char *bio_addr = bvec_kmap_irq(bvec, &flags);
		memcpy(bio_addr, addr, bvec->bv_len);
		bvec_kunmap_irq(bio_addr, &flags);
		addr += bvec->bv_len;
	}
}

static void memcpy_bio_into_reg_page(struct io_job *io, void *page)
{
	int i;
	struct bio_vec *bvec;
	struct bio *bio = io->bio;
	char *addr =
		page + to_bytes(bio->bi_sector & GECKO_SECTOR_TO_BLOCK_MASK);
	bio_for_each_segment(bvec, bio, i) {
		unsigned long flags;
		char *bio_addr = bvec_kmap_irq(bvec, &flags);
		memcpy(addr, bio_addr, bvec->bv_len);
		bvec_kunmap_irq(bio_addr, &flags);
		addr += bvec->bv_len;
	}
}

static void memcpy_reg_page_into_bio(struct io_job *io, void *page)
{
	int i;
	struct bio_vec *bvec;
	struct bio *bio = io->bio;
	char *addr =
		page + to_bytes(bio->bi_sector & GECKO_SECTOR_TO_BLOCK_MASK);
	bio_for_each_segment(bvec, bio, i) {
		unsigned long flags;
		char *bio_addr = bvec_kmap_irq(bvec, &flags);
		memcpy(bio_addr, addr, bvec->bv_len);
		bvec_kunmap_irq(bio_addr, &flags);
		addr += bvec->bv_len;
	}
}



/*****************************************************************************\
 * Version operations.
\*****************************************************************************/

static inline u32 mark_version_pending(void)
{
	return MAX_VERSION;
}

static inline int is_version_pending(u32 version)
{
	return (version >= MAX_VERSION);
}

static inline int is_version_tx_write(u32 version)
{
	return (version == TX_WRITE_NO_VERSION);
}

static inline int is_version_tx_read(u32 version)
{
	return (version == TX_READ_NO_VERSION);
}

static u32 get_oldest_ver_in_use(struct dm_isotope *dmi)
{
	unsigned long flags;
	struct proc_info *pi;
	u32 version = MAX_VERSION;

	spin_lock_irqsave(&dmi->tx_proc_info_list_lock, flags);
	list_for_each_entry(pi, &dmi->tx_proc_info_list, tt_list) {
		if (pi->ver_opened < version) {
			BUG_ON(is_version_pending(pi->ver_opened));
			version = pi->ver_opened;
		}
	}
	spin_unlock_irqrestore(&dmi->tx_proc_info_list_lock, flags);
	return version;
}

static inline u32 __inc_and_get_curr_ver(struct dm_gecko *dmg)
{
	return (++dmg->curr_ver);
}

static inline u32 __inc_and_get_outstanding_ver(struct dm_isotope *dmi)
{
	u32 outstanding_ver;
	unsigned long flags;

	spin_lock_irqsave(&dmi->version_lock, flags);
	BUG_ON(dmi->outstanding_ver < dmi->curr_ver);

	outstanding_ver = ++dmi->outstanding_ver;
	spin_unlock_irqrestore(&dmi->version_lock, flags);

	return outstanding_ver;
}

/*****************************************************************************\
 * tx_record and proc_info operations.
\*****************************************************************************/

static inline void init_tx_record(struct tx_record *txr, u32 start_ver)
{
	txr->nest_count = 0;
	txr->start_ver = start_ver;
	txr->end_ver = 0;
	INIT_LIST_HEAD(&txr->io_list);
	txr->success = 0;
	txr->fail_all_successors = 0;
	txr->state = 0;
	txr->nr_reads = 0;
	txr->nr_writes = 0;
	txr->nr_tx_to_wait = 0;
	txr->nr_accessed_bytes = 0;
	init_waitqueue_head(&txr->prior_tx_wait_queue);
	spin_lock_init(&txr->lock);
}


static inline void init_proc_info(struct proc_info *pi, pid_t pid)
{
	pi->pid = pid;
	pi->flags = 0;
	pi->ver_opened = mark_version_pending();
	pi->ver_limit = mark_version_pending();
	atomic_set(&pi->nr_outstanding_io, 0);

	INIT_LIST_HEAD(&pi->pi_list);
	INIT_LIST_HEAD(&pi->tt_list);
	init_waitqueue_head(&pi->tx_io_wait_queue);
}

static inline int is_transaction_ongoing(struct proc_info *pi)
{
	if (pi == NULL) {
		return 0;
	}
	return test_bit(PROC_INFO_TRANSACTION, &pi->flags);
}

/* operation on proc_info_list_map hash table */
static struct proc_info *get_proc_info(struct dm_isotope *dmi,
				       pid_t pid)
{
	struct proc_info *pi;
	unsigned long flags;
	unsigned long idx = hash_long(pid, HASH_TABLE_BITS);
	struct list_head *proc_info_list = &dmi->proc_info_list_map[idx];

	spin_lock_irqsave(&dmi->proc_info_list_map_lock, flags);
	list_for_each_entry(pi, proc_info_list, pi_list) {
		if (pi->pid == pid) {
			spin_unlock_irqrestore(&dmi->proc_info_list_map_lock,
					       flags);
			return pi;
		}
	}
	spin_unlock_irqrestore(&dmi->proc_info_list_map_lock, flags);
	return NULL;
}

/* WARNING: duplicates are not checked. */
static void put_proc_info(struct dm_isotope *dmi,
			  struct proc_info *pi)
{
	unsigned long flags;
	unsigned long idx = hash_long(pi->pid, HASH_TABLE_BITS);
	struct list_head *proc_info_list = &dmi->proc_info_list_map[idx];

	spin_lock_irqsave(&dmi->proc_info_list_map_lock, flags);
	list_add_tail(&pi->pi_list, proc_info_list);
	++dmi->nr_proc;
	spin_unlock_irqrestore(&dmi->proc_info_list_map_lock, flags);
}

static void remove_proc_info(struct dm_isotope *dmi, struct proc_info *pi)
{
	unsigned long flags;
	spin_lock_irqsave(&dmi->proc_info_list_map_lock, flags);
	list_del(&pi->pi_list);
	--dmi->nr_proc;
	spin_unlock_irqrestore(&dmi->proc_info_list_map_lock, flags);
}


/*****************************************************************************\
 * Sector and block device operations.
\*****************************************************************************/

static inline int sector_in_dev(sector_t sector, struct dm_dev_info *dev)
{
	return (sector >= dev->start) && (sector < dev->start + dev->len);
}

static struct dm_dev_info *dev_for_sector(struct dm_gecko *dmg, sector_t sector)
{
	struct dm_dev_info *dev;
	list_for_each_entry(dev, &dmg->dev_map.dm_dev_info_list, list) {
		if (sector < dev->start + dev->len) {
			return dev;
		}
	}
	return NULL;
}

static struct dm_dev_info *get_next_dev(struct dm_gecko *dmg,
					struct dm_dev_info *curr_dev)
{
	struct dm_dev_info *next_dev;
	int next_idx = curr_dev->idx + 1;
	if (next_idx >= dmg->dev_map.cnt)
		next_idx = 0;

	list_for_each_entry(next_dev, &dmg->dev_map.dm_dev_info_list, list) {
		if (next_dev->idx == next_idx) {
			//printk("next_idx selected %d\n", next_idx);
			return next_dev;
		}
	}
	return NULL;
}

static struct dm_dev_info * linear_to_phy(struct dm_gecko *dmg, sector_t sector,
					  struct dm_io_region *where)
{
	struct dm_dev_info *dev = dev_for_sector(dmg, sector);

	BUG_ON(!dev);  /* must fit in the range somewhere */

	where->bdev = dev->ddev->bdev;
	where->sector = sector - dev->start;
	where->count = GECKO_SECTORS_PER_BLOCK;
	return dev;
}


/*****************************************************************************\
 * Simple block operations.
\*****************************************************************************/

static inline u32 mark_block_free(struct dm_gecko *dmg)
{
	return dmg->size;
}

static inline int is_block_marked_free(u32 block, struct dm_gecko *dmg)
{
	return (block == dmg->size);
}

static inline int is_block_invalid(u32 block, struct dm_gecko *dmg)
{
	return (block > dmg->size);
}

static inline int is_block_free_or_invalid(u32 block, struct dm_gecko *dmg)
{
	return (block >= dmg->size);
}

static inline int __no_available_blocks(struct dm_gecko *dmg)
{
	/* can be less than the watermark temporarily while gc runs */
	return (dmg->available_blocks <= DM_TX_CRITICAL_WATERMARK);
}

static inline int __no_available_blocks_hard(struct dm_gecko *dmg)
{
	return (dmg->available_blocks <= DM_TX_CRITICAL_WATERMARK_HARD);
}

static inline u32 __relocatable_blocks(struct dm_gecko *dmg)
{
	return dmg->free_blocks - dmg->available_blocks;
}

static inline u32 __unavailable_blocks(struct dm_gecko *dmg)
{
	return dmg->size - dmg->available_blocks;
}

static inline u32 __used_blocks(struct dm_gecko *dmg)
{
	return dmg->size - dmg->free_blocks;
}


/*****************************************************************************\
 * r_map and d_list_map operations.
\*****************************************************************************/

static inline void mark_r_map_entry_free(struct dm_gecko *dmg, u32 l_block)
{
	dmg->r_map[l_block].virt_addr = mark_block_free(dmg);
	dmg->r_map[l_block].version = mark_version_pending();
}

static inline int __is_l_block_free(struct dm_gecko *dmg, u32 l_block)
{
	int itr = 0;
	struct d_map_entry *entry;
	u32 v_block;

	/* if we assume r_map is in SSD and not in memory
	 * this method may take longer. */
	v_block = dmg->r_map[l_block].virt_addr;
	if (is_block_marked_free(v_block, dmg)) {
		BUG_ON(!is_version_pending(dmg->r_map[l_block].version));
		return 1;
	}

	list_for_each_entry(entry, &dmg->d_list_map[v_block], list) {
		if (entry->phy_addr == l_block) {
			if (itr > 0 && entry->version < dmg->oldest_ver) {
				return 1;
			} else {
				return 0;
			}

		}
		itr++;
	}
	BUG_ON(!is_block_marked_free(l_block, dmg));
	return 1;
}

static inline int __is_d_list_map_invalid(struct dm_gecko *dmg, u32 v_block)
{
	return list_empty(&dmg->d_list_map[v_block]);
}

static inline int __is_d_list_map_free(struct dm_gecko *dmg, u32 v_block)
{
	return list_empty(&dmg->d_list_map[v_block]);
}

static inline u32 __get_latest_l_block(struct dm_gecko *dmg, u32 v_block)
{
	if (list_empty(&dmg->d_list_map[v_block])) {
		return dmg->size;
	} else {
		struct d_map_entry *entry =
			list_first_entry(&dmg->d_list_map[v_block],
					 struct d_map_entry, list);
		return entry->phy_addr;
	}
}

static inline u32 __get_latest_version(struct dm_gecko *dmg, u32 v_block)
{
	if (list_empty(&dmg->d_list_map[v_block])) {
		return MAX_VERSION;
	} else {
		struct d_map_entry *entry =
			list_first_entry(&dmg->d_list_map[v_block],
					 struct d_map_entry, list);
		return entry->version;
	}
}

static inline u32 __get_old_l_block(struct dm_gecko *dmg, u32 v_block,
				    u32 version)
{
	if (list_empty(&dmg->d_list_map[v_block])) {
		return dmg->size;
	} else {
		struct d_map_entry *entry;
		/* The list is sorted from the latest to the oldest. */
		list_for_each_entry(entry, &dmg->d_list_map[v_block], list) {
			if (entry->version <= version) {
				return entry->phy_addr;
			}
		}
		return dmg->size;
	}
}

static inline u32 __get_old_version_limit(struct dm_gecko *dmg, u32 v_block,
					  u32 version)
{
	u32 limit = MAX_VERSION;
	if (list_empty(&dmg->d_list_map[v_block])) {
		return TX_NO_VERSION;
	} else {
		struct d_map_entry *entry;
		limit = dmg->curr_ver;
		/* The list is sorted from the latest to the oldest. */
		list_for_each_entry(entry, &dmg->d_list_map[v_block], list) {
			if (entry->version <= version) {
				return limit;
			}
			limit = entry->version;
		}
		return TX_NO_VERSION;
	}
}

static inline void * __get_old_l_block_page(struct dm_gecko *dmg, u32 v_block,
					    u32 version)
{
	if (list_empty(&dmg->d_list_map[v_block])) {
		return NULL;
	} else {
		struct d_map_entry *entry;
		/* The list is sorted from the latest to the oldest. */
		list_for_each_entry(entry, &dmg->d_list_map[v_block], list) {

			if (entry->version <= version) {
				return entry->page;
			}
		}
		return NULL;
	}
}

/* lock must be held */
static inline struct d_map_entry *__get_new_d_map_entry(struct dm_gecko *dmg,
							u32 phy_addr)
{
	struct d_map_entry *entry;
	entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
	if (entry == NULL) {
		return NULL;
	}
	entry->phy_addr = phy_addr;
	entry->version = __inc_and_get_curr_ver(dmg);
	entry->page = NULL;
	INIT_LIST_HEAD(&entry->list);
	return entry;
}

static inline struct d_map_entry *__get_new_d_map_entry_no_version(u32 phy_addr)
{
	struct d_map_entry *entry;
	entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
	if (entry == NULL) {
		return NULL;
	}
	entry->phy_addr = phy_addr;
	entry->version = MAX_VERSION;
	entry->page = NULL;
	INIT_LIST_HEAD(&entry->list);
	return entry;
}

/* lock must be held */
static inline
struct d_map_entry * __insert_new_d_map_entry_with_version(struct dm_gecko *dmg,
							   u32 v_block,
							   u32 l_block,
							   u32 version)
{
	struct d_map_entry *new_entry
		= __get_new_d_map_entry_no_version(l_block);
	if (new_entry == NULL) {
		return NULL;
	}
	new_entry->version = version;
	list_add(&new_entry->list, &dmg->d_list_map[v_block]);

	return new_entry;
}

/* lock must be held */
static inline
struct d_map_entry * __insert_new_d_map_entry(struct dm_gecko *dmg, u32 v_block,
					      u32 l_block)
{
	struct d_map_entry *new_entry
		= __get_new_d_map_entry(dmg, l_block);
	if (new_entry == NULL) {
		return NULL;
	}
	list_add(&new_entry->list, &dmg->d_list_map[v_block]);

	return new_entry;
}

/* lock must be held */
static inline void __remove_d_map_entry(struct dm_gecko *dmg,
					struct d_map_entry *entry)
{
	entry->phy_addr = mark_block_free(dmg);
	entry->version = mark_version_pending();
	if (entry->page != NULL) {
		free_page((unsigned long) entry->page);
	}
	list_del(&entry->list);
	kfree(entry);
}

/* lock must be held
 * This function is used to update the phy addr during gc.
 */
static inline u32 __update_d_map_entry(struct dm_gecko *dmg, u32 v_block,
				       u32 old_l_block, u32 new_l_block)
{
	struct d_map_entry *entry;

	list_for_each_entry(entry, &dmg->d_list_map[v_block], list) {
		if (entry->phy_addr == old_l_block) {
			entry->phy_addr = new_l_block;
			return entry->version;
		}
	}
	BUG_ON(true);
}

/* lock must be held */
static inline struct d_map_entry * __get_d_map_entry(struct dm_gecko *dmg,
						     u32 v_block, u32 version)
{
	struct d_map_entry *entry;

	list_for_each_entry(entry, &dmg->d_list_map[v_block], list) {
		if (entry->version == version) {
			return entry;
		}
	}

	return NULL;
}

/*****************************************************************************\
 * I/O handling functions.
\*****************************************************************************/

static void do_complete_generic(struct dm_tx *dmtx)
{
	struct dm_isotope *dmi = dmtx->dmi;
	if (atomic_dec_and_test(&dmi->nr_outstanding_io)) {
		wake_up(&dmi->io_finish_wait_queue);
	}
}

static struct io_job *get_io_job_for_id(u32 id)
{
	struct io_job *io;
	unsigned long flags;

	unsigned long bucket_idx = hash_long(id, HASH_TABLE_BITS);
	struct list_head *bucket = &outstanding_io_job_list_map[bucket_idx];

	spin_lock_irqsave(&outstanding_io_job_list_map_lock, flags);
	list_for_each_entry(io, bucket, hash_list) {
		if (io->id == id) {
			list_del(&io->hash_list);
			spin_unlock_irqrestore(&outstanding_io_job_list_map_lock,
					       flags);
			return io;
		}
	}
	spin_unlock_irqrestore(&outstanding_io_job_list_map_lock, flags);
	return NULL;
}

static void put_io_job_for_id(u32 id, struct io_job *io)
{
	unsigned long flags;
	unsigned long bucket_idx = hash_long(id, HASH_TABLE_BITS);
	struct list_head *bucket = &outstanding_io_job_list_map[bucket_idx];

	spin_lock_irqsave(&outstanding_io_job_list_map_lock, flags);
	list_add_tail(&io->hash_list, bucket);
	spin_unlock_irqrestore(&outstanding_io_job_list_map_lock, flags);
}

static void notify_finished_io(struct io_job *io)
{
	unsigned long flags;

	spin_lock_irqsave(&finished_io_list_lock, flags);
	list_add_tail(&io->finished_job_list, &finished_io_list);
	spin_unlock_irqrestore(&finished_io_list_lock, flags);

	queue_work(io_finish_work_queue, &io_finish_work);
}

static void submit_io_job_to_gecko_backend(struct dm_gecko *dmg,
					   struct io_job *io);

static void finalize_regular_io(struct io_job *io)
{
	struct dm_tx *dmtx = io->dmtx;
	struct dm_gecko *dmg = io->dmg;
	if (is_io_job_read_modify_write(io)) {
		if (io->rw == READ) {
			memcpy_bio_into_page(io);
			io->rw = WRITE;
			put_io_job_for_id(io->id, io);
			submit_io_job_to_gecko_backend(dmg, io);
			return;
		} else {
			free_page((unsigned long)io->page);
		}
	} else if (is_io_job_subblock_read(io)) {
		memcpy_page_into_bio(io);
		free_page((unsigned long)io->page);
	}

	bio_endio(io->bio, io->err);
	mempool_free(io, io_job_mempool);
	do_complete_generic(dmtx);
}

static void proc_info_io_complete(struct proc_info *pi)
{
	if (is_transaction_ongoing(pi)) {
		if (atomic_dec_and_test(&pi->nr_outstanding_io)) {
			wake_up(&pi->tx_io_wait_queue);
		}
		BUG_ON(atomic_read(&pi->nr_outstanding_io) < 0);
	}
}

static void finalize_tx_io(struct io_job *io)
{
	struct dm_tx *dmtx = io->dmtx;
	BUG_ON(io->pi == NULL);
	proc_info_io_complete(io->pi);

	if (io->err) {
		unsigned long flags;
		spin_lock_irqsave(&io->pi->txr->lock, flags);
		io->pi->txr->fail_all_successors = 1;
		spin_unlock_irqrestore(&io->pi->txr->lock, flags);
	}

	if(is_io_job_read_modify_write(io)) {
		// At this point io->page is pointed by txio->page so
		// we don't free the page here.
		if (io->rw == READ) {
			memcpy_bio_into_page(io);
			goto bio_endio_and_return;
		} else {
			// Tx write is always full block write from
			// txio->page.
			BUG_ON(true);
		}
	}
	if (is_io_job_subblock_read(io)) {
		memcpy_page_into_bio(io);
		free_page((unsigned long)io->page);
		goto bio_endio_and_return;
	}

	if (io->rw == READ) {
		goto bio_endio_and_return;
	} else {
		// Writes never use bio as all writes for transactions are
		// deferred writes that are issued from endtx calls.
		BUG_ON(io->bio);
		goto mempool_free_and_return;
	}
	return;

bio_endio_and_return:
	bio_endio(io->bio, io->err);
mempool_free_and_return:
	mempool_free(io, io_job_mempool);
	do_complete_generic(dmtx);
}

static void match_and_finalize_io(u32 id)
{
	struct io_job *io = get_io_job_for_id(id);
	BUG_ON(io == NULL);

	if (is_io_job_tx(io)) {
		finalize_tx_io(io);
	} else {
		finalize_regular_io(io);
	}
}

static void finish_io(struct work_struct *unused_work_struct)
{
	unsigned long flags;

	spin_lock_irqsave(&finished_io_list_lock, flags);
	while (!list_empty(&finished_io_list)) {
		struct io_job *io =
			container_of(finished_io_list.next, struct io_job,
				     finished_job_list);
		list_del(&io->finished_job_list);
		spin_unlock_irqrestore(&finished_io_list_lock, flags);

		match_and_finalize_io(io->id);

		spin_lock_irqsave(&finished_io_list_lock, flags);
	}
	spin_unlock_irqrestore(&finished_io_list_lock, flags);
}

/* Allocate/claim the next contiguously available block for writing or
   gc.  Do not need to check if the circular ring is full, since
   ->available_blocks is consistently updated and it indicates how
   many slots are available */
static  u32 __claim_next_free_block(struct dm_gecko *dmg)
{
	struct dm_dev_info *curr_dev = dmg->curr_dev;
	struct dm_dev_info *next_dev = NULL;

	u32 head = dmg->head;

	BUG_ON(!__is_l_block_free(dmg, head));
	if ((++dmg->head) == dmg->size) {
		dmg->head = 0;
		++dmg->head_wrap_around;
	}

	++curr_dev->head;
	if (dmg->head % dmg->seg_size_blk == 0) {
		next_dev = get_next_dev(dmg, curr_dev);
		BUG_ON(next_dev == NULL);
		dmg->head = next_dev->head;
		dmg->curr_dev = next_dev;
	}
	--dmg->available_blocks;
	--dmg->free_blocks;

	return head;
}

/* ->lock must be held */
static int __relocate_written_block(struct io_job *io)
{
	struct dm_gecko *dmg = io->dmg;
	struct d_map_entry *entry;

	BUG_ON(dmg->r_map[io->l_block].virt_addr != io->v_block);

	// TODO: the version we get from put_new_d_map_entry does not
	// work correctly if transactional writes are used together.
	// Transactional writes use outstanding_ver not curr_ver.
	// Thus, make writes without begin end TX a singleton TX.
	// But this should be done in the isotope layer not here.
	if (io->version == TX_NO_VERSION) {
		entry = __insert_new_d_map_entry(dmg, io->v_block, io->l_block);
		if (entry == NULL) {
			goto err_out;
		}
		io->version = entry->version;
	} else {
		entry = __insert_new_d_map_entry_with_version(dmg, io->v_block,
							      io->l_block,
							      io->version);
		if (entry == NULL) {
			goto err_out;
		}
		if (io->version > dmg->curr_ver) {
			dmg->curr_ver = io->version;
		}
	}
	BUG_ON(!is_version_pending(dmg->r_map[io->l_block].version));
	dmg->r_map[io->l_block].version = io->version;

	if (test_bit(io->v_block, dmg->cached_v_block_map)) {
		IOCPRINTK("allocating new page for non-tx cached write");
		entry->page = (void*)__get_free_page(GFP_ATOMIC);
		if (!entry->page) {
			printk(DM_TX_PREFIX "Page Cache (addr %llu ver %u) Failed",
			       (unsigned long long)io->v_block, io->version);
			goto err_out;
		} else {
			if (io->page != NULL) {
				memcpy(entry->page, io->page, PAGE_SIZE);
			} else {
				memcpy_bio_into_reg_page(io, entry->page);
			}
		}
	}
	return 0;

err_out:
	return -ENOMEM;
}

static void gecko_io_complete_callback(unsigned long err, void *context)
{
	struct io_job *io = (struct io_job *)context;
	struct dm_gecko *dmg = io->dmg;
	struct dm_dev_info *dev = NULL;
	unsigned long flags;

	dev = dev_for_sector(dmg, block_to_sector(io->l_block));
	if (io->rw == READ) {
		atomic_dec(&dev->outstanding_reads);
	} else {
		atomic_dec(&dev->outstanding_writes);
	}

	if (err) {
		struct dm_gecko_stats *stats;
		get_cpu();
		stats = this_cpu_ptr(dmg->stats);
		io->err = err;
		if (io->rw == READ) {
			zero_fill_bio(io->bio);
			++stats->read_err;
		} else {
			++stats->write_err;
		}
		put_cpu();

		goto notify_and_out;
	}

	if (io->rw == READ) {
		// Fill in read missed blocks
		if (dmg->lru_cache_size_blk > 0) {
			lru_cache_write(dmg->lru_mem_cache, io->l_block,
					io->page, io->bio, 1);
		}
	} else {
		spin_lock_irqsave(&dmg->lock, flags);
		err = __relocate_written_block(io);
		spin_unlock_irqrestore(&dmg->lock, flags);
		if (err) {
			io->err = err;
			goto notify_and_out;
		}

		// Write data to cache
		if (dmg->lru_cache_size_blk > 0 &&
		    dmg->lru_mem_cache->policy == LRU_CACHE_POLICY_READWRITE) {
			lru_cache_write(dmg->lru_mem_cache, io->l_block,
					io->page, io->bio, 0);
		}

	}
notify_and_out:
	notify_finished_io(io);
}

void cache_copy_complete_callback(int read_err, unsigned long write_err,
				  void *context)
{
	BUG_ON(true);
}

/* WARNING: do NOT touch any of the shared state (e.g. the direct and
 * reverse relocation maps) from this function---accessing the members
 * of the io_job passed in is safe, e.g. io->v_block or
 * io->l_block. The context (parameter passed to the callback) is the
 * io_job. */
static int dm_dispatch_io_bio(struct io_job *io, io_notify_fn io_complete_fn)
{
	struct dm_gecko *dmg = io->dmg;
	struct dm_io_request iorq;
	struct dm_io_region where;
	struct dm_dev_info *dev;

	sector_t sector;
	int nr_regions = 1;
	int flags;

	/* The physical map requires no synchronization since it is
	 * initialized once and not altered henceforth. Further, the
	 * dm_io_region(s) can be allocated on-stack even though the
	 * dm_io is asynchronous since it is used to set the fields of
	 * a newly allocated bio (which is itself submitted for io
	 * through the submit_bio() interface). WARNING! do not touch
	 * the virtual and linear maps since reads and writes may be
	 * issued concurrently (that's the contract at the
	 * block-level---request ordering is not ensured. */

	sector = block_to_sector(io->l_block);
	dev = linear_to_phy(dmg, sector, &where);

	if (io->rw == READ) {
		atomic_inc(&dev->outstanding_reads);
	} else {
		atomic_inc(&dev->outstanding_writes);
	}

	flags = 0;
	iorq.bi_rw = (io->rw | flags);

	if (io->page != NULL) {
		// unaligned requests or tx writes.
		iorq.mem.type = DM_IO_KMEM;
		iorq.mem.ptr.addr = io->page;
		// only required for DM_IO_PAGE_LIST
		iorq.mem.offset = 0;
	} else {
		struct bio *bio = io->bio;
		iorq.mem.type = DM_IO_BVEC;
		iorq.mem.ptr.bvec = bio->bi_io_vec + bio->bi_idx;
	}
	iorq.notify.fn = io_complete_fn;
	iorq.notify.context = io;
	iorq.client = dmg->io_client;

	return dm_io(&iorq, nr_regions, &where, NULL);
}

static void submit_io_job_to_gecko_backend(struct dm_gecko *dmg,
					   struct io_job *io)
{
	struct dm_gecko_stats *stats;
	unsigned long flags;
	int rw = io->rw;
	u32 v_block = io->v_block;
	u32 version = io->version;

	spin_lock_irqsave(&dmg->lock, flags);
	stats = this_cpu_ptr(dmg->stats);

	// v_block should be within valid range
	if (is_block_free_or_invalid(v_block, dmg)) {
		spin_unlock_irqrestore(&dmg->lock, flags);
		io->err = -ENXIO;
		goto out_without_submitting_io;
	}

	if (version > MAX_VERSION) {
		io->l_block = __get_latest_l_block(dmg, v_block);
	} else {
		io->l_block = __get_old_l_block(dmg, v_block, version);
	}

	if (rw == READ) {
		++stats->reads;
		DPRINTK("read v %u l %u s %u", v_block, io->l_block,
			dmg->size);
		// Handle non-assigned reads
		if (is_block_marked_free(io->l_block, dmg)) {
			++stats->read_empty;
			spin_unlock_irqrestore(&dmg->lock, flags);
			if (is_io_job_read_modify_write(io) ||
			    is_io_job_subblock_read(io)) {
				clear_page(io->page);
			} else {
				zero_fill_bio(io->bio);
			}
			goto out_without_submitting_io;
		}

		// Check for pinned cache
		if (test_bit(v_block, dmg->cached_v_block_map)) {
			void *cached_page = __get_old_l_block_page(dmg, v_block,
								   version);
			if (cached_page != NULL) {
				spin_unlock_irqrestore(&dmg->lock, flags);
				memcpy_reg_page_into_bio(io, cached_page);
				goto out_without_submitting_io;
			}
		}

		// Check for lru cache
		if (dmg->lru_cache_size_blk > 0) {
			if(!lru_cache_read(dmg->lru_mem_cache, io->l_block,
					   io->page, io->bio)) {
				spin_unlock_irqrestore(&dmg->lock, flags);
				goto out_without_submitting_io;
			}
		}

		// TODO: check for SSD cache

	} else {
		// Different from reads, we persist the data and then copy the
		// data to the cache for writes so we do no cache operations
		// here.
		++stats->writes;
		DPRINTK("write v %u l %u s %u", v_block, io->l_block,
			dmg->size);
		if (__no_available_blocks(dmg)) {
			// TODO: Handle no available space:
			// e.g. by triggering gc
			BUG_ON(true);
		}
		io->l_block = __claim_next_free_block(dmg);
		dmg->r_map[io->l_block].virt_addr = v_block;
	}
	spin_unlock_irqrestore(&dmg->lock, flags);

	dm_dispatch_io_bio(io, gecko_io_complete_callback);
	return;

out_without_submitting_io:
	notify_finished_io(io);
	return;
}

static void prepare_to_send_to_backend(struct dm_isotope *dmi,
				       struct io_job *io)
{
	unsigned long flags;
	spin_lock_irqsave(&dmi->request_id_lock, flags);
	io->id = dmi->request_id++;
	spin_unlock_irqrestore(&dmi->request_id_lock, flags);
	put_io_job_for_id(io->id, io);
}

static void submit_io_job(struct io_job *io)
{
	// TODO: Handle gc vs read/write clash.

	prepare_to_send_to_backend(io->dmi, io);
	submit_io_job_to_gecko_backend(io->dmg, io);
}

static int prepare_tx_io(struct io_job *io)
{
	struct proc_info *pi = io->pi;
	struct tx_io * txio;
	struct dm_isotope_stats *stats;
	set_io_job_tx(io);
	io->version = pi->ver_opened;

	// Record transaction I/O to transaction record
	txio = mempool_alloc(tx_io_mempool, GFP_ATOMIC);
	txio->accessed_bits = NULL;
	txio->data_bits = NULL;
	txio->accessed_start = MAX_U16;
	txio->accessed_cnt = MAX_U16;
	txio->page = NULL;
	txio->rw = bio_data_dir(io->bio);
	txio->v_block = io->v_block;

	get_cpu();
	stats = this_cpu_ptr(io->dmi->stats);
	if (txio->rw == READ) {
		++stats->tx_reads;
	} else {
		++stats->tx_writes;
	}
	put_cpu();

	if (txio->rw == READ) {
		++pi->txr->nr_reads;
		if (is_io_job_subblock_read(io)) {
			// TODO: mark subblock access or leave it to the user?
		}
	} else {
		++pi->txr->nr_writes;
		if (is_io_job_read_modify_write(io)) {
			BUG_ON(io->page == NULL);
			txio->page = io->page;
			// TODO: mark subblock access or leave it to the user?
		} else {
			txio->page = (void *) __get_free_page(GFP_ATOMIC);
			if (txio->page == NULL) {
				mempool_free(txio, tx_io_mempool);
				return -ENOMEM;
			}
			memcpy_bio_into_reg_page(io, txio->page);
		}
	}
	list_add_tail(&txio->io_list, &pi->txr->io_list);

	// Read and read-modify-write become outstanding io
	if (io->rw == READ) {
		atomic_inc(&pi->nr_outstanding_io);
	}
	return 0;
}

static int prepare_subblock_io(struct io_job *io)
{
	struct dm_isotope *dmi = io->dmi;
	struct dm_isotope_stats *stats;
	struct bio *bio = io->bio;
	/* if not aligned at page boundary, must be less than
	 * a page worth of data */
	BUG_ON(bio->bi_size >= GECKO_BLOCK_SIZE);

	io->page = (void *)__get_free_page(GFP_ATOMIC);
	if (io->page == NULL) {
		return 1;
	}

	get_cpu();
	stats = this_cpu_ptr(dmi->stats);
	if (bio_data_dir(bio) == READ) {
		++stats->subblock_reads;
		set_io_job_subblock_read(io);
	} else {
		++stats->subblock_writes;
		set_io_job_read_modify_write(io);
	}
	put_cpu();

	io->rw = READ;  /* read-modify-update cycle, read first */
	DPRINTK("%s request unaligned, sector(%llu) : size(%llu)",
		(bio_data_dir(bio) == READ) ? "READ" : "WRITE",
		(unsigned long long)bio->bi_sector,
		(unsigned long long)bio->bi_size);
	return 0;

}

static int map_rw(struct dm_tx *dmtx, struct bio *bio)
{
	struct dm_isotope *dmi = dmtx->dmi;
	struct dm_gecko *dmg = dmtx->dmg;
	int err = 0;
	struct io_job *io = mempool_alloc(io_job_mempool, GFP_ATOMIC);

	if (io == NULL) {
		err = -ENOMEM;
		goto bio_endio_and_out;
	}

	io->type = 0;
	io->bio = bio;
	io->dmtx = dmtx;
	io->dmi = dmi;
	io->dmg = dmg;
	io->page = NULL;
	io->pi = NULL;
	io->version = TX_NO_VERSION;
	io->err = 0;

	atomic_inc(&dmi->nr_outstanding_io);

	if (!bio_at_block_boundary(bio)) { // Subblock I/O
		if ((err = prepare_subblock_io(io))) {
			goto abort_tx_and_out;
		}
	} else { // Regular full block I/O
		BUG_ON(bio->bi_size != GECKO_BLOCK_SIZE);
		io->rw = bio_data_dir(bio);
	}

	io->v_block = sector_to_block(bio->bi_sector);
	io->pi = get_proc_info(dmi, current->pid);

	if (is_transaction_ongoing(io->pi)) {
		if((err = prepare_tx_io(io))) {
			goto abort_tx_and_out;
		}
		// We do the read of the read-modify-write cycle first and
		// submit the write later on during endtx. At this point
		// prepare_subblock_io function made io->rw = READ for such
		// I/Os, so only full block writes exit here.
		if (io->rw == WRITE)
			goto finish_io_and_out;
	} else {
		if (io->rw == WRITE) {
		}
	}

	submit_io_job(io);
	return DM_MAPIO_SUBMITTED;

abort_tx_and_out:
	// TODO: abort transaction if the io belonged to a transaction.

finish_io_and_out:
	mempool_free(io, io_job_mempool);

bio_endio_and_out:
	bio_endio(bio, err);
	do_complete_generic(dmtx);

	return DM_MAPIO_SUBMITTED;
}

/* This is the case when flush request comes in.
 * Since device mapper has multiple devices it should
 * redirect the request to appropriate device that
 * holds the cached requests that need to be flushed */
static int map_flush(struct dm_gecko *dmg, struct bio *bio,
		     unsigned target_req_nr)
{
	struct dm_io_region where;
	struct dm_gecko_stats *stats;
	get_cpu();
	stats = this_cpu_ptr(dmg->stats);
	++stats->empty_barriers;
	put_cpu();

	// TODO: find the appropriate block device and send the flush
	// command accordingly. The code below is incorrect.
	linear_to_phy(dmg, block_to_sector(dmg->head) + target_req_nr,
		      &where);
	bio->bi_bdev = where.bdev;
	/* the empty barriers do not indicate which
	 * sectors:size are sync'ed */
	DPRINTK("bio_empty_barrier device(%u:%u) (%llu:%llu) (%u)",
		MAJOR(bio->bi_bdev->bd_dev),
		MINOR(bio->bi_bdev->bd_dev),
		(unsigned long long)
		sector_to_block(bio->bi_sector),
		(unsigned long long) to_sector(bio->bi_size),
		target_req_nr);

	return DM_MAPIO_REMAPPED;
}

/* TRIMs are advisory. We do not do anything. Simply trimming a
 * block can mess with ongoing read/write/gc and transactions. */
static int map_discard(struct dm_gecko *dmg, struct bio *bio)
{
	unsigned long flags;
	struct dm_gecko_stats *stats;
	u32 l_block;
	sector_t v_block = sector_to_block(bio->bi_sector);

	/* never discard block 0 which holds the superblock */
	BUG_ON(v_block == 0);
	spin_lock_irqsave(&dmg->lock, flags);
	/* preemption is disabled under spinlock */
	stats = this_cpu_ptr(dmg->stats);

	l_block = __get_latest_l_block(dmg, v_block);

	if (__is_d_list_map_free(dmg, v_block)) {
		WARN(1, DM_TX_PREFIX "trim on free block!\n");
	} else {
		BUG_ON(v_block != dmg->r_map[l_block].virt_addr);
		// TODO: for now we are doing nothing for discard. We should
		// consider ongoing I/Os and handle discard accordingly.
		++stats->discards;
	}
	spin_unlock_irqrestore(&dmg->lock, flags);

	bio_endio(bio, 0);
	return DM_MAPIO_SUBMITTED;
}
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 7, 0)
static int dm_tx_map(struct dm_target *ti, struct bio *bio,
		     union map_info *map_context)
#else
static int dm_tx_map(struct dm_target *ti, struct bio *bio)
#endif
{
	struct dm_tx *dmtx = (struct dm_tx *) ti->private;
	struct dm_gecko *dmg = dmtx->dmg;

	int ret = DM_MAPIO_REQUEUE;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 36)
	if (bio_empty_barrier(bio)) {
#else
	if (bio->bi_rw & REQ_FLUSH) {
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 35)
		unsigned target_req_nr = map_context->flush_request;
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(3, 7, 0)
		unsigned target_req_nr = map_context->target_request_nr;
#else
		unsigned target_req_nr = dm_bio_get_target_bio_nr(bio);
#endif

		ret = map_flush(dmg, bio, target_req_nr);
	} else if (bio->bi_rw & REQ_DISCARD) {
		ret = map_discard(dmg, bio);
	} else {
		ret = map_rw(dmtx, bio);
	}
	return ret;
}


/*****************************************************************************\
 * Initialization and destruction functions.
\*****************************************************************************/

static void dm_gecko_put_devices(struct dm_target *ti, struct dm_gecko *dmg)
{
	struct list_head *dm_dev_info_list = &dmg->dev_map.dm_dev_info_list;

	while (!list_empty(dm_dev_info_list)) {
		struct dm_dev_info *dev =
			list_entry(dm_dev_info_list->next, struct dm_dev_info,
				   list);
		list_del(&dev->list);
		if (dev->ddev) {
			dm_put_device(ti, dev->ddev);
		}
		kfree(dev);
	}
}

static struct dm_dev_info *dev_info_alloc_and_init(gfp_t flags)
{
	struct dm_dev_info *dev = kzalloc(sizeof(*dev), flags);
	if (!dev) {
		return NULL;
	}
	atomic_set(&dev->outstanding_writes, 0);
	atomic_set(&dev->outstanding_reads, 0);
	dev->ddev = NULL;
	return dev;
}

static int init_isotope(struct dm_target *ti, struct dm_isotope *dmi)
{
	int i;

	atomic_set(&dmi->nr_outstanding_io, 0);
	init_waitqueue_head(&dmi->io_finish_wait_queue);

	dmi->request_id = 0;
	dmi->curr_ver = 0;
	dmi->outstanding_ver = 0;
	dmi->oldest_ver = 0;

	INIT_LIST_HEAD(&dmi->tx_record_list);
	INIT_LIST_HEAD(&dmi->tx_proc_info_list);
	dmi->proc_info_list_map = kmalloc(sizeof(struct list_head) *
					  HASH_TABLE_SIZE,
					  GFP_KERNEL);
	if (!dmi->proc_info_list_map) {
		ti->error = DM_TX_PREFIX "kzalloc to proc_info_list_map "
			"failed";
		goto err_out;
	}
	for (i = 0; i < HASH_TABLE_SIZE; i++)
		INIT_LIST_HEAD(&dmi->proc_info_list_map[i]);
	dmi->nr_proc = 0;

	dmi->tmp_proc_info_list_map = kmalloc(sizeof(struct list_head) *
					      HASH_TABLE_SIZE,
					      GFP_KERNEL);
	if (!dmi->tmp_proc_info_list_map) {
		ti->error = DM_TX_PREFIX "kzalloc to tmp_proc_info_list_map "
			"failed";
		goto free_proc_info_list_map_and_out;
	}
	for (i = 0; i < HASH_TABLE_SIZE; i++)
		INIT_LIST_HEAD(&dmi->tmp_proc_info_list_map[i]);

	dmi->nr_tmp_proc = 0;

	spin_lock_init(&dmi->request_id_lock);
	spin_lock_init(&dmi->version_lock);
	spin_lock_init(&dmi->tx_record_list_lock);
	spin_lock_init(&dmi->tx_proc_info_list_lock);
	spin_lock_init(&dmi->proc_info_list_map_lock);
	spin_lock_init(&dmi->tmp_proc_info_list_map_lock);

	dmi->stats = alloc_percpu(struct dm_isotope_stats);
	if (!dmi->stats) {
		ti->error = DM_TX_PREFIX "alloc_percpu to stats failed";
		goto free_tmp_proc_info_list_map_and_out;
	}

	return 0;

free_tmp_proc_info_list_map_and_out:
	kfree(dmi->tmp_proc_info_list_map);
free_proc_info_list_map_and_out:
	kfree(dmi->proc_info_list_map);
err_out:
	return -ENOMEM;
}

static void destroy_isotope(struct dm_isotope *dmi)
{
	free_percpu(dmi->stats);
	kfree(dmi->tmp_proc_info_list_map);
	kfree(dmi->proc_info_list_map);
}

static int init_gecko(struct dm_target *ti, struct dm_gecko *dmg,
		      struct ctr_args *args)
{
	int err;
	int i;
	u32 tmp_u32;
	spin_lock_init(&dmg->lock);
	//spin_lock_init(&dmg->io_lock);
	init_waitqueue_head(&dmg->free_space_wait_queue);
	dmg->gc_req_in_progress = 0;
	dmg->max_gc_req_in_progress = GC_CONCURRENT_REQ;
	dmg->curr_ver = 0;
	dmg->oldest_ver = 0;

	dmg->gc_ctrl.low_watermark = GC_DEFAULT_LOW_WATERMARK;
	dmg->gc_ctrl.high_watermark = GC_DEFAULT_HIGH_WATERMARK;

	// TODO: move stats from gecko to dmtx
	if (!(dmg->stats = alloc_percpu(struct dm_gecko_stats))) {
		ti->error = DM_TX_PREFIX "unable to alloc_percpu stats";
		printk("%s\n", ti->error);
		err = -ENOMEM;
		goto err_out;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
	dmg->io_client = dm_io_client_create();
#else
	dmg->io_client = dm_io_client_create(DM_TX_GC_COPY_PAGES);
#endif
	if (IS_ERR(dmg->io_client)) {
		ti->error =
			DM_TX_PREFIX "unable to register as an io client";
		err = PTR_ERR(dmg->io_client);
		printk("%s, errno=%d\n", ti->error, err);
		goto free_dmg_stats_and_out;
	}

	dmg->seg_size_blk = args->seg_size_mb << GECKO_MB_TO_BLOCK_SHIFT;
	printk(DM_TX_PREFIX "using seg size %u MB, %u blks\n",
	       args->seg_size_mb, dmg->seg_size_blk);

	dmg->dev_map.cnt = args->nr_blkdevs;
	printk(DM_TX_PREFIX "# of devices: %d\n", dmg->dev_map.cnt);

	/* loading drives */
	INIT_LIST_HEAD(&dmg->dev_map.dm_dev_info_list);
	dmg->dev_map.len = 0;
	for (i = 0; i < dmg->dev_map.cnt; i++) {  /* for i-th devs in chain */
		struct dm_dev_info *dev = dev_info_alloc_and_init(GFP_KERNEL);
		if (!dev) {
			ti->error = DM_TX_PREFIX "kmalloc dm_dev_info";
			printk("%s\n", ti->error);
			err = -ENOMEM;
			goto put_devices_and_out;
		}
		dev->idx = i;
		list_add_tail(&dev->list, &dmg->dev_map.dm_dev_info_list);

		err = dm_get_device(ti, args->blkdev_paths[i],
				    dm_table_get_mode(ti->table), &dev->ddev);
		if (err) {
			ti->error = DM_TX_PREFIX "device lookup failed";
			printk("%s\n", ti->error);
			goto put_devices_and_out;
		}
		printk(DM_TX_PREFIX "added %d th dev: %s\n", i,
		       args->blkdev_paths[i]);

		dev->start = dmg->dev_map.len;
		dev->tail = sector_to_block(dev->start);
		dev->head = sector_to_block(dev->start);
		dev->len = dev->ddev->bdev->bd_inode->i_size >> SECTOR_SHIFT;
		printk(DM_TX_PREFIX "dev %d start=%ld, len=%ld, head=%ld, tail=%ld\n",
		       dev->idx, dev->start, dev->len, dev->head, dev->tail);
		dmg->dev_map.len += dev->len;
	}

	if (dmg->dev_map.len != ti->len) {
		ti->error =
			DM_TX_PREFIX "dev_map length != dm_target length";
		printk("%s\n", ti->error);
		err = -EINVAL;
		goto put_devices_and_out;
	}

	if (sector_to_block(dmg->dev_map.len) > 0xffffffff-1) {
		ti->error = DM_TX_PREFIX "unsupported size (too large)";
		printk("%s \n", ti->error);
		err = -EINVAL;
		goto put_devices_and_out;
	}
	dmg->size = sector_to_block(dmg->dev_map.len);

	/* (dmg->size-1) for circular buffer logic: one slot wasted to
	 * distinguish between full and empty circular buffer. */
	dmg->available_blocks = dmg->free_blocks = dmg->size-1;

	dmg->lru_cache_size_blk = args->mem_cache_size_mb
		<< GECKO_MB_TO_BLOCK_SHIFT;
	printk(DM_TX_PREFIX "using lru_cache size %u MB, %u blks\n",
	       args->mem_cache_size_mb, dmg->lru_cache_size_blk);

	if (strcmp(args->mem_cache_policy, "none") == 0) {
		tmp_u32 = 0xFFFFFFFF;
	} else if (strcmp(args->mem_cache_policy, "lru_rd") == 0) {
		tmp_u32 = LRU_CACHE_POLICY_READONLY;
	} else if (strcmp(args->mem_cache_policy, "lru_rdwr") == 0) {
		tmp_u32 = LRU_CACHE_POLICY_READWRITE;
	} else {
		ti->error = DM_TX_PREFIX "invalid lru cache policy";
		printk("%s\n", ti->error);
		err = -EINVAL;
		goto put_devices_and_out;
	}
	printk(DM_TX_PREFIX "using lru_cache policy %s (%u)\n",
	       args->mem_cache_policy, tmp_u32);

	// TODO: make use of cache policy rather than the size
	if (dmg->lru_cache_size_blk > 0) {
		if(lru_cache_init(&dmg->lru_mem_cache, dmg->lru_cache_size_blk,
				  tmp_u32)) {
			ti->error = DM_TX_PREFIX "lru cache init failed";
			printk("%s\n", ti->error);
			err = -ENOMEM;
			goto put_devices_and_out;
		}
	}

	dmg->d_list_map = vmalloc(PAGE_ALIGN(sizeof(struct list_head)
					     * dmg->size));
	if (!dmg->d_list_map) {
		ti->error = DM_TX_PREFIX "vmalloc ->d_list_map failed";
		printk("%s\n", ti->error);
		err = -ENOMEM;
		goto destroy_lru_cache_and_out;
	}

	dmg->r_map = vmalloc(PAGE_ALIGN(sizeof(*dmg->r_map) * dmg->size));
	if (!dmg->r_map) {
		ti->error = DM_TX_PREFIX "vmalloc ->r_map failed";
		printk("%s\n", ti->error);
		err = -ENOMEM;
		goto destroy_d_list_map_and_out;
	}

	tmp_u32= dmg->size / (sizeof(unsigned long) * 8);
	dmg->cached_v_block_map
		= (unsigned long *) vmalloc(PAGE_ALIGN(sizeof(unsigned long)
						       * tmp_u32));
	if (!dmg->cached_v_block_map) {
		ti->error = DM_TX_PREFIX "vmalloc ->cached_v_block_map failed";
		printk("%s\n", ti->error);
		err = -ENOMEM;
		goto destroy_r_map_and_out;
	}

	for (i = 0; i < dmg->size; ++i) {
		INIT_LIST_HEAD(&dmg->d_list_map[i]);
		mark_r_map_entry_free(dmg, i);
		clear_bit(i, dmg->cached_v_block_map);
	}

	dmg->tail = dmg->head = 0;
	dmg->curr_dev = dev_for_sector(dmg, block_to_sector(dmg->head));

	//hrtimer_init(&dmg->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	//dmg->timer.function = fire_gc_timer;
	//INIT_WORK(&dmg->gc_work, try_sched_gc);
	//atomic_set(&dmg->gc_work_scheduled_by_timer, 0);
	//atomic_set(&dmg->timer_active, 1);

	return 0;

destroy_r_map_and_out:
	vfree(dmg->r_map);
destroy_d_list_map_and_out:
	vfree(dmg->d_list_map);
destroy_lru_cache_and_out:
	lru_cache_destroy(&dmg->lru_mem_cache);
put_devices_and_out:
	dm_gecko_put_devices(ti, dmg);
	dm_io_client_destroy(dmg->io_client);
free_dmg_stats_and_out:
	free_percpu(dmg->stats);
err_out:
	return err;
}

static void destroy_gecko(struct dm_target *ti, struct dm_gecko *dmg)
{
	int i;
	struct d_map_entry *entry, *tmp;
	vfree((void*)dmg->cached_v_block_map);
	vfree(dmg->r_map);
	for (i = 0; i < dmg->size; i++) {
		list_for_each_entry_safe(entry, tmp, &dmg->d_list_map[i],
					 list) {
			list_del(&entry->list);
		}
	}
	vfree(dmg->d_list_map);
	lru_cache_destroy(&dmg->lru_mem_cache);
	dm_gecko_put_devices(ti, dmg);
	dm_io_client_destroy(dmg->io_client);
	free_percpu(dmg->stats);
}

static int read_positive_long(char *str, int *return_value,
			      struct dm_target *ti, char *err_msg)
{
	char *end;
	(*return_value) = simple_strtol(str, &end, 10);
	if ((*end) || (*return_value) < 0) {
		ti->error = err_msg;
		return -EINVAL;
	}
	return 0;
}

static int read_power_of_two_long(char *str, u32 *return_value,
				  struct dm_target *ti, char *err_msg)
{
	int err;
	if ((err = read_positive_long(str, return_value, ti, err_msg))) {
		return err;
	}
	if (!POW_OF_2((*return_value))) {
		ti->error = err_msg;
		return -EINVAL;
	}
	return 0;
}

static int read_ctr_args(struct dm_target *ti, struct ctr_args *args,
			 unsigned int argc, char *argv[])
{
	int i;
	int err;
	int idx = 0;
	if (argc < 5) {
		ti->error = "not enough args:\n" DMTX_CREATE_CMD "\n";
		err = -EINVAL;
		goto err_out;
	}

	// persistent data map related
	if ((err = read_positive_long(argv[idx++], &args->persistent,
				      ti, "invalid persistence arg\n"))) {
		goto err_out;
	}
	printk(DM_TX_PREFIX "args->persistent %d\n", args->persistent);
	args->meta_filename = argv[idx++];
	printk(DM_TX_PREFIX "args->meta_filename %s\n", args->meta_filename);

	// blkdev related 
	args->blkdev_layout = argv[idx++];
	printk(DM_TX_PREFIX "args->blkdev_layout %s\n", args->blkdev_layout);
	if ((err = read_positive_long(argv[idx++], &args->nr_blkdevs,
				      ti, "invalid nr_blkdevs arg\n"))) {
		goto err_out;
	} else if (args->nr_blkdevs > DM_TX_MAX_STRIPES) {
		ti->error = "invalid nr_blkdevs arg (should be < 32)\n";
		err = -EINVAL;
		goto err_out;
	}
	printk(DM_TX_PREFIX "args->nr_blkdevs %d\n", args->nr_blkdevs);

	if (args->nr_blkdevs + 5 > argc - idx) {
		ti->error = "not enough args:\n" DMTX_CREATE_CMD "\n";
		err = -EINVAL;
		goto err_out;
	}

	for (i = 0; i < args->nr_blkdevs; ++i) {
		args->blkdev_paths[i] = argv[idx++];
		printk(DM_TX_PREFIX "args->blkdev_paths %s\n",
		       args->blkdev_paths[i]);
	}

	// gecko related
	if ((err = read_power_of_two_long(argv[idx++], &args->seg_size_mb,
					  ti, "invalid seg_size_mb arg\n"))) {
		goto err_out;
	}
	printk(DM_TX_PREFIX "args->seg_size_mb %d\n", args->seg_size_mb);

	// ssd cache related
	args->ssd_cache_policy = argv[idx++];
	printk(DM_TX_PREFIX "args->ssd_cache_policy %s\n",
	       args->ssd_cache_policy);
	args->ssd_cache_path = argv[idx++];
	printk(DM_TX_PREFIX "args->ssd_cache_path %s\n",
	       args->ssd_cache_path);
	if ((err = read_power_of_two_long(argv[idx++],
					  &args->ssd_cache_size_mb, ti,
					  "invalid ssd_cache_size_mb arg\n"))) {
		goto err_out;
	}
	printk(DM_TX_PREFIX "args->ssd_cache_size_mb %d\n",
	       args->ssd_cache_size_mb);

	// memory cache related
	args->mem_cache_policy = argv[idx++];
	printk(DM_TX_PREFIX "args->mem_cache_policy %s\n",
	       args->mem_cache_policy);
	if ((err = read_power_of_two_long(argv[idx++],
					  &args->mem_cache_size_mb, ti,
					  "invalid mem_cache_size_mb arg\n"))) {
		goto err_out;
	}
	printk(DM_TX_PREFIX "args->mem_cache_size_mb %d\n",
	       args->mem_cache_size_mb);

	return 0;

err_out:
	return err;
}

int init_dm_tx(struct dm_target *ti, struct dm_tx *dmtx,
	       struct ctr_args *args) {
	int err = 0;
	dmtx->flags = 0;
	dmtx->persistent = args->persistent;
	dmtx->meta_filename = kstrdup(args->meta_filename, GFP_KERNEL);
	if (!dmtx->meta_filename) {
		ti->error = DM_TX_PREFIX "unable to kstrdup meta-filename";
		printk("%s\n", ti->error);
		err = -ENOMEM;
		goto err_out;
	}
	printk(DM_TX_PREFIX "meta_filename %s\n", dmtx->meta_filename);

	if (strcmp(args->blkdev_layout, "gecko") == 0) {
		dmtx->blkdev_layout = BLKDEV_LAYOUT_GECKO;
	} else if (strcmp(args->mem_cache_policy, "linear") == 0) {
		dmtx->blkdev_layout = BLKDEV_LAYOUT_LINEAR;
	} else {
		ti->error = DM_TX_PREFIX "alloc_percpu to stats failed";
		err = -EINVAL;
		goto free_meta_filename_and_out;
	}

	dmtx->stats = alloc_percpu(struct dm_tx_stats);
	if (!dmtx->stats) {
		ti->error = DM_TX_PREFIX "alloc_percpu to stats failed";
		err = -ENOMEM;
		goto free_meta_filename_and_out;
	}
	return 0;

free_meta_filename_and_out:
	kfree(dmtx->meta_filename);
err_out:
	return err;
}

void destroy_dm_tx(struct dm_tx *dmtx) {
	free_percpu(dmtx->stats);
	if (dmtx->meta_filename != NULL) {
		kfree(dmtx->meta_filename);
	}
}

static int dm_tx_ctr(struct dm_target *ti, unsigned int argc, char *argv[])
{
	int err;
	int i;
	struct ctr_args args;

	struct dm_tx *dmtx;
	struct dm_isotope *dmi;
	struct dm_gecko *dmg;

	if ((err = read_ctr_args(ti, &args, argc, argv))) {
		goto err_out;
	}

	if(!(dmtx = kzalloc(sizeof(*dmtx), GFP_KERNEL))) {
		ti->error = DM_TX_PREFIX "unable to allocate dmtx context";
		err = -ENOMEM;
		goto err_out;
	}
	if ((err = init_dm_tx(ti, dmtx, &args))) {
		goto free_dmtx_and_out;
	}

	if (!(dmi = kzalloc(sizeof(*dmi), GFP_KERNEL))) {
		ti->error = DM_TX_PREFIX
			"unable to allocate isotope context";
		err = -ENOMEM;
		goto destroy_dmtx_and_out;
	}
	if((err = init_isotope(ti, dmi))) {
		goto free_isotope_and_out;
	}

	if(!(dmg = kzalloc(sizeof(*dmg), GFP_KERNEL))) {
		ti->error = DM_TX_PREFIX "unable to allocate gecko context";
		err = -ENOMEM;
		goto destroy_isotope_and_out;
	}
	if ((err = init_gecko(ti, dmg, &args))) {
		goto free_dmg_and_out;
	}

	dmtx->dmi = dmi;
	dmtx->dmg = dmg;

	/* alloc the htable of IO requests in-progress */
	outstanding_io_job_list_map =
		kmalloc(sizeof(struct list_head) * HASH_TABLE_SIZE, GFP_KERNEL);
	if (!outstanding_io_job_list_map) {
		ti->error = DM_TX_PREFIX "kmalloc pending htable failed";
		printk("%s\n", ti->error);
		err = -ENOMEM;
		goto destroy_gecko_and_out;
	}
	for (i = 0; i < HASH_TABLE_SIZE; i++)
		INIT_LIST_HEAD(&outstanding_io_job_list_map[i]);


#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 5, 0)
	ti->split_io = GECKO_SECTORS_PER_BLOCK;  /* size in # of sectors */
#else
	ti->max_io_len = GECKO_SECTOR_PER_BLOCK;
#endif
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 8, 0)
	ti->num_flush_requests = dmg->dev_map.cnt;
	ti->num_discard_requests = dmg->dev_map.cnt;
#else
	ti->num_flush_bios = dmg->dev_map.cnt;
	ti->num_discard_bios = dmg->dev_map.cnt;
#endif
	ti->private = dmtx;

	printk(DM_TX_PREFIX "dm_tx_ctr done.\n");

	return 0;

destroy_gecko_and_out:
	destroy_gecko(ti, dmg);
free_dmg_and_out:
	kfree(dmg);
destroy_isotope_and_out:
	destroy_isotope(dmi);
free_isotope_and_out:
	kfree(dmi);
destroy_dmtx_and_out:
	destroy_dm_tx(dmtx);
free_dmtx_and_out:
	kfree(dmtx);
err_out:
	return err;
}

static long (*sys_rename_wrapper)(const char __user *oldname,
				  const char __user *newname) = NULL;

static void try_to_clean_up_txr(struct dm_isotope *dmi);
static void dm_tx_dtr(struct dm_target *ti)
{
	// At this point, `dmsetup message' cannot be issued against
	// the module any longer, therefore only the extant
	// metadata-sync and gc may be running (besides regular IOs
	// that have not yet completed).
	struct dm_tx *dmtx = (struct dm_tx *) ti->private;
	struct dm_isotope *dmi = dmtx->dmi;
	struct dm_gecko *dmg = dmtx->dmg;

	// Never clear this bit, the module is about to be unloaded.
	set_bit(DM_TX_FINAL_SYNC_METADATA, &dmtx->flags);
	set_bit(DM_TX_GC_FORCE_STOP, &dmtx->flags);

	wait_event(dmi->io_finish_wait_queue,
		   atomic_read(&dmi->nr_outstanding_io) == 0);

	try_to_clean_up_txr(dmi);

	kfree(outstanding_io_job_list_map);

	destroy_gecko(ti, dmg);
	kfree(dmg);

	destroy_isotope(dmi);
	kfree(dmi);

	destroy_dm_tx(dmtx);
	kfree(dmtx);

	printk(DM_TX_PREFIX "dm_tx_dtr done.\n");
}


/*****************************************************************************\
 * Status and message handling functions.
\*****************************************************************************/

#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 5, 0)
static int dm_tx_status(struct dm_target *ti, status_type_t type,
			char *result, unsigned int maxlen)
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(3, 8, 0)
static int dm_tx_status(struct dm_target *ti, status_type_t type,
			unsigned status_flags, char *result,
			unsigned int maxlen)
#else
static void dm_tx_status(struct dm_target *ti, status_type_t type,
			 unsigned status_flags, char *result,
			 unsigned int maxlen)
#endif
{
	struct dm_tx *dmtx = (struct dm_tx *) ti->private;
	struct dm_isotope *dmi = dmtx->dmi;
	struct dm_gecko *dmg = dmtx->dmg;
	int cpu, sz = 0;        /* sz is used by DMEMIT */
	struct dm_gecko_stats agg_gecko_stats, *g_cursor;
	struct dm_isotope_stats agg_isotope_stats, *i_cursor;

	memset(&agg_gecko_stats, 0, sizeof(agg_gecko_stats));
	memset(&agg_isotope_stats, 0, sizeof(agg_isotope_stats));

	for_each_possible_cpu(cpu) {
		g_cursor = per_cpu_ptr(dmg->stats, cpu);

		agg_gecko_stats.reads += g_cursor->reads;
		agg_gecko_stats.writes += g_cursor->writes;
		agg_gecko_stats.gc += g_cursor->gc;
		agg_gecko_stats.discards += g_cursor->discards;
		agg_gecko_stats.empty_barriers += g_cursor->empty_barriers;
		agg_gecko_stats.gc_recycle += g_cursor->gc_recycle;
		agg_gecko_stats.rw_clash += g_cursor->rw_clash;
		agg_gecko_stats.rw_gc_clash += g_cursor->rw_gc_clash;
		agg_gecko_stats.gc_clash += g_cursor->gc_clash;
		agg_gecko_stats.gc_rw_clash += g_cursor->gc_rw_clash;
		agg_gecko_stats.ww_clash += g_cursor->ww_clash;
		agg_gecko_stats.read_empty += g_cursor->read_empty;
		agg_gecko_stats.read_err += g_cursor->read_err;
		agg_gecko_stats.write_err += g_cursor->write_err;
	}

	for_each_possible_cpu(cpu) {
		i_cursor = per_cpu_ptr(dmi->stats, cpu);

		agg_isotope_stats.tx_reads += i_cursor->tx_reads;
		agg_isotope_stats.subblock_reads += i_cursor->subblock_reads;
		agg_isotope_stats.tx_writes += i_cursor->tx_writes;
		agg_isotope_stats.subblock_writes += i_cursor->subblock_writes;
		agg_isotope_stats.readwrite_tx += i_cursor->readwrite_tx;
		agg_isotope_stats.writeonly_tx += i_cursor->writeonly_tx;
		agg_isotope_stats.readonly_tx += i_cursor->readonly_tx;
		agg_isotope_stats.tx_success += i_cursor->tx_success;
		agg_isotope_stats.tx_failure += i_cursor->tx_failure;
		agg_isotope_stats.tx_abort += i_cursor->tx_abort;
	}

	switch (type) {
	case STATUSTYPE_INFO:
		DMEMIT("\n- Gecko\n "
		       "reads(%llu), writes(%llu), gc(%llu), discards(%llu), "
		       "empty_barriers(%llu), gc_recycle(%llu), "
		       "rw_clash(%llu), rw_gc_clash(%llu), gc_clash(%llu), "
		       "gc_rw_clash(%llu), ww_clash(%llu), read_empty (%llu), "
		       "read_err(%llu), write_err(%llu)\n",
		       agg_gecko_stats.reads,
		       agg_gecko_stats.writes,
		       agg_gecko_stats.gc,
		       agg_gecko_stats.discards,
		       agg_gecko_stats.empty_barriers,
		       agg_gecko_stats.gc_recycle,
		       agg_gecko_stats.rw_clash,
		       agg_gecko_stats.rw_gc_clash,
		       agg_gecko_stats.gc_clash,
		       agg_gecko_stats.gc_rw_clash,
		       agg_gecko_stats.ww_clash,
		       agg_gecko_stats.read_empty,
		       agg_gecko_stats.read_err,
		       agg_gecko_stats.write_err);
		DMEMIT("- Isotope\n "
		       "tx_reads(%llu), subblock_reads(%llu), "
		       "tx_writes(%llu), subblock_writes(%llu), "
		       "readwrite_tx(%llu), writeonly_tx(%llu), "
		       "readonly_tx(%llu), "
		       "tx_success(%llu), tx_failure(%llu), tx_abort(%llu), "
		       "outstanding_ios(%d)",
		       agg_isotope_stats.tx_reads,
		       agg_isotope_stats.subblock_reads,
		       agg_isotope_stats.tx_writes,
		       agg_isotope_stats.subblock_writes,
		       agg_isotope_stats.readwrite_tx,
		       agg_isotope_stats.writeonly_tx,
		       agg_isotope_stats.readonly_tx,
		       agg_isotope_stats.tx_success,
		       agg_isotope_stats.tx_failure,
		       agg_isotope_stats.tx_abort,
		       atomic_read(&dmi->nr_outstanding_io));
		break;
	case STATUSTYPE_TABLE:
		DMEMIT("\n"
		       "mode(%s | %s | %s) size(%lu), "
		       "available_blocks(%lu), "
		       "free_blocks(%lu), used_blocks(%lu), "
		       "unavailable_blocks(%lu), "
		       "relocatable_blocks(%lu), gc_req_in_progress(%lu), "
		       "tail_wrap_around(%lu), head_wrap_around(%lu), "
		       "curr_ver(%u), oldest_ver(%u)",
		       test_bit(DM_TX_GC_FORCE_STOP,
				&dmtx->flags) ? "gc-off"
		       : (test_bit(DM_TX_GC_STARTED, &dmtx->flags) ?
			  "gc-on" : "gc-idle"),
		       test_bit(DM_TX_INDEPENDENT_GC,
				&dmtx->flags) ? "gc-compact-in-body" :
				"gc-move-to-tail",
		       test_bit(DM_TX_SYNCING_METADATA,
				&dmtx->flags) ? "sync-metadata-on" :
				"sync-metadata-off",
		       (long unsigned)dmg->size,
		       (long unsigned)dmg->available_blocks,
		       (long unsigned)dmg->free_blocks,
		       (long unsigned)__used_blocks(dmg),
		       (long unsigned)__unavailable_blocks(dmg),
		       (long unsigned)__relocatable_blocks(dmg),
		       (long unsigned)dmg->gc_req_in_progress,
		       dmg->tail_wrap_around,
		       dmg->head_wrap_around,
		       dmg->curr_ver, dmg->oldest_ver);
		break;
	}
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 8, 0)
	return 0;
#endif
}

static int dm_tx_message(struct dm_target *ti, unsigned argc, char **argv)
{
	struct dm_tx *dmtx = (struct dm_tx *) ti->private;
	struct dm_gecko *dmg = dmtx->dmg;
	if (argc < 1 || argc > 3) {
		ti->error = DM_TX_PREFIX "invalid number of arguments";
		goto bad;
	}
	if (strcmp(argv[0], "gc-off") == 0) {
		set_bit(DM_TX_GC_FORCE_STOP, &dmtx->flags);
	} else if (strcmp(argv[0], "gc-on") == 0) {
		clear_bit(DM_TX_GC_FORCE_STOP, &dmtx->flags);
	} else if (strcmp(argv[0], "set-gc-max-concurrent-requests") == 0) {
		int max_gc_concurrent_req;
		if (argc < 2) {
			ti->error =
				DM_TX_PREFIX "too few args (need one integer)";
			goto bad;
		}
		max_gc_concurrent_req = simple_strtol(argv[1], NULL, 10);
		if (max_gc_concurrent_req < MIN_GC_CONCURRENT_REQ ||
		    max_gc_concurrent_req > MAX_GC_CONCURRENT_REQ) {
			ti->error =
				DM_TX_PREFIX "invalid argument (not in range)";
			goto bad;
		}
		dmg->max_gc_req_in_progress = max_gc_concurrent_req;
	} else if (strcmp(argv[0], "set-gc-watermarks") == 0) {
		unsigned long low_gc_watermark, high_gc_watermark;
		if (argc < 3) {
			ti->error =
				DM_TX_PREFIX "too few args (need 2 watermarks)";
			goto bad;
		}
		low_gc_watermark = simple_strtoul(argv[1], NULL, 10);
		high_gc_watermark = simple_strtoul(argv[2], NULL, 10);
		if (low_gc_watermark >= high_gc_watermark) {
			ti->error =
				DM_TX_PREFIX "low watermark >= high watermark";
			goto bad;
		}
		dmg->gc_ctrl.low_watermark = low_gc_watermark;
		dmg->gc_ctrl.high_watermark = high_gc_watermark;
	} else {
		ti->error = DM_TX_PREFIX "invalid dmsetup message";
		goto bad;
	}

	return 0;
bad:
	printk("%s\n", ti->error);
	return -EINVAL;
}


/*****************************************************************************\
 * ioctl functions: Isotope and Yogurt functions are here.
\*****************************************************************************/

static int ioctl_check(unsigned int cmd, unsigned long arg)
{
	if (_IOC_TYPE(cmd) != DM_TX_IOCTL_TYPE) {
		IOCPRINTK("(%d), type [0x%X] nr [0x%X]: BAD TYPE!",
			  current->pid, _IOC_TYPE(cmd), _IOC_NR(cmd));
		return -EBADF;
	}
	if (_IOC_DIR(cmd) & _IOC_READ) {
		if(!access_ok(VERIFY_WRITE, (void __user *) arg,
			      _IOC_SIZE(cmd))) {
			return -EFAULT;
		}
	}
	if (_IOC_DIR(cmd) & _IOC_WRITE) {
		if(!access_ok(VERIFY_READ, (void __user *) arg,
			      _IOC_SIZE(cmd))) {
			return -EFAULT;
		}
	}
	return 0;
}

static int ioctl_begintx(struct dm_tx *dmtx)
{
	struct dm_isotope *dmi = dmtx->dmi;
	struct proc_info *pi;
	unsigned long flags;

	pi = get_proc_info(dmi, current->pid);

	if (!pi) {
		pi = mempool_alloc(proc_info_mempool, GFP_ATOMIC);
		init_proc_info(pi, current->pid);
		put_proc_info(dmi, pi);
	} else {
		if(is_transaction_ongoing(pi)) {
			pi->txr->nest_count++;
			IOCPRINTK("(%d) FTX: nested tx cnt %d", current->pid,
				  pi->txr->nest_count);
			return 0;
		}
	}

	set_bit(PROC_INFO_TRANSACTION, &pi->flags);
	pi->txr = mempool_alloc(tx_record_mempool, GFP_ATOMIC);

	spin_lock_irqsave(&dmi->version_lock, flags);
	pi->ver_opened = dmi->curr_ver;
	spin_unlock_irqrestore(&dmi->version_lock, flags);

	init_tx_record(pi->txr, pi->ver_opened);

	spin_lock_irqsave(&dmi->tx_proc_info_list_lock, flags);
	list_add_tail(&pi->tt_list, &dmi->tx_proc_info_list);
	spin_unlock_irqrestore(&dmi->tx_proc_info_list_lock, flags);

	IOCPRINTK("(%d) FTX: begin start_ver %d", current->pid,
		  pi->txr->start_ver);
	return 0;
}

static pid_t ioctl_releasetx(struct dm_tx *dmtx)
{
	struct dm_isotope *dmi = dmtx->dmi;
	struct proc_info *pi;
	struct list_head *proc_info_list;
	unsigned long flags;

	pi = get_proc_info(dmi, current->pid);

	if (!pi) {
		/* there is no transaction ongoing and
		 * this process called release tx */
		goto err_out;
	} else {
		pid_t tmp_pid = pi->pid + PID_MAX_LIMIT;
		int safe = 0;

		remove_proc_info(dmi, pi);

		spin_lock_irqsave(&dmi->tmp_proc_info_list_map_lock, flags);
		while (!safe) {
			unsigned long idx = hash_long(tmp_pid, HASH_TABLE_BITS);
			struct proc_info *tmp_pi;
			proc_info_list = &dmi->tmp_proc_info_list_map[idx];

			// TODO: this is a bad collision avoidance mechanism
			// FIX THIS LATER !!
			safe = 1;

			list_for_each_entry(tmp_pi, proc_info_list, pi_list) {
				if (tmp_pi->pid == tmp_pid) {
					safe = 0;
					tmp_pid++;
					break;
				}
			}
			if (tmp_pid < PID_MAX_LIMIT) {
				goto unlock_and_out;
			}
		}
		pi->pid = tmp_pid;

		list_add_tail(&pi->pi_list, proc_info_list);
		++dmi->nr_tmp_proc;
		spin_unlock_irqrestore(&dmi->tmp_proc_info_list_map_lock,
				       flags);

		return pi->pid;
	}

unlock_and_out:
	spin_unlock_irqrestore(&dmi->tmp_proc_info_list_map_lock, flags);
	put_proc_info(dmi, pi);
err_out:
	return pi->pid;
}

static int ioctl_takeovertx(struct dm_tx *dmtx, pid_t tx_handle)
{
	struct dm_isotope *dmi = dmtx->dmi;
	struct proc_info *pi;
	unsigned long idx;
	struct list_head *proc_info_list;
	int found = 0;
	unsigned long flags;

	if((pi = get_proc_info(dmi, current->pid))) {
		goto err_out;
	}

	idx = hash_long(tx_handle, HASH_TABLE_BITS);
	proc_info_list = &dmi->tmp_proc_info_list_map[idx];

	spin_lock_irqsave(&dmi->tmp_proc_info_list_map_lock, flags);
	list_for_each_entry(pi, proc_info_list, pi_list) {
		if (pi->pid == tx_handle) {
			found = 1;
			break;
		}
	}
	if (!found) {
		spin_unlock_irqrestore(&dmi->tmp_proc_info_list_map_lock,
				       flags);
		goto err_out;
	}
	list_del(&pi->pi_list);
	--dmi->nr_tmp_proc;
	spin_unlock_irqrestore(&dmi->tmp_proc_info_list_map_lock, flags);

	pi->pid = current->pid;
	put_proc_info(dmi, pi);

	return 0;

err_out:
	return 1;
}

// dmi->tx_record_list_lock should be held
static int has_write_conflict(struct tx_io *txio, struct tx_record *txr)
{
	int conflict = 0;
	struct tx_io *tmp_txio;

	list_for_each_entry(tmp_txio, &txr->io_list, io_list) {
		if ((tmp_txio->v_block == txio->v_block) &&
		    (tmp_txio->rw == WRITE)) {
			if (txio->accessed_bits == NULL ||
			    tmp_txio->accessed_bits == NULL) {
				IOCPRINTK("(%d) FTX (ext): "
					  "block conflict %d vs %d",
					  current->pid, txio->v_block,
					  tmp_txio->v_block);
				conflict = 1;
				break;
			} else {
				u16 tmp_start = tmp_txio->accessed_start;
				u16 tmp_end = tmp_txio->accessed_start
					+ tmp_txio->accessed_cnt - 1;
				u16 start = txio->accessed_start;
				u16 end = txio->accessed_start
					+ txio->accessed_cnt - 1;

				BUG_ON(tmp_txio->accessed_start == MAX_U16 ||
				       tmp_txio->accessed_cnt == MAX_U16 ||
				       txio->accessed_start == MAX_U16 ||
				       txio->accessed_cnt == MAX_U16);

				if ((tmp_start >= start && tmp_start <= end) ||
				    (tmp_end >= start && tmp_end <= end) ||
				    (tmp_start < start && tmp_end > end)) {
					conflict = 1;
					break;
				}
				DPRINTK("(%d) txrcurver %d txrendver %d "
					"v_block %d tmp_start %d start %d tmp_end %d "
					"end %d: sbits %d, tmp sbits %d",
					conflict,
					txr->start_ver,
					txr->end_ver,
					txio->v_block,
					tmp_start,
					start,
					tmp_end,
					end,
					txio->data_bits,
					tmp_txio->data_bits);
			}
		}
	}

	IOCPRINTK("(%d) FTX (ext): conflict %d", current->pid, conflict);
	return conflict;
}

// dmi->tx_record_list_lock should be held
static int check_conflict(struct dm_isotope *dmi, struct tx_record *txr, int rw)
{
	int conflict = 0;
	struct tx_io *txio;
	struct tx_record *tmp_txr;

	list_for_each_entry(tmp_txr, &dmi->tx_record_list, record_list) {
		// For successful transactions within conflict window,
		// check for write-write conflicts
		if ((tmp_txr->success) && (tmp_txr->end_ver > txr->start_ver)) {
			list_for_each_entry(txio, &txr->io_list, io_list) {
				if (txio->rw == rw) {
					conflict = has_write_conflict(txio,
								      tmp_txr);
					if (conflict) {
						goto out;
					}
				}
			}
		}
	}
out:
	IOCPRINTK("(%d) FTX: tx_record check result (s:0, f:1): %d",
		  current->pid, conflict);
	return conflict;
}

// dmi->tx_record_list_lock should be held
static inline int check_snapshot_isolation(struct dm_isotope *dmi,
					   struct tx_record *txr)
{
	return check_conflict(dmi, txr, WRITE);
}

// dmi->tx_record_list_lock should be held
static inline int check_strict_serializability(struct dm_isotope *dmi,
					       struct tx_record *txr)
{
	return check_conflict(dmi, txr, READ);
}

// dmi->tx_record_list_lock should be held
static int check_tx_success(struct dm_isotope *dmi, struct tx_record *txr)
{
	int conflict = 0;
	unsigned long flags;
	// Write only transaction always succeeds
	if (txr->nr_reads == 0) {
		spin_lock_irqsave(&dmi->version_lock, flags);
		txr->start_ver = dmi->outstanding_ver;
		spin_unlock_irqrestore(&dmi->version_lock, flags);
		txr->success = 1;
		return 0;
	}
	if (txr->nr_writes == 0) {
		txr->end_ver = txr->start_ver;
		txr->success = 1;
		return 0;
	}

	conflict = check_snapshot_isolation(dmi, txr);
	//conflict = check_strict_serializability(dmg, txr);

	if (!conflict) txr->success = 1;
	else txr->success = 0;

	return conflict;
}

// dmi->tx_record_list_lock should be held
static void count_tx_to_wait(struct dm_isotope *dmi, struct tx_record *txr)
{
	struct tx_record *tmp_txr;

	// txr is the latest item to be added to the tx_record_list. txr can
	// commit only after all prior transactions finish commit.
	list_for_each_entry(tmp_txr, &dmi->tx_record_list, record_list) {
		// Check unfinished prior transactions
		BUG_ON(txr == tmp_txr);
		if (tmp_txr->state <= 3) {
			++txr->nr_tx_to_wait;
			IOCPRINTK("(%d) FTX: Should WAIT TXR end_ver "
				  "%u, My start_ver %u", current->pid,
				  tmp_txr->end_ver, txr->start_ver);
		}
	}
}

// dmi->tx_record_list_lock should be held
static void copy_missing_data(struct tx_io *src_txio, struct tx_io *dst_txio,
			      u32 nr_accessed_bytes, u32 granularity)
{
	int i, j;
	int start_byte;
	int end_byte;

	BUG_ON(dst_txio->data_bits == NULL);

	if (src_txio->data_bits == NULL) {
		start_byte = 0;
		end_byte = nr_accessed_bytes - 1;
	} else {
		start_byte = src_txio->accessed_start / 8;
		end_byte = (src_txio->accessed_start +
			    src_txio->accessed_cnt - 1) / 8;
	}

	for (j = start_byte; j <= end_byte; j++) {
		for (i = 0; i < 8; i++) {
			/* Check whether the latest data is
			 * already in the page */
			int idx = j * 8 + i;
			char *src_addr, *dst_addr;
			if (test_bit(idx, (volatile unsigned long *)
				     dst_txio->data_bits)) {
				continue;
			}
			if (src_txio->data_bits != NULL) {
				if (test_bit(idx, (volatile unsigned long *)
					     src_txio->data_bits)) {
copy_data:
					BUG_ON(src_txio->page == NULL ||
					       dst_txio->page == NULL);

					src_addr = src_txio->page + idx
						* granularity;
					dst_addr = dst_txio->page + idx
						* granularity;
					memcpy(dst_addr, src_addr, granularity);
					__set_bit(idx,
						  (volatile unsigned long *)
						  dst_txio->data_bits);
					IOCPRINTK("start %d end %d - byte %d "
						  "bit %d copied %d",
						  start_byte, end_byte, j, i,
						  idx);
				}
			} else {
				goto copy_data;
			}
		}
	}
	if (src_txio->data_bits == NULL) {
		// All data in dst_txio is up to date
		// so data_bit is not needed
		kfree((void *) dst_txio->data_bits);
		dst_txio->data_bits = NULL;
	}
	// TODO NOW: dst_txio->data_bits can be freed to indicate
	// all txio data is up to date when all data_bits are set.
	// Currently, this code does not check all data_bits being
	// set. 
}

// dmi->tx_record_list_lock should be held
// Scan txr and merge until all writes with the same v_block are 
// subsumed by the given txio
static void scan_self_and_merge(struct tx_record *txr, struct tx_io *txio)
{
	struct tx_io *tmp_txio = txio;

	list_for_each_entry_continue_reverse(tmp_txio, &txr->io_list,
					     io_list) {
		if ((tmp_txio->v_block == txio->v_block) &&
		    (tmp_txio->rw == WRITE)) {
			BUG_ON(txio == tmp_txio);

			if (txio->data_bits != NULL) {
				copy_missing_data(tmp_txio, txio,
						  txr->nr_accessed_bytes,
						  txr->granularity);
				IOCPRINTK("(%d) (ext): SELF MERGE "
					  "%u-%X %u-%X %p",
					  current->pid, txr->end_ver,
					  txio->data_bits, txr->end_ver,
					  tmp_txio->data_bits, tmp_txio);

			}
			// merged page or overwritten page is no longer needed
			free_page((unsigned long) tmp_txio->page);
			tmp_txio->page = NULL;
		}
	}
}

// dmi->tx_record_list_lock should be held
static void merge_data_within_tx(struct tx_record *txr)
{
	struct tx_io *txio;
	list_for_each_entry_reverse(txio, &txr->io_list, io_list) {
		if ((txio->rw == WRITE) && (txio->page != NULL)) {
			scan_self_and_merge(txr, txio);
		}
	}
}

// dmi->tx_record_list_lock should be held
static int scan_tx_and_merge(struct tx_io *txio, struct tx_record *txr)
{
	struct tx_io *tmp_txio;
	list_for_each_entry_reverse(tmp_txio, &txr->io_list, io_list) {
		if ((tmp_txio->v_block == txio->v_block) &&
		    (tmp_txio->rw == WRITE)) {
			if (tmp_txio->page == NULL) {
				continue;
			}
			copy_missing_data(tmp_txio, txio,
					  txr->nr_accessed_bytes,
					  txr->granularity);

			DPRINTK("(%d): DIFF MERGE %u-%X    %u-%X", current->pid,
				txr->end_ver,
				txio->data_bits,
				txr->end_ver,
				tmp_txio->data_bits);

			if (txio->data_bits == NULL) {
				return 0;
			}
		}
	}
	return 1;
}

// dmi->tx_record_list_lock should be held
static void scan_others_to_merge(struct dm_isotope *dmi, struct tx_record *txr,
				 struct tx_io *txio)
{
	struct tx_record *tmp_txr = txr;

	list_for_each_entry_continue_reverse(tmp_txr,
					     &dmi->tx_record_list,
					     record_list) {
		BUG_ON(txr == tmp_txr);
		/* We are interested in the transaction records that
		 * ended after the starting point of the current 
		 * transaction and the one same as the starting point. */
		if (tmp_txr->end_ver < txr->start_ver || (!tmp_txr->success)) {
			continue;
		}
		if (!scan_tx_and_merge(txio, tmp_txr)) {
			return;
		}
	}
}

static void merge_data_with_other_tx(struct dm_isotope *dmi,
				     struct tx_record *txr)
{
	struct tx_io *txio;
	list_for_each_entry_reverse(txio, &txr->io_list, io_list) {
		if (txio->rw == WRITE) {
			if (txio->data_bits != NULL) {
				/* write requests with no page is already
				 * subsumed or merged to a previous write
				 * in the same transaction */
				if (txio->page != NULL) {
					scan_others_to_merge(dmi, txr, txio);
				}
			}
		}
	}
}


// WARN: lock not held!
// This is read only operation to txr and it is guaranteed
// that the txios in the txr will not be updated.
static int create_and_submit_io_jobs(struct dm_tx *dmtx,
				     struct proc_info *pi,
				     struct tx_record *txr)
{
	struct dm_isotope *dmi = dmtx->dmi;
	struct dm_gecko *dmg = dmtx->dmg;
	struct tx_io *txio;

	BUG_ON(in_interrupt());

	list_for_each_entry(txio, &txr->io_list, io_list) {
		struct io_job *io;
		if (txio->rw == READ) {
			continue;
		}

		// Merged blocks no longer hold page
		if (txio->page == NULL) {
			continue;
		}

		io = mempool_alloc(io_job_mempool, GFP_ATOMIC);
		//io = kmem_cache_alloc(io_job_cache, GFP_ATOMIC);
		if (io == NULL) {
			unsigned long flags;
			spin_lock_irqsave(&txr->lock, flags);
			txr->fail_all_successors = 1;
			spin_unlock_irqrestore(&txr->lock, flags);
			printk(DM_TX_PREFIX "memory alloc failed");
			return -ENOMEM;
		}
		io->type = 0;
		io->bio = NULL;
		io->dmtx = dmtx;
		io->dmi = dmi;
		io->dmg = dmg;
		io->page = txio->page;
		io->pi = pi;
		io->version = txr->end_ver;
		io->err = 0;

		set_io_job_tx(io);
		io->rw = txio->rw;
		io->v_block = txio->v_block;
		io->txio = txio;

		BUG_ON(io->rw != WRITE);

		atomic_inc(&pi->nr_outstanding_io);
		atomic_inc(&dmi->nr_outstanding_io);
		submit_io_job(io);
	}
	return 0;
}

struct tx_record_meta {
	unsigned char success;
	u32 start_ver;
	u32 end_ver;
	int nr_io;
};

struct tx_io_meta {
	unsigned char rw;
	unsigned char accessed_bits;
	u32 v_block;
	u32 l_block;
};

// TODO: accessed_bits are not included
static int persist_tx_record(struct tx_record *txr)
{
	struct file *file = NULL;
	loff_t pos = 0;
	char *page;

	mm_segment_t old_fs = get_fs();
	struct tx_record_meta *txr_meta;
	struct tx_io_meta *txio_meta;
	char *page_offset = 0;
	int sz;

	struct tx_io *txio;
	unsigned long flags;
	int result = 0;

	page = (char *) __get_free_page(GFP_KERNEL);
	if (!page) {
		spin_lock_irqsave(&txr->lock, flags);
		txr->fail_all_successors = 1;
		spin_unlock_irqrestore(&txr->lock, flags);
		result = 1;
		goto return_failure;
	}

	set_fs(KERNEL_DS);
	file = filp_open("/tmp/gecko_tx_record", O_LARGEFILE | O_WRONLY |
			 O_CREAT | O_APPEND, 0644);
	if (!file) {
		spin_lock_irqsave(&txr->lock, flags);
		txr->fail_all_successors = 1;
		spin_unlock_irqrestore(&txr->lock, flags);
		printk(DM_TX_PREFIX "open /tmp/gecko_tx_record\n");
		result = 1;
		goto free_and_return_failure;
	}

	txr_meta = (struct tx_record_meta *) page;
	txr_meta->success = txr->success;
	txr_meta->start_ver = txr->start_ver;
	txr_meta->end_ver = txr->end_ver;
	txr_meta->nr_io = txr->nr_reads + txr->nr_writes;

	if (txr_meta->nr_io >= NUM_TX_IO_LIMIT) {
		spin_lock_irqsave(&txr->lock, flags);
		txr->fail_all_successors = 1;
		spin_unlock_irqrestore(&txr->lock, flags);
		printk("Tx supports up to %d IOs", NUM_TX_IO_LIMIT);
		result = 1;
		goto close_and_return_failure;
	}

	page_offset = page + sizeof(*txr_meta);

	list_for_each_entry(txio, &txr->io_list, io_list) {
		txio_meta = (struct tx_io_meta *) page_offset;
		txio_meta->rw = (unsigned char) txio->rw;
		txio_meta->v_block = txio->v_block;
		txio_meta->l_block = txio->l_block;
		page_offset += sizeof(*txio_meta);
	}

	sz = vfs_write(file, page, PAGE_SIZE, &pos);
	if (sz != PAGE_SIZE) {
		spin_lock_irqsave(&txr->lock, flags);
		txr->fail_all_successors = 1;
		spin_unlock_irqrestore(&txr->lock, flags);
		result = 1;
	}

close_and_return_failure:
	filp_close(file, current->files);

free_and_return_failure:
	free_page((unsigned long) page);
	set_fs(old_fs);

return_failure:
	return result;
}

// dmi->tx_record_list_lock should be held
static void make_tx_visible(struct dm_isotope *dmi, struct tx_record *txr)
{
	unsigned long flags;
	spin_lock_irqsave(&dmi->version_lock, flags);
	BUG_ON(dmi->curr_ver > txr->end_ver);
	dmi->curr_ver = txr->end_ver;
	spin_unlock_irqrestore(&dmi->version_lock, flags);
}

// dmi->tx_record_list_lock should be held
static int adjust_tx_count(struct dm_isotope *dmi, struct tx_record *txr)
{
	int cnt = 0;
	list_for_each_entry_continue(txr, &dmi->tx_record_list,
				     record_list) {
		--txr->nr_tx_to_wait;

		BUG_ON(txr->nr_tx_to_wait < 0);
		if (txr->nr_tx_to_wait == 0) {
			wake_up(&txr->prior_tx_wait_queue);
		}
		cnt++;
	}
	return cnt;
}

static void clean_up_and_free_txr(struct tx_record *txr)
{
	struct tx_io *txio, *tmp;

	list_for_each_entry_safe(txio, tmp, &txr->io_list, io_list) {
		if (txio->page != NULL) {
			free_page((unsigned long) txio->page);
			txio->page = NULL;
		}
		list_del(&txio->io_list);

		if (txio->accessed_bits != NULL) {
			kfree((void *) txio->accessed_bits);
			txio->accessed_bits = NULL;
		}
		if (txio->data_bits != NULL) {
			kfree((void *) txio->data_bits);
			txio->data_bits = NULL;
		}

		mempool_free(txio, tx_io_mempool);
	}
	BUG_ON(!list_empty(&txr->io_list));
	mempool_free(txr, tx_record_mempool);
}

// dmi->tx_record_list_lock should be held
static void try_to_clean_up_txr(struct dm_isotope *dmi)
{
	u32 oldest_ver_in_use;
	struct tx_record *txr, *tmp;
	oldest_ver_in_use = get_oldest_ver_in_use(dmi);

	list_for_each_entry_safe(txr, tmp, &dmi->tx_record_list, record_list) {
		if (txr->end_ver <= oldest_ver_in_use) {
			// All failed tx removed itself while processing failure
			BUG_ON(txr->success == 0);
			list_del(&txr->record_list);
			clean_up_and_free_txr(txr);
		} else {
			break;
		}
	}
}

//struct timespec ts_start, ts_end, ts_res;
static int process_tx_success(struct dm_tx *dmtx, struct proc_info *pi)
{
	struct dm_isotope *dmi = dmtx->dmi;
	struct tx_record *txr = pi->txr;
	unsigned long flags;

	IOCPRINTK("(%d): FTX SUCCESS", current->pid);
	BUG_ON(atomic_read(&pi->nr_outstanding_io) != 0);

	// At this point txr for current transaction is
	// also in the dmi->tx_record_list

	// 1. Merge pages if necessary
	IOCPRINTK("(%d): FTX block merge start", current->pid);

	spin_lock_irqsave(&dmi->tx_record_list_lock, flags);
	merge_data_within_tx(txr);
	merge_data_with_other_tx(dmi, txr);
	spin_unlock_irqrestore(&dmi->tx_record_list_lock, flags);

	IOCPRINTK("(%d): FTX block merge complete FTX end_ver %u",
		  current->pid, txr->end_ver);

	// 2. Submit buffered writes
	IOCPRINTK("(%d): FTX submitting IO", current->pid);
	if(create_and_submit_io_jobs(dmtx, pi, txr)) {
		goto err_out;
	}

	// 3. wait until all outstanding I/Os to finish
	// TODO (jyshin): modify to wait_event!
	IOCPRINTK("(%d): FTX IO SLEEP pi->nr_outstanding_io = %d", current->pid,
		  atomic_read(&pi->nr_outstanding_io));
	wait_event_interruptible(pi->tx_io_wait_queue,
				 atomic_read(&pi->nr_outstanding_io) == 0);
	IOCPRINTK("(%d): FTX Woke up IO done", current->pid);

	if (txr->fail_all_successors == 1) {
		goto err_out;
	}

	spin_lock_irqsave(&dmi->tx_record_list_lock, flags);
	txr->state = 3;
	spin_unlock_irqrestore(&dmi->tx_record_list_lock, flags);

	// 4. Flush tx_record to flash
	// FIX: versioned dev ops start
	if (persist_tx_record(txr)) {
		// FIX: versioned dev ops end 
		IOCPRINTK("(%d): FTX Persist TXR failed", current->pid);
		goto err_out;
	}
	//IOCPRINTK("(%d): FTX Persist TXR Success", current->pid);

	// 5. Sleep until transactions  proceeding it to finish 
	// TODO: wait may hang due to unfinished transactions. 
	IOCPRINTK("(%d): FTX TXR SLEEP txr->nr_tx_to_wait = %d", current->pid,
		  txr->nr_tx_to_wait);
	wait_event_interruptible(txr->prior_tx_wait_queue,
				 txr->nr_tx_to_wait == 0);
	IOCPRINTK("(%d): FTX Woke up TXR wait done", current->pid);

	// 6. modify metadata and modify the mapping
	spin_lock_irqsave(&dmi->tx_record_list_lock, flags);

	adjust_tx_count(dmi, txr);
	make_tx_visible(dmi, txr);
	txr->state = 4;

	try_to_clean_up_txr(dmi);
	spin_unlock_irqrestore(&dmi->tx_record_list_lock, flags);

	return 0;

err_out:
	BUG_ON(true);
	return 1;
}

static void process_tx_failure(struct dm_isotope *dmi,
			       struct proc_info *pi)
{
	struct tx_record *txr = pi->txr;
	unsigned long flags;

	wait_event_interruptible(pi->tx_io_wait_queue,
				 atomic_read(&pi->nr_outstanding_io) == 0);

	if(persist_tx_record(txr)) {
		IOCPRINTK("(%d): FTX Persist TXR failed", current->pid);
	}
	wait_event_interruptible(txr->prior_tx_wait_queue,
				 txr->nr_tx_to_wait == 0);

	spin_lock_irqsave(&dmi->tx_record_list_lock, flags);
	txr->state = 4;
	adjust_tx_count(dmi, txr);
	list_del(&txr->record_list);
	spin_unlock_irqrestore(&dmi->tx_record_list_lock, flags);

	clean_up_and_free_txr(txr);
}

static void clean_up_tx(struct dm_tx *dmtx, struct proc_info *pi)
{
	struct dm_isotope *dmi = dmtx->dmi;
	unsigned long flags;

	if (is_transaction_ongoing(pi)) {
		clear_bit(PROC_INFO_TRANSACTION, &pi->flags);
	}
	IOCPRINTK("(%d): FLAG 0x%X Num remaining %u", current->pid,
		  (unsigned int) pi->flags,
		  atomic_read(&pi->nr_outstanding_io));

	spin_lock_irqsave(&dmi->tx_proc_info_list_lock, flags);
	list_del(&pi->tt_list);
	spin_unlock_irqrestore(&dmi->tx_proc_info_list_lock, flags);

	remove_proc_info(dmi, pi);

	pi->txr = NULL;

	mempool_free(pi, proc_info_mempool);
}

static int ioctl_endtx(struct dm_tx *dmtx, u32 *version)
{
	struct dm_isotope *dmi = dmtx->dmi;

	unsigned long flags;
	unsigned long ver_flags;
	//unsigned long ver_flags;
	struct proc_info *pi;
	struct tx_record *txr;

	int result = 0;
	struct dm_isotope_stats *stats;

	pi = get_proc_info(dmi, current->pid);

	if (!pi) {
		return 1;
	}
	if (!is_transaction_ongoing(pi)) {
		return 1;
	}
	txr = pi->txr;
	BUG_ON(txr == NULL);

	if (--txr->nest_count > 0) {
		return 0;
	}
	// TODO modify to wait_event! 
	// 1. Wait for outstanding reads to finish
	IOCPRINTK("(%d): EndTx sleep pi->nr_outstanding_io = %d",
		  pi->pid, atomic_read(&pi->nr_outstanding_io));
	wait_event_interruptible(pi->tx_io_wait_queue,
				 atomic_read(&pi->nr_outstanding_io) == 0);
	IOCPRINTK("(%d): EndTx awoke", pi->pid);

	// 2. Check tx success or failure
	spin_lock_irqsave(&dmi->tx_record_list_lock, flags);
	result = check_tx_success(dmi, txr);
	if (txr->fail_all_successors) {
		txr->success = 0;
		result = 1;
	}

	get_cpu();
	stats = this_cpu_ptr(dmi->stats);
	if (result) {
		++stats->tx_failure;
	} else {
		++stats->tx_success;
	}
	if (txr->nr_writes == 0) {
		++stats->readonly_tx;
	} else if (txr->nr_reads == 0) {
		++stats->writeonly_tx;
	} else {
		++stats->readwrite_tx;
	}
	put_cpu();

	count_tx_to_wait(dmi, txr);
	txr->state = 2;
	list_add_tail(&txr->record_list, &dmi->tx_record_list);

	// 4. Depending on the tx success/failure result commit or abort tx
	if (!result) {

		txr->end_ver = __inc_and_get_outstanding_ver(dmi);
		if (txr->nr_writes == 0) {
			(*version) = txr->start_ver;
		} else {
			(*version) = txr->end_ver;
		}
		spin_unlock_irqrestore(&dmi->tx_record_list_lock, flags);

		IOCPRINTK("(%d): FTX success", pi->pid);
		result = process_tx_success(dmtx, pi);

		IOCPRINTK("(%d): FTX success result %d", pi->pid, result);
		if (result) {
			goto fail_all_successors;
		}
	} else {
		spin_lock_irqsave(&dmi->version_lock, ver_flags);
		txr->end_ver = dmi->curr_ver;
		spin_unlock_irqrestore(&dmi->version_lock, ver_flags);

		spin_unlock_irqrestore(&dmi->tx_record_list_lock, flags);
		process_tx_failure(dmi, pi);
	}

	clean_up_tx(dmtx, pi);
	return result;

fail_all_successors:
	// TODO: handle failure during a successful transaction commit. All
	// transactions dependent on this failed transaction should fail. 
	return result;
}

static int ioctl_aborttx(struct dm_tx *dmtx)
{
	struct dm_isotope *dmi = dmtx->dmi;
	struct proc_info *pi;
	int result = 0;
	unsigned long flags;
	struct dm_isotope_stats *stats;
	pi = get_proc_info(dmi, current->pid);

	if (!pi) {
		IOCPRINTK("(%d): AbortTx failed. No proc_info found.",
			  current->pid);
		result = 1;
		goto aborttx_out;
	}
	if (!is_transaction_ongoing(pi)) {
		IOCPRINTK("(%d): AbortTx failed. No transaction ongoing.",
			  current->pid);
		result = 1;
		goto aborttx_out;
	}
	IOCPRINTK("(%d): AbortTx sleep pi->nr_outstanding_io = %d", pi->pid,
		  atomic_read(&pi->nr_outstanding_io));

	// TODO modify to wait_event! This is temporarily made
	// interruptible for testing purposes.
	wait_event_interruptible(pi->tx_io_wait_queue,
				 atomic_read(&pi->nr_outstanding_io) == 0);
	IOCPRINTK("(%d): AbortTx awoke", pi->pid);

	spin_lock_irqsave(&dmi->tx_record_list_lock, flags);
	result = check_tx_success(dmi, pi->txr);
	spin_unlock_irqrestore(&dmi->tx_record_list_lock, flags);

	if (pi->txr->nest_count > 0) {
		pi->txr->fail_all_successors = 1;
		goto aborttx_out;
	}

	clean_up_and_free_txr(pi->txr);
	clean_up_tx(dmtx, pi);

	get_cpu();
	stats = this_cpu_ptr(dmi->stats);
	++stats->tx_abort;
	put_cpu();

aborttx_out:
	return result;
}

static int ioctl_openver(struct dm_tx *dmtx, u32 version)
{
	struct dm_isotope *dmi = dmtx->dmi;
	struct proc_info *pi;
	unsigned long flags;

	spin_lock_irqsave(&dmi->version_lock, flags);
	if (version < dmi->oldest_ver || dmi->curr_ver < version) {
		IOCPRINTK("(%d), TRIED TO OPEN AN INVALID VERSION [%u]!",
			  current->pid, version);
		spin_unlock_irqrestore(&dmi->version_lock, flags);
		return 1;
	}
	spin_unlock_irqrestore(&dmi->version_lock, flags);

	pi = get_proc_info(dmi, current->pid);
	if (!pi) {
		return 1;
	}
	if (!is_transaction_ongoing(pi)) {
		return 1;
	}
	// Can be used for read-only operations.
	if (pi->txr->nr_writes) {
		return 1;
	}

	pi->ver_opened = version;
	pi->txr->start_ver = version;

	return 0;
}

static int ioctl_setoldestver(struct dm_isotope *dmi, struct dm_gecko *dmg,
			      u32 version)
{
	unsigned long flags;
	spin_lock_irqsave(&dmi->version_lock, flags);
	if (version >= dmi->oldest_ver && version <= dmi->curr_ver) {
		u32 ver_limit = get_oldest_ver_in_use(dmi);
		if (version <= ver_limit) {
			// TODO NOW: dmg->free_blocks should be adjusted
			dmi->oldest_ver = version;
			dmg->oldest_ver = version;
			spin_unlock_irqrestore(&dmi->version_lock, flags);
			return 0;
		} else {
			IOCPRINTK("OLDEST_VER IN USE %u < NEW OLDEST %u!",
				  ver_limit, version);
			spin_unlock_irqrestore(&dmi->version_lock, flags);
			return 1;
		}
	}
	IOCPRINTK("INVALID VERSION (< oldest, > current)!");
	spin_unlock_irqrestore(&dmi->version_lock, flags);
	return 1;
}

static int ioctl_setcachedrange(struct dm_gecko *dmg, u32 addr_limit)
{
	int i;
	for (i = 0; i < addr_limit; i++) {
		set_bit(i, dmg->cached_v_block_map);
	}
	IOCPRINTK("Finished setting 0 to %u cachable", addr_limit);
	return 0;
}

static int ioctl_setcachedblock(struct dm_gecko *dmg, u32 v_block)
{
	set_bit(v_block, dmg->cached_v_block_map);
	IOCPRINTK("Finished setting %u cachable", v_block);
	return 0;
}

static int allocate_and_set_accessed_bits(struct tx_io *txio,
					  u32 nr_accessed_bytes, u16 start,
					  u16 cnt)
{
	int i;
	if (txio->accessed_bits == NULL) {
		txio->accessed_bits =
			kzalloc(sizeof(unsigned char)
				* nr_accessed_bytes, GFP_ATOMIC);
		if (txio->accessed_bits == NULL) {
			return 1;
		}
	}
	if (txio->data_bits == NULL) {
		txio->data_bits =
			kzalloc(sizeof(unsigned char)
				* nr_accessed_bytes, GFP_ATOMIC);;
		if (txio->data_bits == NULL) {
			kfree((void *) txio->accessed_bits);
			txio->accessed_bits = NULL;
			return 1;
		}
	}
	txio->accessed_start = start;
	txio->accessed_cnt = cnt;
	for (i = start; i < start + cnt; i++) {
		__set_bit(i, (volatile unsigned long *) txio->accessed_bits);
		__set_bit(i, (volatile unsigned long *) txio->data_bits);

		if (i >= nr_accessed_bytes * 8) {
			BUG_ON(true);
			return 1;
		}
	}
	IOCPRINTK("Alloc accessedbits complete %d", i);
	return 0;
}

static int ioctl_setaccessedbits(struct dm_tx *dmtx, u32 arg)
{
	struct dm_isotope *dmi = dmtx->dmi;

	u32 id;
	u32 shift; // log2(granularity)
	u32 granularity; // subblock size
	u16 start; // start subblock
	u16 cnt; // subblock count
	u32 accessed_bytes;
	int result = 1;

	struct proc_info *pi;
	struct tx_record *txr;
	struct tx_io *txio;
	u32 idx = 0;

	id = DM_TX_EXTAB_ID(arg);
	shift = DM_TX_EXTAB_SIZE(arg);
	granularity = (1U << shift);
	start = DM_TX_EXTAB_START(arg);
	cnt = DM_TX_EXTAB_CNT(arg);

	if ((1U << shift) > GECKO_SECTOR_SIZE) {
		IOCPRINTK("shift is too large");
		return 1;
	}
	if (start + cnt > (GECKO_BLOCK_SIZE >> shift)) {
		IOCPRINTK("accessedbits: start + cnt %d out of bound %d",
			  start+cnt, (GECKO_BLOCK_SIZE>>shift));
		return 1;
	}

	accessed_bytes = (GECKO_BLOCK_SIZE >> shift) >> 3;

	IOCPRINTK("Set Dirty Bits id %u, gran %u (%u), start %u, cnt %u, dbytes %u",
		  id, granularity, shift, start, cnt, accessed_bytes);

	pi = get_proc_info(dmi, current->pid);

	if (!pi) {
		IOCPRINTK("accessedbits: pi doesn't exist");
		return 1;
	}
	if (!is_transaction_ongoing(pi)) {
		IOCPRINTK("accessedbits: not doing tx");
		return 1;
	}
	if (pi->txr->nr_writes + pi->txr->nr_reads <= id) {
		IOCPRINTK("accessedbits: id out of bound");
		return 1;
	}

	txr = pi->txr;
	if (txr->nr_accessed_bytes == 0) {
		txr->nr_accessed_bytes = accessed_bytes;
		txr->granularity = granularity;
	} else if (txr->nr_accessed_bytes != accessed_bytes) {
		IOCPRINTK("accessedbits: inconsistent granularity");
		return 1;
	}

	list_for_each_entry(txio, &txr->io_list, io_list) {
		if (id == idx) {
			result = allocate_and_set_accessed_bits(txio,
								txr->nr_accessed_bytes,
								start, cnt);
			break;
		} else {
			idx++;
		}
	}

	return result;
}

static void ioctl_getcost(struct dm_gecko *dmg, struct addr_versions *addr_vers)
{
	unsigned long flags;
	u32 l_blk;
	int i;
	struct dm_dev_info *dev;
	u32 addr = addr_vers->addr;;
	for (i = 0; i < DM_TX_COST_QUERY_LIMIT; i++) {
		int cost = 0;
		if (addr_vers->versions[i] == 0xFFFFFFFF) {
			break;
		}

		spin_lock_irqsave(&dmg->lock, flags);
		l_blk = __get_old_l_block(dmg, addr, addr_vers->versions[i]);
		spin_unlock_irqrestore(&dmg->lock, flags);

		if (dmg->lru_cache_size_blk > 0) {
			if (lru_cache_is_hit(dmg->lru_mem_cache, l_blk)) {
				addr_vers->versions[i] = cost;
				continue;
			}
		}
		if (l_blk == dmg->size) {
			addr_vers->versions[i] = 0x7FFFFFFF;
		} else {
			dev = dev_for_sector(dmg, block_to_sector(l_blk));
			cost += atomic_read(&dev->outstanding_reads);
			cost += (atomic_read(&dev->outstanding_writes) *
				 YOGURT_WRITE_WEIGHT);
			addr_vers->versions[i] = YOGURT_WRITE_WEIGHT + cost;
		}
	}
}

static int ioctl_getversionlimit(struct dm_gecko *dmg, struct dm_isotope *dmi,
				 struct addr_version * addr_ver)
{
	unsigned long flags;
	u32 addr = addr_ver->addr;
	u32 limit;
	spin_lock_irqsave(&dmg->lock, flags);
	limit = __get_old_version_limit(dmg, addr, addr_ver->version);
	spin_unlock_irqrestore(&dmg->lock, flags);

	if (limit >= MAX_VERSION) {
		spin_lock_irqsave(&dmi->version_lock, flags);
		limit = 0;
		spin_unlock_irqrestore(&dmi->version_lock, flags);
	}
	return limit;
}

// return 0 for success and 1 for failure
static int dm_tx_ioctl(struct dm_target *ti, unsigned int cmd,
		       unsigned long arg)
{
	struct dm_tx *dmtx = (struct dm_tx *) ti->private;
	struct dm_isotope *dmi = dmtx->dmi;
	struct dm_gecko *dmg = dmtx->dmg;

	int result = 0;
	u32 tmp_ver = 0;
	u32 tmp_addr = 0;
	pid_t tmp_handle = 0;
	unsigned long flags;
	struct addr_versions addr_vers;
	struct addr_version addr_ver;

	result = ioctl_check(cmd, arg);
	if (result) {
		return result;
	}

	switch (cmd) {
	case DM_TX_IOC_Q_BEGINFTX:
		IOCPRINTK("(%d), type [0x%X] nr [0x%X]: BeginTX",
			  current->pid, _IOC_TYPE(cmd), _IOC_NR(cmd));
		result = ioctl_begintx(dmtx);
		break;

	case DM_TX_IOC_GQ_ENDFTX:
		IOCPRINTK("(%d), type [0x%X] nr [0x%X]: EndTX - start",
			  current->pid, _IOC_TYPE(cmd), _IOC_NR(cmd));
		result = ioctl_endtx(dmtx, &tmp_ver);
		IOCPRINTK("(%d), type [0x%X] nr [0x%X]: EndTX - done",
			  current->pid, _IOC_TYPE(cmd), _IOC_NR(cmd));
		__put_user(tmp_ver, (u32 __user *) arg);
		break;

	case DM_TX_IOC_GQ_RELEASETX:
		IOCPRINTK("(%d), type [0x%X] nr [0x%X]: ReleaseTX - start",
			  current->pid, _IOC_TYPE(cmd), _IOC_NR(cmd));

		tmp_handle = ioctl_releasetx(dmtx);
		if (tmp_handle < PID_MAX_LIMIT) {
			result = 1;
			break;
		}
		result = __put_user(tmp_handle, (u32 __user *) arg);

		IOCPRINTK("(%d), type [0x%X] nr [0x%X]: ReleaseTx done hdl: %u",
			  current->pid, _IOC_TYPE(cmd), _IOC_NR(cmd),
			  tmp_handle);
		break;

	case DM_TX_IOC_SQ_TAKEOVERTX:
		result = __get_user(tmp_handle, (u32 __user *) arg);
		IOCPRINTK("(%d), type [0x%X] nr [0x%X]: takeover handle [%u]",
			  current->pid, _IOC_TYPE(cmd), _IOC_NR(cmd),
			  tmp_handle);
		if (!result) {
			result = ioctl_takeovertx(dmtx, tmp_handle);
		}
		IOCPRINTK("(%d), type [0x%X] nr [0x%X]: takeover done [%u]",
			  current->pid, _IOC_TYPE(cmd), _IOC_NR(cmd),
			  tmp_handle);
		break;


	case DM_TX_IOC_Q_ABORTFTX:
		IOCPRINTK("(%d), type [0x%X] nr [0x%X]: AbortTX",
			  current->pid, _IOC_TYPE(cmd), _IOC_NR(cmd));
		result = ioctl_aborttx(dmtx);
		break;

	case DM_TX_IOC_G_GETCURVER:
		IOCPRINTK("(%d), type [0x%X] nr [0x%X]: Get Curr Ver [%u]",
			  current->pid, _IOC_TYPE(cmd), _IOC_NR(cmd),
			  dmi->curr_ver);
		spin_lock_irqsave(&dmi->version_lock, flags);
		tmp_ver = dmi->curr_ver;
		spin_unlock_irqrestore(&dmi->version_lock, flags);
		result = __put_user(tmp_ver, (u32 __user *) arg);
		break;

	case DM_TX_IOC_G_GETPID:
		IOCPRINTK("(%d), type [0x%X] nr [0x%X]: Get PID",
			  current->pid, _IOC_TYPE(cmd), _IOC_NR(cmd));
		result = __put_user(current->pid, (u32 __user *) arg);
		break;

	case DM_TX_IOC_G_GETOLDESTVER:
		IOCPRINTK("(%d), type [0x%X] nr [0x%X]: Get Oldest Ver [%u]",
			  current->pid, _IOC_TYPE(cmd), _IOC_NR(cmd),
			  dmi->oldest_ver);
		tmp_ver = get_oldest_ver_in_use(dmi);
		result = __put_user(tmp_ver, (u32 __user *) arg);
		break;

	case DM_TX_IOC_SQ_SETOLDESTVER:
		result = __get_user(tmp_ver, (u32 __user *) arg);
		IOCPRINTK("(%d), type [0x%X] nr [0x%X]: Set Oldest Ver [%u]",
			  current->pid, _IOC_TYPE(cmd), _IOC_NR(cmd), tmp_ver);

		if (!capable(CAP_SYS_ADMIN)) {
			IOCPRINTK("NOT ENOUGH PRIVILEGE FOR SETOLDESTVER!");
			return -EPERM;
		}

		if (!result) {
			result = ioctl_setoldestver(dmi, dmg, tmp_ver);
		}
		break;

	case DM_TX_IOC_SQ_OPENVER:
		result = __get_user(tmp_ver, (u32 __user *) arg);
		IOCPRINTK("(%d), type [0x%X] nr [0x%X]: OpenVersion[%u]",
			  current->pid, _IOC_TYPE(cmd), _IOC_NR(cmd), tmp_ver);

		if (!result) {
			result = ioctl_openver(dmtx, tmp_ver);
		}
		break;

	case DM_TX_IOC_SQ_SETCACHEDRANGE:
		result = __get_user(tmp_addr, (u32 __user *) arg);
		IOCPRINTK("(%d), type [0x%X] nr [0x%X]: "
			  "Set cached range up to [%u]",
			  current->pid, _IOC_TYPE(cmd), _IOC_NR(cmd), tmp_addr);

		if (!capable(CAP_SYS_ADMIN)) {
			IOCPRINTK("NOT ENOUGH PRIVILEGE FOR SETOLDESTVER!");
			return -EPERM;
		}

		if (!result) {
			spin_lock_irqsave(&dmg->lock, flags);
			result = ioctl_setcachedrange(dmg, tmp_addr);
			spin_unlock_irqrestore(&dmg->lock, flags);
		}
		break;

	case DM_TX_IOC_SQ_SETCACHEDBLOCK:
		result = __get_user(tmp_addr, (u32 __user *) arg);
		IOCPRINTK("(%d), type [0x%X] nr [0x%X]: Set cached block [%u]",
			  current->pid, _IOC_TYPE(cmd), _IOC_NR(cmd), tmp_addr);

		if (!capable(CAP_SYS_ADMIN)) {
			IOCPRINTK("NOT ENOUGH PRIVILEGE FOR SETOLDESTVER!");
			return -EPERM;
		}

		if (!result) {
			spin_lock_irqsave(&dmg->lock, flags);
			result = ioctl_setcachedblock(dmg, tmp_addr);
			spin_unlock_irqrestore(&dmg->lock, flags);
		}
		break;

	case DM_TX_IOC_SQ_SETDIRTYBITS:
		result = __get_user(tmp_addr, (u32 __user *) arg);
		IOCPRINTK("(%d), type [0x%X] nr [0x%X]: "
			  "Set accessedbits code [%u]",
			  current->pid, _IOC_TYPE(cmd), _IOC_NR(cmd), tmp_addr);

		if (!result) {
			ioctl_setaccessedbits(dmtx, tmp_addr);
		}
		break;

	case DM_TX_IOC_TGQ_GETCOST:
		if (copy_from_user(&addr_vers, (void __user *) arg,
				   sizeof(addr_vers)) != 0) {
			printk(DM_TX_PREFIX "IOCTL: GetCost error (%d), "
			       "type [0x%X] nr [0x%X]:  [0x%lX]", current->pid,
			       _IOC_TYPE(cmd), _IOC_NR(cmd), arg);
			return -EFAULT;
		}
		//printk("copy success %u - %u %u %u\n", addr_vers.version, addr_vers.addr[0],
		//		addr_vers.addr[1], addr_vers.addr[2]);
		ioctl_getcost(dmg, &addr_vers);
		//printk("Cost %u\n", tmp_cost);
		//result = __put_user(tmp_cost, (int __user *) arg);
		result = copy_to_user((void __user *) arg, &addr_vers,
				      sizeof(addr_vers));
		break;

	case DM_TX_IOC_TGQ_GETVERLIMIT:
		if (copy_from_user(&addr_ver, (void __user *) arg,
				   sizeof(addr_ver)) != 0) {
			printk(DM_TX_PREFIX "IOCTL: GetVerLimit error (%d), "
			       "type [0x%X] nr [0x%X]:  [0x%lX]", current->pid,
			       _IOC_TYPE(cmd), _IOC_NR(cmd), arg);
			return -EFAULT;
		}
		//printk("copy success %u - %u %u %u\n", addr_vers.version, addr_vers.addr[0],
		//		addr_vers.addr[1], addr_vers.addr[2]);
		tmp_ver = ioctl_getversionlimit(dmg, dmi, &addr_ver);
		//printk("Cost %u\n", tmp_cost);
		//result = __put_user(tmp_cost, (int __user *) arg);
		if (tmp_ver == TX_NO_VERSION) {
			return -EFAULT;
		}
		addr_ver.version = tmp_ver;
		result = copy_to_user((void __user *) arg, &addr_ver,
				      sizeof(addr_ver));
		break;

	default:
		printk(DM_TX_PREFIX "IOCTL: (%d), type [0x%X] nr [0x%X]: Invalid Arg\n",
		       current->pid, _IOC_TYPE(cmd), _IOC_NR(cmd));
		result = -ENOTTY;
	}

	return result;
}

static struct target_type dm_tx_target = {
	.name = "dm-tx",
	.version = {0, 0, 1},
	.module = THIS_MODULE,
	.ctr = dm_tx_ctr,
	.dtr = dm_tx_dtr,
	.map = dm_tx_map,
	.status = dm_tx_status,
	.message = dm_tx_message,
	.ioctl = dm_tx_ioctl,
};

static int __init dm_tx_init(void)
{
	int err = -ENOMEM;

#ifdef CONFIG_KALLSYMS
	unsigned long sys_rename_addr = kallsyms_lookup_name("sys_rename");
	if (sys_rename_addr == 0) {
		printk(DM_TX_PREFIX "Unable to lookup sys_rename symbol\n");
	} else {
		sys_rename_wrapper = (void *) sys_rename_addr;
		printk(DM_TX_PREFIX "Found sys_rename at address 0x%p\n",
		       sys_rename_wrapper);
	}
#elif defined SYS_RENAME_EXPORTED_TO_MODULES
	sys_rename_wrapper = sys_rename;
#endif

	if (!(io_job_cache = KMEM_CACHE(io_job, 0))) {
		printk(DM_TX_PREFIX "unable to alloc io_job cache\n");
		goto err_out;
	}

	if (!(d_map_entry_cache = KMEM_CACHE(d_map_entry, 0))) {
		printk(DM_TX_PREFIX "unable to alloc d_map_entry cache\n");
		goto destroy_io_job_cache_and_out;
	}

	if (!(proc_info_cache = KMEM_CACHE(proc_info, 0))) {
		printk(DM_TX_PREFIX "unable to alloc proc_info cache\n");
		goto destroy_d_map_entry_cache_and_out;
	}

	if (!(tx_record_cache = KMEM_CACHE(tx_record, 0))) {
		printk(DM_TX_PREFIX "unable to alloc tx_record cache\n");
		goto destroy_proc_info_cache_and_out;
	}

	if (!(tx_io_cache = KMEM_CACHE(tx_io, 0))) {
		printk(DM_TX_PREFIX "unable to alloc tx_io cache\n");
		goto destroy_tx_record_cache_and_out;
	}

	io_job_mempool = mempool_create_slab_pool(MIN_JOBS_IN_POOL,
						  io_job_cache);
	if (!io_job_mempool) {
		printk(DM_TX_PREFIX "unable to alloc io_job mempool\n");
		goto destroy_tx_io_cache_and_out;
	}

	d_map_entry_mempool = mempool_create_slab_pool(MIN_JOBS_IN_POOL,
						       d_map_entry_cache);
	if (!d_map_entry_mempool) {
		printk(DM_TX_PREFIX "unable to alloc d_map_entry mempool\n");
		goto destroy_io_job_mempool_and_out;
	}

	proc_info_mempool = mempool_create_slab_pool(MIN_PROCS_IN_POOL,
						     proc_info_cache);
	if (!proc_info_mempool) {
		printk(DM_TX_PREFIX "unable to alloc proc_info mempool\n");
		goto destory_d_map_entry_mempool_and_out;
	}

	tx_record_mempool = mempool_create_slab_pool(MIN_PROCS_IN_POOL,
						     tx_record_cache);
	if (!tx_record_mempool) {
		printk(DM_TX_PREFIX "unable to alloc tx_record mempool\n");
		goto destroy_proc_info_mempool_and_out;
	}

	tx_io_mempool = mempool_create_slab_pool(MIN_PROCS_IN_POOL,
						 tx_io_cache);
	if (!tx_io_mempool) {
		printk(DM_TX_PREFIX "unable to alloc tx_io mempool\n");
		goto destroy_tx_record_mempool_and_out;
	}

	if (!(io_finish_work_queue =
	      create_singlethread_workqueue("geckod-io-fin"))) {
		printk(DM_TX_PREFIX
		       "unable to create geckod-io-fin workqueue\n");
		goto destroy_tx_io_mempool_and_out;
	}
	INIT_WORK(&io_finish_work, finish_io);


	if ((err = dm_register_target(&dm_tx_target)) < 0) {
		printk(DM_TX_PREFIX "register target failed %d\n", err);
		goto destroy_io_finish_work_queue_and_out;
	}

	printk(DM_TX_PREFIX "module loaded\n");

	return 0;

destroy_io_finish_work_queue_and_out:
	destroy_workqueue(io_finish_work_queue);
destroy_tx_io_mempool_and_out:
	mempool_destroy(tx_io_mempool);
destroy_tx_record_mempool_and_out:
	mempool_destroy(tx_record_mempool);
destroy_proc_info_mempool_and_out:
	mempool_destroy(proc_info_mempool);
destory_d_map_entry_mempool_and_out:
	mempool_destroy(d_map_entry_mempool);
destroy_io_job_mempool_and_out:
	mempool_destroy(io_job_mempool);
destroy_tx_io_cache_and_out:
	kmem_cache_destroy(tx_io_cache);
destroy_tx_record_cache_and_out:
	kmem_cache_destroy(tx_record_cache);
destroy_proc_info_cache_and_out:
	kmem_cache_destroy(proc_info_cache);
destroy_d_map_entry_cache_and_out:
	kmem_cache_destroy(d_map_entry_cache);
destroy_io_job_cache_and_out:
	kmem_cache_destroy(io_job_cache);
err_out:
	return err;
}

static void __exit dm_tx_exit(void)
{
	dm_unregister_target(&dm_tx_target);
	mempool_destroy(io_job_mempool);
	mempool_destroy(d_map_entry_mempool);
	mempool_destroy(proc_info_mempool);
	mempool_destroy(tx_record_mempool);
	mempool_destroy(tx_io_mempool);
	kmem_cache_destroy(io_job_cache);
	kmem_cache_destroy(d_map_entry_cache);
	kmem_cache_destroy(proc_info_cache);
	kmem_cache_destroy(tx_record_cache);
	kmem_cache_destroy(tx_io_cache);
	destroy_workqueue(io_finish_work_queue);
	printk(DM_TX_PREFIX "module unloaded\n");
}

module_init(dm_tx_init);
module_exit(dm_tx_exit);

MODULE_DESCRIPTION("dm-tx: combination of Gecko, Isotope and Yogurt.");
MODULE_AUTHOR("Ji-Yong Shin <jyshin@cs.cornell.edu>");
#ifndef MODULE_LICENSE
#define MODULE_LICENSE(a)
#endif
MODULE_LICENSE("Dual BSD/GPL");
