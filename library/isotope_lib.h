#ifndef __ISOTOPE_LIB_H__
#define  __ISOTOPE_LIB_H__

#include "../src/dm-tx-ioctl.h"

// Begins transaction.
int begin_tx(int fd);

// Ends transaction.
unsigned int end_tx(int fd);

// Aborts transaction.
int abort_tx(int fd);

// Get current version number.
unsigned int get_curr_ver(int fd);

// Get oldest version used by a live transaction. If there is no live
// transaction, then MAX_VERSION is returned.
unsigned int get_oldest_ver(int fd);

// Releases an ongoing transaction. This disconnects the bound between the pid
// and the transaction.
unsigned int release_tx(int fd);

// Takes over a released transaction. This binds the caller pid with the
// transaction.
int takeover_tx(int fd, unsigned int handle);

// Set pinned memory cache on addr.
int set_cached_block(int fd, unsigned int addr);

// Set pinned memory cache. From 0 to addr.
int set_cached_range(int fd, unsigned int addr);

// Set accessed bits on subblocks.
// id: I/O sequence number within a TX.
// size: subblock size (= 2 ^ (size))
// start: start position in subblock granularity
// cnt: number of subblocks from start
int mark_accessed(int fd, int id, int size, int start, int cnt);

#endif
