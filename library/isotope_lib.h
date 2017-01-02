#ifndef __ISOTOPE_LIB_H__
#define  __ISOTOPE_LIB_H__

#include "../src/dm-tx-ioctl.h"

int begin_tx(int fd);
unsigned int end_tx(int fd);
int abort_tx(int fd);
unsigned int get_curr_ver(int fd);
unsigned int get_oldest_ver(int fd);
unsigned int release_tx(int fd);
int takeover_tx(int fd, unsigned int handle);
int set_cached_block(int fd, unsigned int addr);
int set_cached_range(int fd, unsigned int addr);
// id: I/O sequence number within a TX.
// size: subblock size (= 2 ^ (size))
// start: start position in subblock granularity
// cnt: number of subblocks from start
int mark_accessed(int fd, int id, int size, int start, int cnt);

#endif
