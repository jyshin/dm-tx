#include "isotope_lib.h"

#include <math.h>
#include <stdio.h>
#include <sys/ioctl.h>

#define VERBOSE 1

int begin_tx(int fd) {
	int retval;
	retval = ioctl(fd, DM_TX_IOC_Q_BEGINFTX);
#if VERBOSE
	fprintf(stderr, "begin_tx retval %d\n", retval);
#endif
	return retval;
}

unsigned int end_tx(int fd) {
	int retval;
	unsigned int version;
	retval = ioctl(fd, DM_TX_IOC_GQ_ENDFTX, &version);
#if VERBOSE
	fprintf(stderr, "end_tx version %u retval %d\n", version, retval);
#endif
	return retval;
}

int abort_tx(int fd) {
	int retval;
	retval = ioctl(fd, DM_TX_IOC_Q_ABORTFTX);
#if VERBOSE
	fprintf(stderr, "abort_tx retval %d\n", retval);
#endif
	return retval;
}

unsigned int get_curr_ver(int fd) {
	int retval;
	unsigned int version;
	retval = ioctl(fd, DM_TX_IOC_G_GETCURVER, &version);
#if VERBOSE
	fprintf(stderr, "curr_ver %u retval %d\n", version, retval);
#endif
	return version;
}

unsigned int get_oldest_ver(int fd) {
	int retval;
	unsigned int version;
	retval = ioctl(fd, DM_TX_IOC_G_GETOLDESTVER, &version);
#if VERBOSE
	fprintf(stderr, "oldest_ver %u retval %d\n", version, retval);
#endif
	return version;
}

unsigned int release_tx(int fd) {
	int retval;
	unsigned int handle;
	retval = ioctl(fd, DM_TX_IOC_GQ_RELEASETX, &handle);
#if VERBOSE
	fprintf(stderr, "release_tx %u retval %d\n", handle, retval);
#endif
	return handle;
}

int takeover_tx(int fd, unsigned int handle) {
	int retval;
	retval = ioctl(fd, DM_TX_IOC_SQ_TAKEOVERTX, &handle);
#if VERBOSE
	fprintf(stderr, "takeover_tx %u retval %d\n", handle, retval);
#endif
	return retval;
}

int set_cached_block(int fd, unsigned int addr) {
	int retval;
	retval = ioctl(fd, DM_TX_IOC_SQ_SETCACHEDBLOCK, &addr);
#if VERBOSE
	fprintf(stderr, "set_cached_block %u retval %d\n", addr, retval);
#endif
	return retval;
}

int set_cached_range(int fd, unsigned int addr) {
	int retval;
	retval = ioctl(fd, DM_TX_IOC_SQ_SETCACHEDRANGE, &addr);
#if VERBOSE
	fprintf(stderr, "set_cached_range %u retval %d\n", addr, retval);
#endif
	return retval;
}

// id: I/O sequence number within a TX.
// size: subblock size (= 2 ^ (size))
// start: start position in subblock granularity
// cnt: number of subblocks from start
int mark_accessed(int fd, int id, int size, int start, int cnt) {
	int retval;
	unsigned long cmd = DM_TX_ENCODE_EXTAB_CODE(id, size, start, cnt);
	retval = ioctl(fd, DM_TX_IOC_SQ_SETDIRTYBITS, &cmd);
#if VERBOSE
	fprintf(stderr, "mark_accessed %d %d %d %d retval %d\n",
		id, size, start, cnt, retval);
#endif
	return retval;
}
