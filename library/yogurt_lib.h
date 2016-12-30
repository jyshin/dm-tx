#ifndef __YOGURT_LIB_H__
#define __YOGURT_LIB_H__
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <map>

enum read_semantics {
	YOGURT_BOUNDED_STALENESS=0,
	YOGURT_MONOTONIC_READS=1,
	YOGURT_READ_MY_WRITES=2,
	YOGURT_FIXED=3,
};
enum read_write {
	YOGURT_READ = 0,
	YOGURT_WRITE = 1,
};

struct session {
	int read_semantic;
	int limit;
	int fd;

	int querying_budget;

	int session_start;
	int version_upper_bound;
	int version_lower_bound;

	std::map<uint64_t, uint32_t> version_map;

	int nr_memory_reads;
	int nr_ssd_reads;
	int nr_busy_ssd_reads;
	int nr_busy_disk_reads;

};

unsigned int get_current_version(struct session *s);
unsigned int probe_costs(struct session *s, unsigned int block);
unsigned int get_version_limit(struct session *s, unsigned int block,
			       unsigned int version);
// called before probing data
void reset_version_range(struct session *s, uint64_t key);
// called between probe calls
void update_version_range(struct session *s, uint64_t key, unsigned int lower,
			  unsigned int upper);
// call after closing snapshot
void update_lower_bound(struct session *s, uint64_t key, int rw,
			unsigned int lower);
int open_snapshot(struct session *s, unsigned int version);
int change_snapshot(struct session *s, unsigned int version);
unsigned int close_snapshot(struct session *s);
struct session * init_session(int fd, int semantics, int limit);
void close_session(struct session *s);

#endif
