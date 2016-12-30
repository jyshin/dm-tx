#include <sys/ioctl.h>
#include <string.h>

#include "yogurt_lib.h"
#include "../src/dm-tx-ioctl.h"


unsigned int get_current_version(struct session *s)
{
	unsigned int current_version;
	ioctl(s->fd, DM_TX_IOC_G_GETCURVER, &current_version);
	return current_version;
}

unsigned int probe_costs(struct session *s, unsigned int block)
{
	int i;
	unsigned int min_cost = 0xFFFFFFFF;
	unsigned int min_version;
	struct addr_versions avs;

	if (s->read_semantic == YOGURT_FIXED) {
		return 0;
	}

	memset(&avs, 0xFF, sizeof(avs));

	avs.addr = block;

	if (s->version_upper_bound == s->version_lower_bound)
		return s->version_lower_bound;

	s->querying_budget = DM_TX_COST_QUERY_LIMIT;

	if (s->version_upper_bound - s->version_lower_bound + 1
	    < s->querying_budget) {
		s->querying_budget = s->version_upper_bound
			- s->version_lower_bound + 1;
	}
	for (i = 0; i < s->querying_budget && i < DM_TX_COST_QUERY_LIMIT;
	     i++) {
		unsigned int version = s->version_lower_bound + i *
			(s->version_upper_bound - s->version_lower_bound) /
			(s->querying_budget - 1);
		avs.versions[i] = version;
	}
	if(!ioctl(s->fd, DM_TX_IOC_TGQ_GETCOST, &avs)) {
		for (i = 0; i < s->querying_budget
		     && i < DM_TX_COST_QUERY_LIMIT; i++) {
			if (avs.versions[i] < min_cost) {
				min_cost = avs.versions[i];
				min_version = s->version_lower_bound + i *
					(s->version_upper_bound -
					 s->version_lower_bound) /
					(s->querying_budget - 1);
			}
		}
	}
	return min_version;
}

unsigned int get_version_limit(struct session *s, unsigned int block,
			       unsigned int version)
{
	struct addr_version av;
	av.addr = block;
	av.version = version;
	if(!ioctl(s->fd, DM_TX_IOC_TGQ_GETVERLIMIT, &av)) {
		return av.version;
	}
	return 0;
}

void reset_version_range(struct session *s, uint64_t key)
{
	std::map<uint64_t, uint32_t>::iterator it;
	if (s->read_semantic == YOGURT_FIXED) {
		return;
	}
	s->version_upper_bound = get_current_version(s);
	if (s->read_semantic == YOGURT_BOUNDED_STALENESS) {
		s->version_lower_bound = s->version_upper_bound - s->limit;
		return;
	}
	it = s->version_map.find(key);
	if (it == s->version_map.end()) {
		s->version_lower_bound = s->session_start;
		s->version_map.insert(std::pair<uint64_t, uint32_t>
				      (key, s->session_start));
	} else {
		s->version_lower_bound = s->version_map[key];
	}
}

void update_version_range(struct session *s, uint64_t key, unsigned int lower,
			  unsigned int upper)
{
	if (s->read_semantic == YOGURT_FIXED) {
		return;
	}
	if (s->read_semantic == YOGURT_BOUNDED_STALENESS) {
		s->version_lower_bound = s->version_upper_bound - s->limit;
	} else if (s->read_semantic == YOGURT_MONOTONIC_READS ||
		   s->read_semantic == YOGURT_READ_MY_WRITES) {
		s->version_lower_bound = lower;
	}
	s->version_upper_bound = upper;
}

void update_lower_bound(struct session *s, uint64_t key, int rw,
			unsigned int lower)
{
	if (s->read_semantic == YOGURT_FIXED) {
		return;
	}
	if (s->read_semantic == YOGURT_MONOTONIC_READS
	    && rw == YOGURT_READ) {
		s->version_map[key] = lower;
	} else if (s->read_semantic == YOGURT_READ_MY_WRITES
		   && rw == YOGURT_WRITE) {
		s->version_map[key] = lower;
	}
}

int open_snapshot(struct session *s, unsigned int version)
{
	if (!ioctl(s->fd, DM_TX_IOC_Q_BEGINFTX)) {
		if (version > 0 && s->read_semantic != YOGURT_FIXED) {
			if (!ioctl(s->fd, DM_TX_IOC_SQ_OPENVER, &version)) {
				return 1; // success
			}
		}
		return 1;
	}
	return 0; // failure;
}

int change_snapshot(struct session *s, unsigned int version)
{
	if (s->read_semantic == YOGURT_FIXED) {
		return 1;
	}
	if (!ioctl(s->fd, DM_TX_IOC_SQ_OPENVER, &version)) {
		return 1;
	}
	return 0;
}

unsigned int close_snapshot(struct session *s)
{
	unsigned int version;
	int result = ioctl(s->fd, DM_TX_IOC_GQ_ENDFTX, &version);
	if (!result) {
		return version; // success;	
	}
	return 0; // failure;
}

struct session * init_session(int fd, int semantics, int limit)
{
	struct session *s = (struct session *) malloc(sizeof(*s));
	if (s == NULL) {
		fprintf(stderr, "malloc to session failed\n");
		return NULL;
	}
	memset(s, 0, sizeof(*s));

	s->read_semantic = semantics;
	s->limit = limit;
	s->fd = fd;
	s->querying_budget = DM_TX_COST_QUERY_LIMIT;
	s->version_upper_bound = get_current_version(s);
	s->version_lower_bound = s->version_upper_bound;
	s->session_start = s->version_upper_bound;
	s->version_map.clear();
	return s;
}

void close_session(struct session *s)
{
	s->version_map.clear();
	free(s);
}
