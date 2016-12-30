#ifndef LRU_CACHE_H
#define LRU_CACHE_H

#include <linux/bio.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/types.h>
#include <linux/spinlock.h>

struct lru_entry {
	sector_t block;
	void *page;
	struct list_head lru;
	struct rb_node rb;
};

struct lru_cache_stats {
	unsigned long long read_miss, write_miss, read_hit, write_hit,
		r_clash, w_clash;
};

enum LRU_CACHE_POLICY {
	LRU_CACHE_POLICY_READONLY,
	LRU_CACHE_POLICY_READWRITE,
};

struct lru_cache {
	spinlock_t lock;
	int policy;

	size_t size;
	size_t capacity;

	struct list_head lru_list;
	struct rb_root rb_tree;

	struct lru_entry *l_map;

	struct lru_cache_stats stats;
};

int lru_cache_is_hit(struct lru_cache *map, sector_t block);
int lru_cache_read(struct lru_cache *map, sector_t v_block, void *page,
		     struct bio *bio);
void lru_cache_write(struct lru_cache *map, sector_t v_block, void *page,
		     struct bio *bio, int is_read_miss);

int lru_cache_init(struct lru_cache **result, size_t capacity_blk, int policy);
void lru_cache_destroy(struct lru_cache **map);

#endif
