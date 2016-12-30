#include <linux/slab.h>
#include <linux/vmalloc.h>
#include "lru-cache.h"

#define SUCCESS 0
#define FAIL (-1)

#define LRU_CACHE_PREFIX "lru-map: "

//#define LRU_CACHE_DEBUG
#ifdef LRU_CACHE_DEBUG
#define DPRINTK( s, arg... ) printk(LRU_CACHE_PREFIX s "\n", ##arg)
#else
#define DPRINTK( s, arg... )
#endif

// LRU list operations
static inline void lru_cache_list_remove(struct lru_entry *entry)
{
	list_del(&entry->lru);
}

static inline void lru_cache_list_add(struct lru_cache *map,
				      struct lru_entry *new)
{
	list_add(&new->lru, &map->lru_list);
}

// RB tree operations
static inline struct lru_entry * lru_cache_rb_tree_search(struct lru_cache *map,
							  sector_t block)
{
	struct rb_node *node = map->rb_tree.rb_node;

	while (node) {
		struct lru_entry * entry = container_of(node, struct lru_entry,
							rb);
		if (entry->block < block) {
			node = node->rb_right;
		} else if (entry->block > block) {
			node = node->rb_left;
		} else {
			return entry;
		}
	}
	return NULL;
}

static int lru_cache_rb_tree_add(struct lru_cache *map, struct lru_entry *new)
{
	struct rb_node **node = &(map->rb_tree.rb_node);
	struct rb_node *parent = NULL;

	while (*node) {
		struct lru_entry *entry = container_of(*node, struct lru_entry,
						       rb);
		parent = *node;
		if (entry->block < new->block) {
			node = &((*node)->rb_right);
		} else if (entry->block > new->block) {
			node = &((*node)->rb_left);
		} else {
			return FAIL;
		}
	}

	rb_link_node(&new->rb, parent, node);
	rb_insert_color(&new->rb, &map->rb_tree);

	DPRINTK("added to rb tree vaddr %llu",
		(unsigned long long) new->block);

	return SUCCESS;
}

// Cache operations 
inline static struct lru_entry * lru_cache_find(struct lru_cache *map,
					 sector_t block)
{
	return lru_cache_rb_tree_search(map, block);
}


inline static void lru_cache_update(struct lru_cache *map,
				    struct lru_entry *entry)
{
	lru_cache_list_remove(entry);
	lru_cache_list_add(map, entry);
}

inline static void lru_cache_remove(struct lru_cache *map,
				    struct lru_entry *entry)
{
	list_del(&entry->lru);
	rb_erase(&entry->rb, &map->rb_tree);
}

static struct lru_entry * lru_cache_evict(struct lru_cache *map)
{
	struct lru_entry *tail = NULL;

	tail = container_of(map->lru_list.prev, struct lru_entry, lru);
	lru_cache_remove(map, tail);

	BUG_ON(tail == NULL);

	return tail;
}

static int lru_cache_add(struct lru_cache *map, struct lru_entry *new)
{
	if (lru_cache_rb_tree_add(map, new) == FAIL) {
		printk(LRU_CACHE_PREFIX
		       "vaddr %llu already exists\n",
		       (unsigned long long) new->block);
		BUG_ON(true);
	}
	lru_cache_list_add(map, new);

	return SUCCESS;
}

int lru_cache_is_hit(struct lru_cache *map, sector_t block)
{
	unsigned long flags;
	spin_lock_irqsave(&map->lock, flags);
	if(lru_cache_find(map, block)) {
		DPRINTK("hit addr %llu", (unsigned long long) block);
		spin_unlock_irqrestore(&map->lock, flags);
		return 1;
	} else {
		DPRINTK("miss addr %llu", (unsigned long long) block);
		spin_unlock_irqrestore(&map->lock, flags);
		return 0;
	}
}

int lru_cache_read(struct lru_cache *map, sector_t block, void *page,
		     struct bio *bio)
{
	struct lru_entry *entry = NULL;
	unsigned long flags;

	spin_lock_irqsave(&map->lock, flags);
	entry = lru_cache_find(map, block);

	DPRINTK("read addr %llu", (unsigned long long) block);

	if (entry) {
		map->stats.read_hit++;
		lru_cache_update(map, entry);
		if (page != NULL) {
			memcpy(page, entry->page, PAGE_SIZE);
		} else {
			int i;
			struct bio_vec *bvec;
			char *addr = entry->page
				+ ((bio->bi_sector & 0x00000007) << 9);
			bio_for_each_segment(bvec, bio, i) {
				unsigned long bflags;
				char *bio_addr = bvec_kmap_irq(bvec, &bflags);
				memcpy(bio_addr, addr, bvec->bv_len);
				bvec_kunmap_irq(bio_addr, &bflags);
				addr += bvec->bv_len;
			}
		}
		spin_unlock_irqrestore(&map->lock, flags);
		DPRINTK("read_hit block %llu page %p",
			(unsigned long long) block, entry->page);

		return 0;
	} else {
		map->stats.read_miss++;
		spin_unlock_irqrestore(&map->lock, flags);

		DPRINTK("read_miss block %llu", (unsigned long long) block);
		return 1;
	}
}

static void copy_to_entry_page(struct lru_entry *entry, void *page,
			       struct bio *bio)
{
	int i;
	struct bio_vec *bvec;
	char *addr;

	if (page) {
		memcpy(entry->page, page, PAGE_SIZE);
	} else {
		addr = entry->page + ((bio->bi_sector & 0x00000007) << 9);
		bio_for_each_segment(bvec, bio, i) {
			unsigned long flags;
			char *bio_addr = bvec_kmap_irq(bvec, &flags);
			memcpy(addr, bio_addr, bvec->bv_len);
			bvec_kunmap_irq(bio_addr, &flags);
			addr += bvec->bv_len;
		}
	}
}

void lru_cache_write(struct lru_cache *map, sector_t block, void *page,
		     struct bio *bio, int is_read_miss)
{
	struct lru_entry *entry;
	unsigned long flags;

	spin_lock_irqsave(&map->lock, flags);
	entry = lru_cache_find(map, block);

	DPRINTK("write addr %llu", (unsigned long long) block);

	if (entry) {
		if (!is_read_miss) {
			map->stats.write_hit++;
		}
		lru_cache_update(map, entry);
		copy_to_entry_page(entry, page, bio);
		DPRINTK("write_hit block %llu page %p",
			(unsigned long long) block, entry->page);
	} else {
		if (!is_read_miss) {
			map->stats.write_miss++;
		}

		if (map->size >= map->capacity) {
			entry = lru_cache_evict(map);
			DPRINTK("evicted block %llu",
				(unsigned long long) entry->block);

			entry->block = block;
			copy_to_entry_page(entry, page, bio);

			DPRINTK("write_miss block %llu",
				(unsigned long long) block);
		} else {
			DPRINTK("write miss and cache not full");
			entry = &map->l_map[map->size];
			map->size++;

			entry->block = block;
			copy_to_entry_page(entry, page, bio);

			DPRINTK("using free addr %p", entry->page);
		}
		lru_cache_add(map, entry);
	}
	spin_unlock_irqrestore(&map->lock, flags);
}

int lru_cache_init(struct lru_cache **result, size_t capacity_blk, int policy)
{
	int i;
	int err = -ENOMEM;

	struct lru_cache *map = kmalloc(sizeof(*map), GFP_KERNEL);
	if (!map) {
		printk(LRU_CACHE_PREFIX "kmalloc lru_cache failed\n");
		err = -ENOMEM;
		goto fail_and_out;
	}

	spin_lock_init(&map->lock);
	INIT_LIST_HEAD(&map->lru_list);
	map->rb_tree = RB_ROOT;

	map->size = 0;
	map->policy = ((policy == 0) ? LRU_CACHE_POLICY_READONLY :
		LRU_CACHE_POLICY_READWRITE);
	map->capacity = capacity_blk;
	map->l_map = vmalloc(sizeof(*map->l_map) * map->capacity);
	if(!map->l_map) {
		printk(LRU_CACHE_PREFIX "vmalloc lru_cache->l_map failed\n");
		err = -ENOMEM;
		goto free_map_and_out;
	}

	for (i = 0; i < map->capacity; i++) {
		map->l_map[i].page = (void *) __get_free_page(GFP_NOIO);
		if (!map->l_map[i].page) {
			printk(LRU_CACHE_PREFIX "page alloc failed\n");
			err = -ENOMEM;
			goto free_page_and_l_map_and_out;
		}
	}
	printk(LRU_CACHE_PREFIX "memory allocated for cache\n");

	*result = map;
	return 0;

free_page_and_l_map_and_out:
	for (i = 0; i < map->capacity; i++) {
		if(map->l_map[i].page) {
			free_page((unsigned long) map->l_map[i].page);
			map->l_map[i].page = NULL;
		}
	}
	vfree(map->l_map);
free_map_and_out:
	kfree(map);
fail_and_out:
	return err;
}


void lru_cache_destroy(struct lru_cache **map)
{
	int i;
	if ((*map) == NULL)
		return;
	for (i = 0; i < (*map)->capacity; i++) {
		if((*map)->l_map[i].page) {
			free_page((unsigned long) (*map)->l_map[i].page);
			(*map)->l_map[i].page = NULL;
		}
	}
	vfree((*map)->l_map);
	kfree(*map);
}
