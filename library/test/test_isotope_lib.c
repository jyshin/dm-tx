#define _GNU_SOURCE /* for O_DIRECT */

#include <sys/mman.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <math.h>
//#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>

#include "../isotope_lib.h"

static inline off_t get_offset(off_t addr, int block_size) {
	return addr * block_size;
}

void test_get_versions(int fd) {
	unsigned int version;
	version = get_curr_ver(fd);
	version = get_oldest_ver(fd);
}

void test_set_cached(int fd, unsigned int addr) {
	set_cached_block(fd, addr);
}

void test_release_takeover_tx(int fd, char *page, int block_size) {
	int i;
	int addrs_size = 8;
	off_t addrs[] = {0, 1, 2, 3, 4, 5, 6, 7};
	int ch = 'i';
	unsigned int handle;
	begin_tx(fd);

	for (i = 0; i < addrs_size; i++) {
		page[0] = ch + i;
		pwrite(fd, page, block_size, get_offset(addrs[i], block_size));
		handle = release_tx(fd);
		takeover_tx(fd, handle);
	}

	end_tx(fd);

}

void test_subblock_tx(int fd, char *page, int block_size) {
	int i;
	int addrs_size = 8;
	off_t addrs[] = {0, 1, 2, 3, 4, 5, 6, 7};
	int ch = '1';

	begin_tx(fd);

	for (i = 0; i < addrs_size; i++) {
		memset(page, 0, block_size);
		page[i * 512] = ch + i;
		pwrite(fd, page, block_size, get_offset(0, block_size));
		mark_accessed(fd, i, 9, i, 1);
	}

	end_tx(fd);

	begin_tx(fd);
	pread(fd, page, block_size, get_offset(0, block_size));
	end_tx(fd);

	fprintf(stdout, "Read: ");
	for (i = 0; i < addrs_size; i++) {
		fprintf(stdout, "%c", page[i * 512]);
	}
	fprintf(stdout, "\n");

}

void test_read_only_tx(int fd, char *page, int block_size) {
	int i;
	int addrs_size = 8;
	off_t addrs[] = {0, 1, 2, 3, 4, 5, 6, 7};

	begin_tx(fd);

	fprintf(stdout, "Read: ");
	for (i = 0; i < addrs_size; i++) {
		pread(fd, page, block_size, get_offset(addrs[i], block_size));
		fprintf(stdout, "%c", page[0]);
	}
	fprintf(stdout, "\n");

	end_tx(fd);
}

void test_write_only_tx(int fd, char *page, int block_size) {
	int i;
	int addrs_size = 8;
	off_t addrs[] = {0, 1, 2, 3, 4, 5, 6, 7};
	int ch = 'A';

	begin_tx(fd);

	for (i = 0; i < addrs_size; i++) {
		page[0] = ch + i;
		pwrite(fd, page, block_size, get_offset(addrs[i], block_size));
	}

	end_tx(fd);
}

void test_read_write_tx(int fd, char *page, int block_size) {
	int i;
	int addrs_size = 8;
	off_t addrs[] = {0, 1, 2, 3, 4, 5, 6, 7};
	int ch = 'a';

	begin_tx(fd);

	for (i = 0; i < addrs_size; i++) {
		page[0] = ch + i;
		pwrite(fd, page, block_size, get_offset(addrs[i], block_size));
	}
	fprintf(stdout, "Read: ");
	for (i = 0; i < addrs_size; i++) {
		pread(fd, page, block_size, get_offset(addrs[i], block_size));
		fprintf(stdout, "%c", page[0]);
	}
	fprintf(stdout, "\n");

	end_tx(fd);
}

void test_abort_tx(int fd) {
	begin_tx(fd);
	abort_tx(fd);
	end_tx(fd);
}

int main(int argc, char *argv[])
{
	char *page;
	int i;
	int opt;
	int fd;
	ssize_t byte_cnt;
	int block_size = 4096;

	while ((opt = getopt(argc, argv, "hb:")) != -1) {
		switch (opt) {
		case 'b':
			block_size = strtoul(optarg, NULL, 0);
			break;
		case 'h':
		default:
			fprintf(stdout, "Usage: %s [-b io size]\n", argv[0]);
			exit(EXIT_SUCCESS);
		}
	}

	printf("START\n");

	page = mmap(NULL, block_size, PROT_READ | PROT_WRITE,
                    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	assert (page != MAP_FAILED);

	fd = open("/dev/mapper/dm-tx", O_DIRECT | O_RDWR);
        assert (fd >= 0);

	test_write_only_tx(fd, page, block_size);
	test_read_only_tx(fd, page, block_size);
	test_read_write_tx(fd, page, block_size);
	test_read_only_tx(fd, page, block_size);
	test_abort_tx(fd);
	test_subblock_tx(fd, page, block_size);
	test_release_takeover_tx(fd, page, block_size);
	test_get_versions(fd);

	munmap(page, block_size);
	close(fd);

	return 0;
}

