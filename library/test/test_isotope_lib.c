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

	get_curr_ver(fd);
	get_oldest_ver(fd);

	begin_tx(fd);
	printf("Tx begin\n");

	int ch = '1';

	for (i = 0; i < 10; i++) {

		lseek(fd, 0, SEEK_SET);
		page[0] = (char) (ch+i);
		printf("write starts at %d with %c\n", 0, page[0]);

		byte_cnt = write(fd, page, block_size);
		assert (byte_cnt == block_size);

                assert (byte_cnt >= 0);
		if (byte_cnt == 0) {
			fprintf(stdout, "End of file\n");
			break;
		}
	}
	mark_accessed(fd, 5, 9, 1, 1);
	mark_accessed(fd, 6, 9, 0, 1);
	mark_accessed(fd, 7, 9, 4, 4);
	mark_accessed(fd, 8, 9, 6, 1);
	mark_accessed(fd, 9, 9, 7, 1);

	ch = getchar();

	end_tx(fd);

	lseek(fd, 0, SEEK_SET);
	byte_cnt = read(fd, page, block_size);
	assert (byte_cnt >= 0);
	printf("after tx read %c\n", page[0]);

	close(fd);
	return 0;
}

