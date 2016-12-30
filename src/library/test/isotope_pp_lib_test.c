//##define _GNU_SOURCE

#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
//#include <sys/types.h>
//#include <sys/stat.h>
#include "../isotope_pp_lib.h"

#define BLOCK_SIZE 4096

static int write_block(struct session *s, char *buffer, int val)
{
	unsigned int version = get_current_version(s);
	reset_version_range(s, 0);
	int is_success = open_snapshot(s, version);
	if (!is_success) {
		fprintf(stdout, "Failed to open snapshot %u.\n", version);
		return 0;
	}

	buffer[0] = 'a' + val;
	lseek(s->fd, 0, SEEK_SET);
	if (write(s->fd, buffer, BLOCK_SIZE) != BLOCK_SIZE) {
		fprintf(stdout, "Write failed data [%c].\n", buffer[0]);
		perror("Write failed.");
	}

	if(!(version = close_snapshot(s))) {
		fprintf(stdout, "Failed to close snapshot.\n");
	} else {
		update_lower_bound(s, 0, ISOTOPE_PP_WRITE, version);
	}
	fprintf(stdout, "[W-V(%u): \"%c\"]\t", version, buffer[0]);
	return 1;
}

static void write_test(struct session *s, char *buffer)
{
	int i;
	fprintf(stdout, "# WRITE TEST START. version -data\n");
	for (i = 0; i < 10; i++) {
		if (!write_block(s, buffer, i)) {
			return;
		}
	}
	fprintf(stdout, "\n# WRITE TEST END.\n");
}

static int read_block(struct session *s, char *buffer, unsigned int version)
{
	int is_success;
	is_success = change_snapshot(s, version);
	if (!is_success) {
		fprintf(stdout, "Snapshot change failed\n");
		return 0;
	}
	lseek(s->fd, 0, SEEK_SET);
	is_success = read(s->fd, buffer, BLOCK_SIZE);
	if (is_success != BLOCK_SIZE) {
		fprintf(stdout, "Read failed [%d]\n", is_success);
		perror("Read failed.");
		return 0;
	} else {
		fprintf(stdout, "[R-V(%u): \"%c\"]\t", version, buffer[0]);
		return 1;
	}
}

static void read_test(struct session *s, char *buffer)
{
	unsigned int i;
	int is_success;
	fprintf(stdout, "# READ TEST START. version-data\n");
	is_success = open_snapshot(s, 0);
	if (!is_success) {
		fprintf(stdout, "Failed to open snapshot.\n");
		return;
	}
	for (i = 1; i < 11; i++) {
		read_block(s, buffer, i);
	}
	if (!close_snapshot(s)) {
		fprintf(stdout, "Failed to close snapshot.\n");
	}
	fprintf(stdout, "\n# READ TEST END.\n");
}

static void version_limit_test(struct session *s)
{
	unsigned int i;
	unsigned int limit;
	fprintf(stdout, "# VERSION LIMIT TEST START. block-version-limit\n");
	for (i = 0; i < 11; i++) {
		limit = get_version_limit(s, 0, i);
		fprintf(stdout, "B(%d)-V(%u)-L(%u)\t",
			0, i, limit);
	}
	fprintf(stdout, "\n# VERSION LIMIT TEST END.\n");
}

static void probe_cost_test(struct session *s)
{
	unsigned int i;
	unsigned int upper_version;
	unsigned int version;
	fprintf(stdout, "# PROBE COST TEST START. "
		"[lower-version, upper-version]-selected-version\n");
	for (i = 1; i < 11; i++) {
		update_version_range(s, 0, i, get_current_version(s));
		version = probe_costs(s, 0);

		upper_version = get_version_limit(s, 0, version);
		update_version_range(s, 0, version, upper_version);
		fprintf(stdout, "V[%u, %u]-V(%u)\t", s->version_lower_bound,
			s->version_upper_bound, version);
	}
	fprintf(stdout, "\n# PROBE COST TEST END.\n");
}

int main(int argc, char *argv[])
{
	int i;
	int fd;
	char *buffer;
	unsigned int version;
	struct session *s;
	int is_success;
	buffer = (char *) mmap(NULL, BLOCK_SIZE, PROT_READ | PROT_WRITE,
		      MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (buffer == NULL) {
		return 1;
	}

	fd = open("/dev/mapper/dm-tx", O_DIRECT | O_RDWR);
	assert(fd > 0);

	s = init_session(fd, ISOTOPE_PP_MONOTONIC_READS, 7);
	assert(s != NULL);

	write_test(s, buffer);
	read_test(s, buffer);
	version_limit_test(s);
	probe_cost_test(s);

	close(s->fd);
	fprintf(stdout, "closed fd\n");
	close_session(s);
	fprintf(stdout, "closed session\n");
	return 0;
}
