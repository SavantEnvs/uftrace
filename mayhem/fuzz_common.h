/* Shared scaffolding for the uftrace harnesses (not part of upstream). */
#ifndef MAYHEM_FUZZ_COMMON_H
#define MAYHEM_FUZZ_COMMON_H

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "utils/utils.h"

/*
 * uftrace's pr_warn()/pr_use() write to logfp unconditionally, and the
 * globals are only set up by main(); do what main() does.
 */
static inline void mayhem_init_logging(void)
{
	logfp = stderr;
	outfp = stdout;
}

/* Create a private scratch directory under $TMPDIR (never an absolute image path). */
static inline int mayhem_scratch_dir(char *dir, size_t len, const char *tag)
{
	const char *tmp = getenv("TMPDIR");

	if (tmp == NULL || *tmp == '\0')
		tmp = "/tmp";
	if (snprintf(dir, len, "%s/uftrace-%s-XXXXXX", tmp, tag) >= (int)len)
		return -1;
	return mkdtemp(dir) == NULL ? -1 : 0;
}

/* Replace the content of @path with @data; the result depends on @data only. */
static inline int mayhem_write_file(const char *path, const uint8_t *data, size_t size)
{
	FILE *fp = fopen(path, "wb");

	if (fp == NULL)
		return -1;
	if (size && fwrite(data, 1, size, fp) != size) {
		fclose(fp);
		return -1;
	}
	return fclose(fp);
}

#endif
