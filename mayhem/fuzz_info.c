/*
 * Fuzz the `info` file of a uftrace data directory (cmds/info.c:
 * read_uftrace_info() + process_uftrace_info()), which `uftrace info/report/
 * replay/dump` parse out of a directory that may come from another machine.
 *
 * Input is a complete `info` file: struct uftrace_file_header followed by the
 * text records selected by hdr.info_mask.
 */
#include <stdint.h>

#include "mayhem/fuzz_common.h"
#include "uftrace.h"

static char scratch_dir[PATH_MAX];
static char info_path[PATH_MAX + 16];

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	mayhem_init_logging();

	if (mayhem_scratch_dir(scratch_dir, sizeof(scratch_dir), "info") < 0)
		return 1;
	snprintf(info_path, sizeof(info_path), "%s/info", scratch_dir);
	return 0;
}

static void discard_info(void *unused, const char *fmt, ...)
{
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct uftrace_data handle = {};
	struct uftrace_opts opts = {
		.dirname = scratch_dir,
	};
	struct uftrace_file_header hdr;
	int ret;

	/* open_info_file() exits on a short header, a wrong magic or an unknown version */
	if (size < sizeof(hdr))
		return -1;
	memcpy(&hdr, data, sizeof(hdr));
	if (memcmp(hdr.magic, UFTRACE_MAGIC_STR, UFTRACE_MAGIC_LEN))
		return -1;
	if (hdr.version < UFTRACE_FILE_VERSION_MIN || hdr.version > UFTRACE_FILE_VERSION)
		return -1;

	if (mayhem_write_file(info_path, data, size) < 0)
		return -1;

	handle.fp = fopen(info_path, "rb");
	if (handle.fp == NULL)
		return -1;
	if (fseek(handle.fp, sizeof(hdr), SEEK_SET) < 0) {
		fclose(handle.fp);
		return -1;
	}
	handle.hdr = hdr;
	handle.dirname = scratch_dir;

	ret = read_uftrace_info(hdr.info_mask, &handle);
	if (ret == 0)
		process_uftrace_info(&handle, &opts, discard_info, NULL);

	clear_uftrace_info(&handle.info);
	fclose(handle.fp);
	return ret == 0 ? 0 : -1;
}
