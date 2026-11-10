/*
 * Fuzz uftrace's filter / trigger / argument-spec / retval-spec parsers
 * (utils/filter.c, utils/argspec.c) against a fixed in-memory symbol table.
 *
 * Input: byte 0 selects the parser, pattern type, ABI and arch; the rest is
 * the option string as given to `uftrace -F/-T/-A/-R/-C/-H`.
 */
#include <stdint.h>

#include "mayhem/fuzz_common.h"
#include "utils/filter.h"
#include "utils/symbol.h"

/* same shape as the fixture of uftrace's own unit tests (utils/filter.c) */
static struct uftrace_symbol syms[] = {
	{ 0x1000, 0x1000, ST_GLOBAL_FUNC, "foo::foo" },
	{ 0x2000, 0x1000, ST_GLOBAL_FUNC, "foo::bar" },
	{ 0x3000, 0x1000, ST_GLOBAL_FUNC, "foo::baz1" },
	{ 0x4000, 0x1000, ST_GLOBAL_FUNC, "foo::baz2" },
	{ 0x5000, 0x1000, ST_GLOBAL_FUNC, "foo::baz3" },
	{ 0x6000, 0x1000, ST_GLOBAL_FUNC, "foo::~foo" },
	{ 0x21000, 0x1000, ST_PLT_FUNC, "malloc" },
	{ 0x22000, 0x1000, ST_PLT_FUNC, "free" },
};
/* uftrace_module ends in a flexible name[]: give it real storage, as xzalloc() does in load_module_symtab() */
static union {
	struct uftrace_module mod;
	char raw[sizeof(struct uftrace_module) + 16];
} fixture;
/* same for uftrace_mmap::libname[], read by find_map_by_name() */
static union {
	struct uftrace_mmap map;
	char raw[sizeof(struct uftrace_mmap) + 16];
} map_fixture;
#define map map_fixture.map

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	mayhem_init_logging();

	fixture.mod.symtab.sym = syms;
	fixture.mod.symtab.nr_sym = ARRAY_SIZE(syms);
	fixture.mod.dinfo.loaded = true;
	strcpy(fixture.mod.name, "foo");

	map.mod = &fixture.mod;
	strcpy(map.libname, "/usr/bin/foo");
	map.start = 0x0;
	map.end = 0x24000;
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static const enum uftrace_pattern_type ptypes[] = { PATT_SIMPLE, PATT_REGEX, PATT_GLOB };
	static const enum uftrace_cpu_arch arches[] = { UFT_CPU_X86_64, UFT_CPU_AARCH64,
							UFT_CPU_I386, UFT_CPU_ARM };
	struct uftrace_sym_info sinfo = {
		.loaded = true,
		.maps = &map,
		.exec_map = &map,
	};
	struct uftrace_triggers_info triggers = {
		.root = RB_ROOT,
	};
	struct uftrace_filter_setting setting = {};
	struct uftrace_trigger tr = {};
	unsigned char sel;
	char *str;

	if (size < 1)
		return -1;

	sel = data[0];
	setting.ptype = ptypes[(sel >> 3) % ARRAY_SIZE(ptypes)];
	setting.arch = arches[(sel >> 5) % ARRAY_SIZE(arches)];
	setting.lp64 = sel & 0x80 ? false : true;
	setting.allow_kernel = true;

	str = malloc(size);
	if (str == NULL)
		return -1;
	memcpy(str, data + 1, size - 1);
	str[size - 1] = '\0';

	switch (sel & 7) {
	case 0:
		uftrace_setup_filter(str, &sinfo, &triggers, &setting);
		break;
	case 1:
		uftrace_setup_trigger(str, &sinfo, &triggers, &setting);
		break;
	case 2:
		uftrace_setup_argument(str, &sinfo, &triggers, &setting);
		break;
	case 3:
		uftrace_setup_retval(str, &sinfo, &triggers, &setting);
		break;
	case 4:
		uftrace_setup_caller_filter(str, &sinfo, &triggers, &setting);
		break;
	default:
		uftrace_setup_hide_filter(str, &sinfo, &triggers, &setting);
		break;
	}

	uftrace_match_filter(0x2000, &triggers, &tr);
	uftrace_match_filter(0x21000, &triggers, &tr);
	uftrace_count_filter(&triggers, 0);

	uftrace_cleanup_triggers(&triggers);
	free(str);
	return 0;
}
