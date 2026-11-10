/*
 * Fuzz the textual `<module>.sym` symbol files that `uftrace record` saves
 * next to the trace data and `uftrace report/replay` load back
 * (utils/symbol.c: check_symbol_file(), load_module_symbol_file()).
 */
#include <stdint.h>

#include "mayhem/fuzz_common.h"
#include "utils/symbol.h"

static char scratch_dir[PATH_MAX];
static char sym_path[PATH_MAX + 16];

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	mayhem_init_logging();

	if (mayhem_scratch_dir(scratch_dir, sizeof(scratch_dir), "sym") < 0)
		return 1;
	snprintf(sym_path, sizeof(sym_path), "%s/mod.sym", scratch_dir);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct uftrace_sym_info sinfo = {
		.loaded = true,
		.symdir = scratch_dir,
		.flags = SYMTAB_FL_USE_SYMFILE | SYMTAB_FL_SYMS_DIR | SYMTAB_FL_DEMANGLE,
	};
	struct uftrace_module *mod;
	char pathname[PATH_MAX];
	char build_id[BUILD_ID_STR_SIZE];
	unsigned long i;

	if (mayhem_write_file(sym_path, data, size) < 0)
		return -1;

	check_symbol_file(sym_path, pathname, sizeof(pathname), build_id, sizeof(build_id));

	/* "mod" names no ELF file, so the symbols can only come from mod.sym */
	mod = load_module_symtab(&sinfo, "mod", "");
	for (i = 0; i < mod->symtab.nr_sym; i++) {
		struct uftrace_symbol *sym = &mod->symtab.sym[i];

		find_sym(&mod->symtab, sym->addr);
		find_symname(&mod->symtab, sym->name);
	}
	unload_module_symtabs();
	return 0;
}
