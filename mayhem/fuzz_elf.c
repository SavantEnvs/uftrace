/*
 * Fuzz uftrace's ELF reader and symbol-table loader (utils/symbol.c,
 * utils/symbol-rawelf.c): the executable/shared-object files that `uftrace
 * record`/`report` open to resolve function names.
 */
#include <stdint.h>

#include "mayhem/fuzz_common.h"
#include "utils/symbol.h"

static char scratch_dir[PATH_MAX];
static char elf_path[PATH_MAX + 16];

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	mayhem_init_logging();

	if (mayhem_scratch_dir(scratch_dir, sizeof(scratch_dir), "elf") < 0)
		return 1;
	snprintf(elf_path, sizeof(elf_path), "%s/module", scratch_dir);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct uftrace_elf_data elf;
	struct uftrace_sym_info sinfo = {
		.loaded = true,
		.symdir = scratch_dir,
		.flags = SYMTAB_FL_DEMANGLE,
	};
	struct uftrace_module *mod;
	char build_id[BUILD_ID_STR_SIZE] = "";
	char *soname;
	unsigned long i;

	if (mayhem_write_file(elf_path, data, size) < 0)
		return -1;

	/* every consumer below starts with elf_init(); a file it refuses is not an ELF object */
	if (elf_init(elf_path, &elf) < 0)
		return -1;
	elf_finish(&elf);

	soname = get_soname(elf_path);
	free(soname);

	has_dependency(elf_path, "libc.so.6");
	check_static_binary(elf_path);
	check_trace_functions(elf_path);
	read_build_id(elf_path, build_id, sizeof(build_id));

	mod = load_module_symtab(&sinfo, elf_path, build_id);
	for (i = 0; i < mod->symtab.nr_sym; i++) {
		struct uftrace_symbol *sym = &mod->symtab.sym[i];

		find_sym(&mod->symtab, sym->addr);
		find_symname(&mod->symtab, sym->name);
	}
	unload_module_symtabs();
	return 0;
}
