/* Fuzz uftrace's built-in C++/Rust symbol demangler (utils/demangle*.c). */
#include <stdint.h>

#include "mayhem/fuzz_common.h"
#include "utils/demangle.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	mayhem_init_logging();
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *name;
	char *demangled;

	/* demangle() takes a C string: NUL-terminate a private copy */
	name = malloc(size + 1);
	if (name == NULL)
		return -1;
	memcpy(name, data, size);
	name[size] = '\0';

	/* the default demangler (DEMANGLE_SIMPLE) also dispatches "_R..." to the Rust v0 parser */
	demangled = demangle(name);
	free(demangled);
	free(name);
	return 0;
}
