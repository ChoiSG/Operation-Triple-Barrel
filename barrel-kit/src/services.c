/* DFR resolver — walks PEB export tables by ROR13 hash. */
#include <windows.h>
#include "tcg.h"

FARPROC resolve(DWORD mod_hash, DWORD func_hash)
{
    return findFunctionByHash(findModuleByHash(mod_hash), func_hash);
}
