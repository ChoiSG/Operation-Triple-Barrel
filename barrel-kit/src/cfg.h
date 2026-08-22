#ifndef CFG_H
#define CFG_H

#include "memory.h"

BOOL cfg_enabled();
BOOL bypass_cfg(PVOID address);
BOOL enable_cfg_for_address(PVOID address);
BOOL enable_cfg_for_region(PVOID base, SIZE_T size);
BOOL enable_cfg_for_dll(DLL_MEMORY * dll_memory);

#endif
