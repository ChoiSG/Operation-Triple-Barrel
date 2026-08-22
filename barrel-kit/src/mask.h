#ifndef MASK_H
#define MASK_H

#include "memory.h"

void mask_memory(MEMORY_LAYOUT * memory, BOOL mask);
BOOL kraken_wait(MEMORY_LAYOUT * memory, HANDLE handle,
                 DWORD milliseconds, PDWORD result);

#endif
