#ifndef MEMORY_H
#define MEMORY_H

#define MAX_HEAP_RECORDS 32
#define MAX_SECTIONS     16

#define ALLOC_VIRTUALALLOC 0
#define ALLOC_MODULESTOMP  1

typedef struct {
    PVOID  pSection;
    SIZE_T szVirtualSection;
} ADV_SECTION_INFO;

typedef void (* FN_ADV_BOF_VP_HOOK)(LPVOID, DWORD);

typedef struct {
    HANDLE          hSacSection;
    PVOID           pSacDllBase;
    PVOID           pSacDllEntryRet;
    PVOID           pLdrDataTableEntry;
    PVOID           pStompStart;
    ADV_SECTION_INFO SacPdata;
    ADV_SECTION_INFO SacRdata;
    SIZE_T          szStomp;
    PVOID           pBackup;
    PVOID           pBackupPdata;
    PVOID           pBackupRdata;
    SIZE_T          szBackup;
    FN_ADV_BOF_VP_HOOK pfnBofVpHook;
    BOOL            bBofMapped;
} ADV_STOMP_DATA;

typedef struct {
    PVOID Data;
    PVOID Code;
    PVOID Module;
    DWORD CodeSize;
    DWORD DataSize;
} PICO_MEMORY;

typedef struct {
    PVOID  Address;
    SIZE_T Size;
} HEAP_RECORD;

typedef struct {
    HEAP_RECORD Records[MAX_HEAP_RECORDS];
    SIZE_T      Count;
} HEAP_MEMORY;

typedef struct {
    PVOID  BaseAddress;
    SIZE_T Size;
    DWORD  CurrentProtect;
    DWORD  PreviousProtect;
} MEMORY_SECTION;

typedef struct {
    PVOID          BaseAddress;
    SIZE_T         Size;
    MEMORY_SECTION Sections[MAX_SECTIONS];
    SIZE_T         Count;
} DLL_MEMORY;

typedef struct {
    PICO_MEMORY Pico;
    DLL_MEMORY  Dll;
    HEAP_MEMORY Heap;
    DWORD       DllAllocMethod;
    PVOID       SacModule;
    PVOID       AdvStompData;
} MEMORY_LAYOUT;

#endif
