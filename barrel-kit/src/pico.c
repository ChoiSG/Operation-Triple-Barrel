/*
 * pico — PICO runtime that lives alongside the loaded DLL.
 *
 * Hooks key APIs via Crystal Palace's addhook mechanism:
 *   - Sleep/WFSO    : mask/unmask memory around sleep
 *   - ExitThread    : cleanup memory before exit
 *   - HeapAlloc/Free: track allocations for sleep masking
 *   - GetProcAddress: resolve IAT hooks before real GPA
 *
 * All API calls go through spoof_call() so a future spoof module
 * can add stack spoofing without changing this code.
 */
#include <windows.h>
#include "memory.h"
#include "mask.h"
#include "spoof.h"
#include "cleanup.h"
#include "cfg.h"
#include "tcg.h"

MEMORY_LAYOUT g_memory;
static DRAUGR_STATE g_draugr_state;

DRAUGR_STATE * draugr_state_get(VOID)
{
    return &g_draugr_state;
}

DECLSPEC_IMPORT VOID   WINAPI KERNEL32$Sleep(DWORD);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$WaitForSingleObject(HANDLE, DWORD);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$WaitForSingleObjectEx(HANDLE, DWORD, BOOL);
DECLSPEC_IMPORT VOID   WINAPI KERNEL32$ExitThread(DWORD);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapReAlloc(HANDLE, DWORD, LPVOID, SIZE_T);
DECLSPEC_IMPORT LONG   NTAPI  NTDLL$NtProtectVirtualMemory(HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR);

/*
 * _GetProcAddress — hook-aware GetProcAddress.
 * Checks the Crystal Palace hook table first. If the function is hooked
 * (via addhook in the spec), returns the hook. Otherwise falls through
 * to the real GetProcAddress.
 */
FARPROC WINAPI _GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    /* ordinal imports bypass the hook table */
    if ((ULONG_PTR) lpProcName >> 16 == 0)
        return GetProcAddress(hModule, lpProcName);

    FARPROC result = __resolve_hook(ror13hash(lpProcName));
    if (result != NULL)
        return result;

    return GetProcAddress(hModule, lpProcName);
}

/*
 * setup_hooks — called by the PIC loader after PicoLoad.
 * Overrides GetProcAddress so ProcessImports resolves hooked APIs
 * to our hook functions instead of the real ones.
 */
void setup_hooks(IMPORTFUNCS * funcs)
{
    funcs->GetProcAddress = (__typeof__(GetProcAddress) *) _GetProcAddress;
}

/*
 * setup_memory — called by the PIC loader after DLL is fully loaded.
 * Stores the memory layout so hooks can mask/free regions later.
 */
void setup_memory(MEMORY_LAYOUT * layout)
{
    if (layout == NULL)
        return;

    __movsb((unsigned char *) &g_memory, (const unsigned char *) layout, sizeof(g_memory));

    /* mark PICO code as a valid CFG target */
    if (g_memory.Pico.Code != NULL && g_memory.Pico.CodeSize != 0)
        enable_cfg_for_region(g_memory.Pico.Code, g_memory.Pico.CodeSize);

    if (g_memory.Dll.BaseAddress != NULL)
        enable_cfg_for_dll(&g_memory.Dll);

    spoof_cut_configure_ms();
}

/* forward declarations for hooked APIs */
VOID   WINAPI _Sleep(DWORD);
DWORD  WINAPI _WaitForSingleObject(HANDLE, DWORD);
VOID   WINAPI _ExitThread(DWORD);
LPVOID WINAPI _HeapAlloc(HANDLE, DWORD, SIZE_T);
BOOL   WINAPI _HeapFree(HANDLE, DWORD, LPVOID);
LPVOID WINAPI _HeapReAlloc(HANDLE, DWORD, LPVOID, SIZE_T);

/*
 * install_inline_hook — write a 12-byte absolute JMP at target to redirect to hook.
 *   mov rax, <hook>   ; 48 B8 <8-byte addr>
 *   jmp rax            ; FF E0
 */
static void install_inline_hook(PVOID target, PVOID hook)
{
    PVOID  page = target;
    SIZE_T sz   = 12;
    ULONG  old;

    if (NTDLL$NtProtectVirtualMemory((HANDLE)(LONG_PTR) -1, &page, &sz, PAGE_EXECUTE_READWRITE, &old) != 0)
        return;

    BYTE * p = (BYTE *) target;
    p[0] = 0x48; p[1] = 0xB8;
    *(ULONG_PTR *)(p + 2) = (ULONG_PTR) hook;
    p[10] = 0xFF; p[11] = 0xE0;

    page = target; sz = 12;
    NTDLL$NtProtectVirtualMemory((HANDLE)(LONG_PTR) -1, &page, &sz, old, &old);
}

/*
 * patch_dispatch — called by PIC loader AFTER DllMain.
 *
 * Installs inline hooks on KERNEL32!WaitForSingleObject so ALL callers
 * (IAT, PEB-walked dispatch tables, dynamic resolution) get intercepted.
 */
void patch_dispatch(MEMORY_LAYOUT * layout)
{
    (void) layout;

    HMODULE k32 = KERNEL32$GetModuleHandleA("kernel32.dll");
    if (!k32) return;

    PVOID real_wfso = (PVOID) GetProcAddress(k32, "WaitForSingleObject");
    if (real_wfso)
        install_inline_hook(real_wfso, (PVOID) _WaitForSingleObject);
}

/* --- hooked APIs --- */

static DWORD short_wait_floor(DWORD milliseconds)
{
    if (milliseconds < 1500 && milliseconds < 30)
        return 30;
    return milliseconds;
}

VOID WINAPI _Sleep(DWORD dwMilliseconds)
{
    DWORD effectiveMilliseconds = short_wait_floor(dwMilliseconds);
    FUNCTION_CALL call = { 0 };
    call.ptr     = (PVOID)(KERNEL32$Sleep);
    call.argc    = 1;
    call.args[0] = spoof_arg(effectiveMilliseconds);

    /* only mask when actually sleeping (>= 1.5s), not during short polls */
    if (dwMilliseconds >= 1500)
        mask_memory(&g_memory, TRUE);

    spoof_call(&call);

    if (dwMilliseconds >= 1500)
        mask_memory(&g_memory, FALSE);
}

DWORD WINAPI _WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds)
{
    DWORD effectiveMilliseconds = short_wait_floor(dwMilliseconds);
    DWORD result;

    if (dwMilliseconds >= 3500 && dwMilliseconds != INFINITE &&
        kraken_wait(&g_memory, hHandle, dwMilliseconds, &result))
        return result;

    FUNCTION_CALL call = { 0 };
    call.ptr     = (PVOID)(KERNEL32$WaitForSingleObjectEx);
    call.argc    = 3;
    call.args[0] = spoof_arg(hHandle);
    call.args[1] = spoof_arg(effectiveMilliseconds);
    call.args[2] = spoof_arg((ULONG_PTR) FALSE);

    return (DWORD) spoof_call(&call);
}

VOID WINAPI _ExitThread(DWORD dwExitCode)
{
    cleanup_memory(&g_memory);

    FUNCTION_CALL call = { 0 };
    call.ptr     = (PVOID)(KERNEL32$ExitThread);
    call.argc    = 1;
    call.args[0] = spoof_arg(dwExitCode);
    spoof_call(&call);
}

LPVOID WINAPI _HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)
{
    FUNCTION_CALL call = { 0 };
    call.ptr     = (PVOID)(KERNEL32$HeapAlloc);
    call.argc    = 3;
    call.args[0] = spoof_arg(hHeap);
    call.args[1] = spoof_arg(dwFlags);
    call.args[2] = spoof_arg(dwBytes);

    LPVOID result = (LPVOID) spoof_call(&call);

    /* track large allocations so mask_memory can encrypt them during sleep */
    if (dwBytes >= 256 && result != NULL && g_memory.Heap.Count < MAX_HEAP_RECORDS) {
        g_memory.Heap.Records[g_memory.Heap.Count].Address = result;
        g_memory.Heap.Records[g_memory.Heap.Count].Size    = dwBytes;
        g_memory.Heap.Count++;
    }

    return result;
}

LPVOID WINAPI _HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes)
{
    FUNCTION_CALL call = { 0 };
    call.ptr     = (PVOID)(KERNEL32$HeapReAlloc);
    call.argc    = 4;
    call.args[0] = spoof_arg(hHeap);
    call.args[1] = spoof_arg(dwFlags);
    call.args[2] = spoof_arg(lpMem);
    call.args[3] = spoof_arg(dwBytes);

    LPVOID result = (LPVOID) spoof_call(&call);

    if (result) {
        BOOL found = FALSE;
        for (int i = 0; i < (int) g_memory.Heap.Count; i++) {
            if (g_memory.Heap.Records[i].Address == lpMem) {
                g_memory.Heap.Records[i].Address = result;
                g_memory.Heap.Records[i].Size    = dwBytes;
                found = TRUE;
                break;
            }
        }
        if (!found && dwBytes >= 256 && g_memory.Heap.Count < MAX_HEAP_RECORDS) {
            g_memory.Heap.Records[g_memory.Heap.Count].Address = result;
            g_memory.Heap.Records[g_memory.Heap.Count].Size    = dwBytes;
            g_memory.Heap.Count++;
        }
    }

    return result;
}

BOOL WINAPI _HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem)
{
    FUNCTION_CALL call = { 0 };
    call.ptr     = (PVOID)(KERNEL32$HeapFree);
    call.argc    = 3;
    call.args[0] = spoof_arg(hHeap);
    call.args[1] = spoof_arg(dwFlags);
    call.args[2] = spoof_arg(lpMem);

    BOOL result = (BOOL) spoof_call(&call);

    if (result) {
        for (int i = 0; i < (int) g_memory.Heap.Count; i++) {
            if (g_memory.Heap.Records[i].Address == lpMem) {
                int last = g_memory.Heap.Count - 1;
                g_memory.Heap.Records[i] = g_memory.Heap.Records[last];
                g_memory.Heap.Records[last].Address = NULL;
                g_memory.Heap.Records[last].Size    = 0;
                g_memory.Heap.Count--;
                break;
            }
        }
    }

    return result;
}
