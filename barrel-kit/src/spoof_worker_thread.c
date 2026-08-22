#pragma GCC optimize ("no-omit-frame-pointer")
#include <windows.h>
#include <stddef.h>
#include "spoof.h"

DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA ( LPCSTR );
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress   ( HMODULE, LPCSTR );
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetTickCount     ( VOID );
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$GetCurrentThread ( VOID );

#define HANDLE_RATE_WINDOW_MS   1000
#define HANDLE_RATE_THRESHOLD   200
#define HANDLE_FASTPATH_HOLD_MS 3000

typedef HANDLE  ( WINAPI * FN_CreateThread ) ( LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD );
typedef HANDLE  ( WINAPI * FN_CreateEventA ) ( LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR );
typedef BOOL    ( WINAPI * FN_SetEvent ) ( HANDLE );
typedef BOOL    ( WINAPI * FN_ResetEvent ) ( HANDLE );
typedef DWORD   ( WINAPI * FN_WaitForSingleObjectEx ) ( HANDLE, DWORD, BOOL );
typedef HANDLE  ( WINAPI * FN_GetProcessHeap ) ( VOID );
typedef LPVOID  ( WINAPI * FN_HeapAlloc ) ( HANDLE, DWORD, SIZE_T );
typedef BOOL    ( WINAPI * FN_OpenThreadToken ) ( HANDLE, DWORD, BOOL, PHANDLE );
typedef BOOL    ( WINAPI * FN_CloseHandle ) ( HANDLE );

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

typedef struct {
    HANDLE                    hWorker;
    HANDLE                    hRequest;
    HANDLE                    hDone;
    FN_SetEvent               set_event;
    FN_ResetEvent             reset_event;
    FN_WaitForSingleObjectEx    wait_so;
    FUNCTION_CALL *           pending_call;
    ULONG_PTR                 result;
    volatile BOOL             stop;
    BOOL                      ready;
    PVOID                     worker_proc;
} PROXY_STATE;

_Static_assert ( offsetof ( PROXY_STATE, worker_proc ) == 72, "worker_proc" );

static PROXY_STATE * proxy_state_get ( VOID )
{
    DRAUGR_STATE * ds = draugr_state_get ();
    if ( ds == NULL )
        return NULL;
    return ( PROXY_STATE * ) ( PVOID ) ds->cut_retaddr;
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

DWORD WINAPI worker_thread_proc ( LPVOID param )
{
    PROXY_STATE * st = ( PROXY_STATE * ) param;

    for ( ;; )
    {
        st->wait_so ( st->hRequest, INFINITE, FALSE );
        if ( st->stop )
            break;
        if ( st->pending_call != NULL ) {
            st->result = dispatch_call ( st->pending_call );
            st->pending_call = NULL;
        }
        st->set_event ( st->hDone );
    }
    return 0;
}

DWORD WINAPI worker_thread_entry ( LPVOID param )
    __attribute__ ( ( naked, noinline, used ) );

DWORD WINAPI worker_thread_entry ( LPVOID param )
{
    __asm__ volatile (
        ".rept 16\n"
        "nop\n"
        ".endr\n"
        "jmp qword ptr [rcx + 72]\n"
    );
}

static BOOL thread_is_impersonating ( VOID )
{
    HMODULE            adv;
    HMODULE            k32;
    FN_OpenThreadToken fn_ott;
    FN_CloseHandle     fn_close;
    HANDLE             tok;

    adv = KERNEL32$GetModuleHandleA ( "advapi32.dll" );
    k32 = KERNEL32$GetModuleHandleA ( "kernel32.dll" );
    if ( adv == NULL || k32 == NULL )
        return FALSE;

    fn_ott = ( FN_OpenThreadToken ) KERNEL32$GetProcAddress ( adv, "OpenThreadToken" );
    fn_close = ( FN_CloseHandle ) KERNEL32$GetProcAddress ( k32, "CloseHandle" );
    if ( fn_ott == NULL || fn_close == NULL )
        return FALSE;

    tok = NULL;
    if ( fn_ott ( KERNEL32$GetCurrentThread (), 0x0008, FALSE, &tok ) ) {
        fn_close ( tok );
        return TRUE;
    }
    return FALSE;
}

void spoof_cut_configure_ms ( VOID )
{
    DRAUGR_STATE * ds = draugr_state_get ();
    if ( ds == NULL )
        return;

    if ( ds->ready == 1 && ds->cut_retaddr != 0 )
        return;

    HMODULE k32 = KERNEL32$GetModuleHandleA ( "kernel32.dll" );
    if ( k32 == NULL )
        return;

    FN_CreateThread        fn_ct    = ( FN_CreateThread )        KERNEL32$GetProcAddress ( k32, "CreateThread" );
    FN_CreateEventA        fn_ce    = ( FN_CreateEventA )        KERNEL32$GetProcAddress ( k32, "CreateEventA" );
    FN_SetEvent            fn_set   = ( FN_SetEvent )            KERNEL32$GetProcAddress ( k32, "SetEvent" );
    FN_ResetEvent          fn_reset = ( FN_ResetEvent )          KERNEL32$GetProcAddress ( k32, "ResetEvent" );
    FN_WaitForSingleObjectEx fn_wait  = ( FN_WaitForSingleObjectEx ) KERNEL32$GetProcAddress ( k32, "WaitForSingleObjectEx" );
    FN_GetProcessHeap      fn_heap  = ( FN_GetProcessHeap )      KERNEL32$GetProcAddress ( k32, "GetProcessHeap" );
    FN_HeapAlloc           fn_alloc = ( FN_HeapAlloc )           KERNEL32$GetProcAddress ( k32, "HeapAlloc" );

    if ( fn_ct == NULL || fn_ce == NULL || fn_set == NULL || fn_reset == NULL ||
         fn_wait == NULL || fn_heap == NULL || fn_alloc == NULL )
        return;

    HANDLE heap = fn_heap ();
    if ( heap == NULL )
        return;

    PROXY_STATE * st = ( PROXY_STATE * ) fn_alloc ( heap, 0x00000008, sizeof ( PROXY_STATE ) );
    if ( st == NULL )
        return;

    st->hRequest = fn_ce ( NULL, FALSE, FALSE, NULL );
    st->hDone    = fn_ce ( NULL, FALSE, FALSE, NULL );
    if ( st->hRequest == NULL || st->hDone == NULL )
        return;

    st->set_event    = fn_set;
    st->reset_event  = fn_reset;
    st->wait_so      = fn_wait;
    st->pending_call = NULL;
    st->result       = 0;
    st->stop         = FALSE;
    st->worker_proc  = ( PVOID ) worker_thread_proc;

    DWORD tid = 0;
    volatile PVOID entry_base = ( PVOID ) worker_thread_entry;
    LPTHREAD_START_ROUTINE worker_entry = ( LPTHREAD_START_ROUTINE ) ( PVOID )
        ( ( ( ULONG_PTR ) entry_base + 15 ) &
          ~( ULONG_PTR ) 15 );
    st->hWorker = fn_ct ( NULL, 0, worker_entry, st, 0, &tid );
    if ( st->hWorker == NULL )
        return;

    st->ready = TRUE;

    ds->cut_retaddr        = ( ULONG_PTR ) ( PVOID ) st;
    ds->wininet_gate_state = 0;
    ds->ready              = 1;
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
    DWORD now;

    if ( state == NULL )
        return FALSE;

    now = KERNEL32$GetTickCount ();

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

    if ( state->handle_fastpath_until != 0 && ( LONG ) ( now - state->handle_fastpath_until ) < 0 )
        return TRUE;

    return FALSE;
}

ULONG_PTR spoof_call ( FUNCTION_CALL * call )
{
    if ( call == NULL || call->ptr == NULL || call->argc < 0 || call->argc > 10 )
        return 0;

    if ( thread_is_impersonating () )
        return dispatch_call ( call );

    PROXY_STATE * st = proxy_state_get ();

    if ( st == NULL || ! st->ready ) {
        spoof_cut_configure_ms ();
        st = proxy_state_get ();
    }

    if ( st != NULL && st->ready && st->hWorker != NULL ) {
        st->pending_call = call;
        st->result       = 0;
        st->set_event ( st->hRequest );
        st->wait_so ( st->hDone, INFINITE, FALSE );
        return st->result;
    }

    return dispatch_call ( call );
}

ULONG_PTR spoof_call_handle ( FUNCTION_CALL * call )
{
    if ( handle_fastpath_active () )
        return dispatch_call ( call );
    return spoof_call ( call );
}
