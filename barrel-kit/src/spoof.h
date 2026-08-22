#ifndef SPOOF_H
#define SPOOF_H

#include <windows.h>

#define spoof_arg(x) (ULONG_PTR)(x)

typedef struct {
    PVOID     ptr;
    DWORD     ssn;
    int       argc;
    ULONG_PTR args[12];
} FUNCTION_CALL;

typedef struct {
    DWORD     ready;
    ULONG_PTR cut_retaddr;
    ULONG_PTR cut_frameaddr;
    ULONG_PTR wininet_gate_state;
    DWORD     handle_window_start;
    DWORD     handle_window_count;
    DWORD     handle_fastpath_until;
} DRAUGR_STATE;

DRAUGR_STATE * draugr_state_get(VOID);

void spoof_cut_configure_ms(VOID);
void spoof_cut_configure(ULONG_PTR retaddr, ULONG_PTR frameaddr);

ULONG_PTR spoof_call(FUNCTION_CALL * call);
ULONG_PTR spoof_call_handle(FUNCTION_CALL * call);

#endif
