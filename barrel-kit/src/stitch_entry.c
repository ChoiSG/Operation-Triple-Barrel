#include <windows.h>

DWORD WINAPI wininet_gate_worker_entry ( LPVOID param )
    __attribute__ ( ( naked, noinline, used ) );

DWORD WINAPI wininet_gate_worker_entry ( LPVOID param )
{
    __asm__ volatile (
        ".rept 16\n"
        "nop\n"
        ".endr\n"
        "jmp qword ptr [rcx + 120]\n"
    );
}
