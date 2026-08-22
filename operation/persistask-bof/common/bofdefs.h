#pragma once
#include <windows.h>
#include <winternl.h>

#define SECURITY_WIN32
#include <sspi.h>
#include <secext.h>

/* BOF heap helpers */
#ifdef BOF
#define intAlloc(size) (PVOID)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr)  HeapFree(GetProcessHeap(), 0, (PVOID)addr)
#else
#define intAlloc(size) malloc(size)
#define intFree(addr)  free(addr)
#endif

/* Dynamic function resolution */
#ifdef BOF

/* kernel32 */
DECLSPEC_IMPORT int    WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
DECLSPEC_IMPORT int    WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL);
DECLSPEC_IMPORT void   WINAPI KERNEL32$Sleep(DWORD);

/* advapi32 */
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);

/* secur32 */
DECLSPEC_IMPORT BOOLEAN WINAPI SECUR32$GetUserNameExA(EXTENDED_NAME_FORMAT, LPSTR, PULONG);

/* ole32 */
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID, DWORD);
DECLSPEC_IMPORT void    WINAPI OLE32$CoUninitialize(void);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
DECLSPEC_IMPORT LPVOID  WINAPI OLE32$CoTaskMemAlloc(SIZE_T);
DECLSPEC_IMPORT void    WINAPI OLE32$CoTaskMemFree(LPVOID);

/* oleaut32 */
DECLSPEC_IMPORT BSTR WINAPI OLEAUT32$SysAllocString(const OLECHAR*);
DECLSPEC_IMPORT void WINAPI OLEAUT32$SysFreeString(BSTR);
DECLSPEC_IMPORT void WINAPI OLEAUT32$VariantInit(VARIANTARG*);

/* msvcrt */
DECLSPEC_IMPORT int __cdecl MSVCRT$strcmp(const char*, const char*);

#endif
