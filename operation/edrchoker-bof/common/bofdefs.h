// bofdefs.h (EDRChoker-BOF)
//
// Dynamic Function Resolution (DFR) declarations for all Win32 APIs used by
// the BOF. The COFF loader resolves LIBRARY$Function symbols at staging time.
//
// WMI CLSIDs/IIDs are hand-declared as static const GUIDs to avoid needing
// wbemuuid.lib (unlinkable from a BOF).

#pragma once

#define _WIN32_DCOM

#include <winsock2.h>
#include <windows.h>
#include <objbase.h>
#include <oleauto.h>
#include <wbemidl.h>
#include <tlhelp32.h>

/* WMI CLSIDs / IIDs. */

// 4590F811-1D3A-11D0-891F-00AA004B2E24
static const CLSID CLSID_WbemLocator_ = {
    0x4590F811, 0x1D3A, 0x11D0,
    {0x89, 0x1F, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24}
};

// DC12A687-737F-11CF-884D-00AA004B2E24
static const IID IID_IWbemLocator_ = {
    0xDC12A687, 0x737F, 0x11CF,
    {0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24}
};

/* ---------- KERNEL32 ---------- */
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$Process32FirstW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$Process32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT int     WINAPI KERNEL32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetLastError(VOID);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$GetCurrentProcess(VOID);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$GetCurrentThread(VOID);
DECLSPEC_IMPORT HLOCAL  WINAPI KERNEL32$LocalAlloc(UINT uFlags, SIZE_T uBytes);
DECLSPEC_IMPORT HLOCAL  WINAPI KERNEL32$LocalFree(HLOCAL hMem);

/* ---------- ADVAPI32 (integrity check) ---------- */
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$OpenThreadToken(HANDLE ThreadHandle, DWORD DesiredAccess, BOOL OpenAsSelf, PHANDLE TokenHandle);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$GetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);
DECLSPEC_IMPORT PUCHAR  WINAPI ADVAPI32$GetSidSubAuthorityCount(PSID pSid);
DECLSPEC_IMPORT PDWORD  WINAPI ADVAPI32$GetSidSubAuthority(PSID pSid, DWORD nSubAuthority);

/* ---------- OLE32 (COM apparatus) ---------- */
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID pvReserved, DWORD dwCoInit);
DECLSPEC_IMPORT void    WINAPI OLE32$CoUninitialize(void);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeSecurity(PSECURITY_DESCRIPTOR pSecDesc, LONG cAuthSvc, SOLE_AUTHENTICATION_SERVICE* asAuthSvc, void* pReserved1, DWORD dwAuthnLevel, DWORD dwImpLevel, void* pAuthList, DWORD dwCapabilities, void* pReserved3);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID* ppv);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoSetProxyBlanket(IUnknown* pProxy, DWORD dwAuthnSvc, DWORD dwAuthzSvc, OLECHAR* pServerPrincName, DWORD dwAuthnLevel, DWORD dwImpLevel, RPC_AUTH_IDENTITY_HANDLE pAuthInfo, DWORD dwCapabilities);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateGuid(GUID* pguid);
DECLSPEC_IMPORT int     WINAPI OLE32$StringFromGUID2(REFGUID rguid, LPOLESTR lpsz, int cchMax);

/* ---------- OLEAUT32 (BSTR + VARIANT) ---------- */
DECLSPEC_IMPORT BSTR    WINAPI OLEAUT32$SysAllocString(const OLECHAR* psz);
DECLSPEC_IMPORT void    WINAPI OLEAUT32$SysFreeString(BSTR bstrString);
DECLSPEC_IMPORT UINT    WINAPI OLEAUT32$SysStringLen(BSTR pbstr);
DECLSPEC_IMPORT void    WINAPI OLEAUT32$VariantInit(VARIANTARG* pvarg);
DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$VariantClear(VARIANTARG* pvarg);

/* ---------- MSVCRT ---------- */
DECLSPEC_IMPORT void*    __cdecl MSVCRT$malloc(size_t _Size);
DECLSPEC_IMPORT void     __cdecl MSVCRT$free(void* _Memory);
DECLSPEC_IMPORT void*    __cdecl MSVCRT$memcpy(void* _Dst, const void* _Src, size_t _Size);
DECLSPEC_IMPORT void*    __cdecl MSVCRT$memset(void* _Dst, int _Val, size_t _Size);
DECLSPEC_IMPORT int      __cdecl MSVCRT$memcmp(const void* _Buf1, const void* _Buf2, size_t _Size);
DECLSPEC_IMPORT int      __cdecl MSVCRT$strcmp(const char* _Str1, const char* _Str2);
DECLSPEC_IMPORT int      __cdecl MSVCRT$_stricmp(const char* _Str1, const char* _Str2);
DECLSPEC_IMPORT size_t   __cdecl MSVCRT$strlen(const char* _Str);
DECLSPEC_IMPORT size_t   __cdecl MSVCRT$wcslen(const wchar_t* _Str);
DECLSPEC_IMPORT int      __cdecl MSVCRT$wcscmp(const wchar_t* _Str1, const wchar_t* _Str2);
DECLSPEC_IMPORT int      __cdecl MSVCRT$_wcsicmp(const wchar_t* _Str1, const wchar_t* _Str2);
DECLSPEC_IMPORT int      __cdecl MSVCRT$_wcsnicmp(const wchar_t* _Str1, const wchar_t* _Str2, size_t _MaxCount);
DECLSPEC_IMPORT int      __cdecl MSVCRT$_snprintf(char* _Dst, size_t _Count, const char* _Format, ...);
DECLSPEC_IMPORT int      __cdecl MSVCRT$_snwprintf(wchar_t* _Dst, size_t _Count, const wchar_t* _Format, ...);
