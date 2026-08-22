#pragma once
#include <windows.h>

#ifdef BOF

/* kernel32 */
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);

/* rpcrt4 */
DECLSPEC_IMPORT RPC_STATUS WINAPI RPCRT4$RpcBindingFromStringBindingW(RPC_WSTR StringBinding, RPC_BINDING_HANDLE *Binding);
DECLSPEC_IMPORT RPC_STATUS WINAPI RPCRT4$RpcStringBindingComposeW(RPC_WSTR ObjUuid, RPC_WSTR ProtSeq, RPC_WSTR NetworkAddr, RPC_WSTR Endpoint, RPC_WSTR Options, RPC_WSTR *StringBinding);
DECLSPEC_IMPORT RPC_STATUS WINAPI RPCRT4$RpcBindingSetAuthInfoExW(RPC_BINDING_HANDLE Binding, RPC_WSTR ServerPrincName, unsigned long AuthnLevel, unsigned long AuthnSvc, RPC_AUTH_IDENTITY_HANDLE AuthIdentity, unsigned long AuthzSvc, RPC_SECURITY_QOS *SecurityQOS);
DECLSPEC_IMPORT RPC_STATUS WINAPI RPCRT4$RpcBindingFree(RPC_BINDING_HANDLE *Binding);
DECLSPEC_IMPORT RPC_STATUS WINAPI RPCRT4$RpcStringFreeW(RPC_WSTR *String);
DECLSPEC_IMPORT CLIENT_CALL_RETURN RPC_VAR_ENTRY RPCRT4$NdrClientCall2(PMIDL_STUB_DESC pStubDescriptor, PFORMAT_STRING pFormat, ...);

/* msvcrt */
WINBASEAPI int __cdecl MSVCRT$swprintf_s(wchar_t *buffer, size_t sizeOfBuffer, const wchar_t *format, ...);
WINBASEAPI wchar_t *__cdecl MSVCRT$wcscat_s(wchar_t *strDestination, size_t numberOfElements, const wchar_t *strSource);
WINBASEAPI void* __cdecl MSVCRT$malloc(size_t size);
WINBASEAPI void __cdecl MSVCRT$free(void* memblock);

#endif
