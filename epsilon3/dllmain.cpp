#include "pch.h"
#include "dllmain.h"
#include "logger.h"
#include <Psapi.h>
#pragma comment(lib, "psapi.lib")

Logger* LOGGER = NULL;
PROCESS_INFORMATION PROCESS_INFO = {};
LPCSTR PROCESS_TO_RUN_NAME = "tachyon.exe";
LPCSTR CURRENT_PROCESS_NAME = "msnmsgr.exe";

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        return OnAttach();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        OnDetach();
        break;
    }
    return TRUE;
}

void WINAPI ImportMe() {};

BOOL OnAttach() {
    SetupLogger();

    DWORD count = GetProcessInstanceCount(PROCESS_TO_RUN_NAME);
    if (count > 0) {
        LOGGER->LogLine("%s process already running, aborting creation.", PROCESS_TO_RUN_NAME);
        return true;
    }

    LOGGER->LogLine("Starting %s...", PROCESS_TO_RUN_NAME);
    DWORD result = CreateBackgroundProcess(PROCESS_TO_RUN_NAME, PROCESS_INFO);
    if (result != ERROR_SUCCESS) {
        LOGGER->LogLine("Killing %s...", CURRENT_PROCESS_NAME);
        return false;
    }

    return true;
}

void OnDetach() {
    SetupLogger();
    DWORD count = GetProcessInstanceCount(CURRENT_PROCESS_NAME);
    if (count <= 1) {
        KillProcessesByName(PROCESS_TO_RUN_NAME);
    }
    Cleanup();
}

void SetupLogger() {
    if (LOGGER == NULL) {
        LOGGER = new Logger("C:\\temp\\epsilon3.txt", true);
    }
}

void Cleanup() {
    CloseHandle(PROCESS_INFO.hProcess);
    CloseHandle(PROCESS_INFO.hThread);

    if (LOGGER != nullptr) {
        delete LOGGER;
    }
}


DWORD GetProcessInstanceCount(LPCSTR processName) {
    DWORD pids[1024];
    DWORD bytesReturned;
    DWORD count = 0;

    if (!EnumProcesses(pids, sizeof(pids), &bytesReturned)) {
        LOGGER->LogLine("Fatal: EnumProcesses failed: 0x%x", GetLastError());
        return 0;
    }

    DWORD pidCount = bytesReturned / sizeof(DWORD);
    for (DWORD i = 0; i < pidCount; i++) {
        HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pids[i]);
        if (h == NULL) continue;

        char name[MAX_PATH] = {};
        GetModuleBaseNameA(h, NULL, name, MAX_PATH);
        CloseHandle(h);

        if (_stricmp(name, processName) == 0)
            count++;
    }

    return count;
}


DWORD KillProcessesByName(LPCSTR processName) {
    DWORD pids[1024];
    DWORD bytesReturned;

    if (!EnumProcesses(pids, sizeof(pids), &bytesReturned)) {
        DWORD error = GetLastError();
        LOGGER->LogLine("Fatal: EnumProcesses failed: 0x%x", GetLastError());
        return error;
    }

    DWORD pidCount = bytesReturned / sizeof(DWORD);
    for (DWORD i = 0; i < pidCount; i++) {
        DWORD pid = pids[i];
        HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (h == NULL) continue;

        char name[MAX_PATH] = {};
        GetModuleBaseNameA(h, NULL, name, MAX_PATH);

        if (_stricmp(name, processName) == 0) {
            if (AttachConsole(pid)) {
                GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid);
                FreeConsole();
            }
        }

        CloseHandle(h);
    }

    return ERROR_SUCCESS;
}

DWORD CreateBackgroundProcess(LPCSTR processNameIn, PROCESS_INFORMATION& processInfoOut) {
    STARTUPINFOA startupInfo = {};
    startupInfo.cb = sizeof(STARTUPINFOA);

    BOOL result = CreateProcessA(
        processNameIn,
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW,
        NULL,
        NULL,
        &startupInfo,
        &processInfoOut
    );

    if (!result) {
        DWORD error = GetLastError();
        LOGGER->LogLine("Could not create %s process. CreateProcessA failed with error Code: 0x%x", processNameIn, error);
        return error;
    }

    LOGGER->LogLine("%s started (pid %lu)", processNameIn, processInfoOut.dwProcessId);
    return ERROR_SUCCESS;
}