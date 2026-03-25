#pragma once

void WINAPI ImportMe();

void Cleanup();
BOOL OnAttach();
void OnDetach();
void SetupLogger();
DWORD GetProcessInstanceCount(LPCSTR processName);
DWORD KillProcessesByName(LPCSTR processName);
DWORD CreateBackgroundProcess(LPCSTR processNameIn, PROCESS_INFORMATION& processInfoOut);