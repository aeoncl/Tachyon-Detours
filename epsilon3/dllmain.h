#pragma once
#include <string>
#include "../libs/logger.h"

void WINAPI ImportMe();

void Cleanup();
BOOL OnAttach();
void OnDetach();
void SetupLogger();
DWORD GetProcessInstanceCount(LPCSTR processName);
DWORD KillProcessesByName(LPCSTR processName);
DWORD CreateBackgroundProcess(LPCSTR processNameIn, PROCESS_INFORMATION& processInfoOut);
std::string ResolveDefaultLogDirectory(DWORD& errorCode);
Logger* CreateLogger(bool enabled);