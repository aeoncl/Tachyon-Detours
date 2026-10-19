#pragma once
#include <vector>

int main(int argc, char* argv[]);

DWORD CreateDebuggedProcess(LPCSTR processNameIn, PROCESS_INFORMATION& processInfoOut, int argc, char* argv[]);
DWORD GetBaseImageAddressViaDebugEvent(const PROCESS_INFORMATION& processInfoIn, void*& baseImageAddressOut);
DWORD ResumeDebuggedProcessAndDetach(const PROCESS_INFORMATION& processInfoIn);
DWORD SanitizeImportAddressTable(HANDLE processIn, void* baseImageAddressIn, const std::vector<std::string>& dllsToRemove);
DWORD InjectLibrairies(HANDLE processIn, const std::vector<std::string>& dllNames);
bool IsDllBlacklisted(const char* dllName, const std::vector<std::string>& dllsToRemove);
void SetupLogger(bool enabled, const char* name);
void Cleanup();