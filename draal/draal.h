#pragma once
#include <vector>

typedef LONG(WINAPI* NtQueryInformationProcess_t)(
    HANDLE, ULONG, PVOID, ULONG, PULONG
    );

typedef struct _PEB
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BYTE BitField;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
} PEB, * PPEB;


typedef struct _PROCESS_BASIC_INFORMATION {
    ULONG ExitStatus;
    PPEB PebBaseAddress;
    ULONG AffinityMask;
    ULONG BasePriority;
    ULONG UniqueProcessId;
    ULONG InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

int main(int argc, char* argv[]);

DWORD CreateSuspendedProcess(LPCSTR processNameIn, PROCESS_INFORMATION& processInfoOut, int argc, char* argv[]);
DWORD GetRemoteBaseImageAddressFromPEB(HANDLE processIn, void*& addressOut);
DWORD SanitizeImportAddressTable(HANDLE processIn, void* baseImageAddressIn, const std::vector<std::string>& dllsToRemove);
DWORD InjectLibrairies(HANDLE processIn, const std::vector<std::string>& dllNames);
bool IsDllBlacklisted(const char* dllName, const std::vector<std::string>& dllsToRemove);
void SetupLogger(bool enabled, const char* name);
void Cleanup();