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

DWORD CreateSuspendedProcess(LPCSTR processNameIn, PROCESS_INFORMATION& processInfoOut);
DWORD GetRemoteBaseImageAddressFromPEB(HANDLE processIn, void*& addressOut);
DWORD SanitizeImportAddressTable(HANDLE processIn, void* baseImageAddressIn);
DWORD InjectLibrairies(HANDLE processIn, std::vector<LPCSTR> dllNames);
bool IsDllBlacklisted(const char* dllName);
void SetupLogger();
void Cleanup();