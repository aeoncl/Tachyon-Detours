#pragma once
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
DWORD CreateMsnMsgrProcess(LPPROCESS_INFORMATION processInfo);
DWORD GetRemoteBaseImageAddressFromPEB(HANDLE processIn, void*& addressOut);
DWORD SanitizeImportAddressTable(HANDLE processIn, void* baseImageAddressIn);
DWORD InjectLibrary(HANDLE processIn, LPCSTR dllName);
bool IsDllBlacklisted(const char* dllName);
void SetupLogger();
void Cleanup();