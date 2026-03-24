// draal.cpp : Ce fichier contient la fonction 'main'. L'exécution du programme commence et se termine à cet endroit.
//
#define WIN32_LEAN_AND_MEAN 

#include <iostream>
#include <windows.h>
#include "logger.h"
#include "draal.h"
#include <detours.h>
#include <vector>
#include <TlHelp32.h>
#pragma comment(lib, "detours")
#include <Psapi.h>
#pragma comment(lib, "psapi.lib")


const char* DLL_BLACKLIST[] = {
	"escargot.dll",
	"reroute.dll",
	"zathras.dll",
	NULL
};


Logger* LOGGER = nullptr;
PROCESS_INFORMATION mainProcessInfo = {};
PROCESS_INFORMATION supportingProcessInfo = {};
HANDLE supportingProcessMutex = NULL;
HANDLE job = NULL;


int main(int argc, char* argv[])
{
	SetupLogger();

	DWORD jobResult = SetupJobObject(job);
	if (jobResult != ERROR_SUCCESS) {
		Cleanup();
		return jobResult;
	}

	HANDLE alreadyExistHandle = GetProcessHandleByName("msnmsgr.exe");
	if (alreadyExistHandle != NULL) {
		LOGGER->LogLine("%s is already running, aborting.", "msnmsgr.exe");
		CloseHandle(alreadyExistHandle);
		Cleanup();
		return ERROR_ALREADY_EXISTS;
	}

	DWORD createMainProcessResult = CreateMainProcess("msnmsgr.exe", mainProcessInfo);
	if (createMainProcessResult != ERROR_SUCCESS) {
		Cleanup();
		return createMainProcessResult;
	}

	DWORD jobAssignMain = AddProcessToJob(mainProcessInfo.hProcess, job);
	if (jobAssignMain != ERROR_SUCCESS) {
		Cleanup();
		return jobAssignMain;
	}

	void* baseImageAddress = nullptr;
	DWORD baseImageAddressResult = GetRemoteBaseImageAddressFromPEB(mainProcessInfo.hProcess, baseImageAddress);
	if (baseImageAddressResult != ERROR_SUCCESS) {
		Cleanup();
		return baseImageAddressResult;
	}

	LOGGER->LogLine("Got base Image Addr: 0x%x", baseImageAddress);

	DWORD sanitizeIATResult = SanitizeImportAddressTable(mainProcessInfo.hProcess, baseImageAddress);
	if (baseImageAddressResult != ERROR_SUCCESS) {
		Cleanup();
		return sanitizeIATResult;
	}

	DWORD injectResult = InjectLibrary(mainProcessInfo.hProcess, "zathras.dll");
	if (injectResult != ERROR_SUCCESS) {
		Cleanup();
		return injectResult;
	}

	DWORD createSupportingProcessResult = CreateProcessIfNotRunning("tachyon.exe", supportingProcessInfo, supportingProcessMutex);
	if (createSupportingProcessResult != ERROR_SUCCESS && createSupportingProcessResult != ERROR_ALREADY_EXISTS) {
		LOGGER->LogLine("Fatal: could not start %s. ", "tachyon.exe");
		TerminateProcess(mainProcessInfo.hProcess, 0);
		Cleanup();
		return createSupportingProcessResult;
	}

	DWORD jobAssignSupport = AddProcessToJob(supportingProcessInfo.hProcess, job);
	if (jobAssignSupport != ERROR_SUCCESS) {
		Cleanup();
		return jobAssignSupport;
	}

	DWORD resumeResult = ResumeThread(mainProcessInfo.hThread);
	if (resumeResult == -1) {
		LOGGER->LogLine("Fatal: Failed to ResumeThread: 0x%x", GetLastError());
		Cleanup();
		return resumeResult;
	}

	if (createSupportingProcessResult != ERROR_ALREADY_EXISTS) {
		DWORD monitorResult = MonitorProcesses(mainProcessInfo.hProcess, supportingProcessInfo.hProcess);
		if (monitorResult != ERROR_SUCCESS) {
			TerminateProcess(mainProcessInfo.hProcess, 1);
			TerminateProcess(supportingProcessInfo.hProcess, 1);
		}
	}

	Cleanup();
	return EXIT_SUCCESS;
}

DWORD SetupJobObject(HANDLE& jobOut) {
	HANDLE job = CreateJobObjectA(NULL, NULL);
	if (job == NULL) {
		DWORD error = GetLastError();
		LOGGER->LogLine("Fatal: CreateJobObject failed: 0x%x", error);
		return error;
	}

	JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = {};
	jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

	if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli))) {
		CloseHandle(job);
		DWORD error = GetLastError();
		LOGGER->LogLine("Fatal: SetInformationJobObject failed: 0x%x", error);
		return error;
	}

	jobOut = job;
	LOGGER->LogLine("Job object created successfully.");
	return ERROR_SUCCESS;
}

DWORD AddProcessToJob(HANDLE hProcess, HANDLE job) {
	if (!AssignProcessToJobObject(job, hProcess)) {
		DWORD error = GetLastError();
		LOGGER->LogLine("Fatal: AssignProcessToJobObject failed: 0x%x", error);
		return error;
	}
	return ERROR_SUCCESS;
}

HANDLE GetProcessHandleByName(LPCSTR processName) {
	DWORD pids[1024];
	DWORD bytesReturned;

	if (!EnumProcesses(pids, sizeof(pids), &bytesReturned)) {
		LOGGER->LogLine("Fatal: EnumProcesses failed: 0x%x", GetLastError());
		return NULL;
	}

	DWORD count = bytesReturned / sizeof(DWORD);
	for (DWORD i = 0; i < count; i++) {
		HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pids[i]);
		if (h == NULL) continue;

		char name[MAX_PATH] = {};
		GetModuleBaseNameA(h, NULL, name, MAX_PATH);

		if (_stricmp(name, processName) == 0) {
			LOGGER->LogLine("GetProcessHandleByName: found '%s' (pid %lu)", name, pids[i]);
			return h;
		}

		CloseHandle(h);
	}

	LOGGER->LogLine("GetProcessHandleByName: '%s' not found", processName);
	return NULL;
}

DWORD MonitorProcesses(HANDLE p1, HANDLE p2) {
	LOGGER->LogLine("Monitoring processes...");

	HANDLE handles[2] = { p1, p2 };

	DWORD result = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
	if (result == WAIT_FAILED) {
		DWORD error = GetLastError();
		LOGGER->LogLine("Fatal: Cannot monitor processes. WaitForMultipleObjects failed with error: 0x%x", error);
		return error;
	}

	HANDLE other = (result == WAIT_OBJECT_0) ? p2 : p1;
	LOGGER->LogLine("One process has died. Killing the other one.");

	TerminateProcess(other, 1);
	return ERROR_SUCCESS;
}

DWORD CreateProcessIfNotRunning(LPCSTR processNameIn, PROCESS_INFORMATION& processInfoOut, HANDLE& mutexOut) {
	HANDLE alreadyExistHandle = GetProcessHandleByName(processNameIn);
	if (alreadyExistHandle != NULL) {
		LOGGER->LogLine("%s is already running, skipping launch.", processNameIn);
		CloseHandle(alreadyExistHandle);
		return ERROR_ALREADY_EXISTS;
	}

	std::string mutexName = std::string("Global\\") + processNameIn + "SingleInstance";

	// Check if already running by using a mutex
	HANDLE mutex = CreateMutexA(NULL, TRUE, mutexName.c_str());
	if (mutex == NULL) {
		DWORD error = GetLastError();
		LOGGER->LogLine("Fatal: Could not create single instance mutex. Error: 0x%x", GetLastError());
		return error;
	}

	if (GetLastError() == ERROR_ALREADY_EXISTS) {
		LOGGER->LogLine("%s is already running, skipping launch.", processNameIn);
		CloseHandle(mutex);
		return ERROR_ALREADY_EXISTS;
	}

	STARTUPINFOA startupInfo = {};
	startupInfo.cb = sizeof(STARTUPINFOA);

	BOOL createProcessResult = CreateProcessA(
		processNameIn,
		NULL, NULL, NULL,
		FALSE, CREATE_NO_WINDOW,
		NULL, NULL,
		&startupInfo,
		&processInfoOut
	);

	if (!createProcessResult) {
		DWORD error = GetLastError();
		LOGGER->LogLine("Fatal: Could not create %s process. Error: 0x%x", processNameIn, error);
		ReleaseMutex(mutex);
		CloseHandle(mutex);
		return error;
	}

	LOGGER->LogLine("%s started (pid %lu)", processNameIn, processInfoOut.dwProcessId);
	mutexOut = mutex;
	return ERROR_SUCCESS;
}

DWORD CreateMainProcess(LPCSTR processNameIn, PROCESS_INFORMATION& processInfoOut) {
	STARTUPINFOA startupInfo = {};
	startupInfo.cb = sizeof(STARTUPINFOA);

	BOOL result = CreateProcessA(
		processNameIn,
		NULL,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED,
		NULL,
		NULL,
		&startupInfo,
		&processInfoOut
	);

	if (!result) {
		DWORD error = GetLastError();
		LOGGER->LogLine("Could not create msnmsgr.exe process. Error Code: 0x%x", error);
		return error;
	}

	LOGGER->LogLine("msnmsgr.exe started suspended (pid %lu)", processInfoOut.dwProcessId);
	return ERROR_SUCCESS;
}

DWORD GetRemoteBaseImageAddressFromPEB(HANDLE processIn, void*& baseImageAddressOut)
{
	NtQueryInformationProcess_t NtQueryInformationProcess = (NtQueryInformationProcess_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
	if (NtQueryInformationProcess == nullptr) {
		LOGGER->LogLine("Fatal: Could not find NtQueryInformationProcess in ntdll.dll");
		return ERROR_APP_INIT_FAILURE;
	}

	PROCESS_BASIC_INFORMATION pbi = {};
	LONG ntQueryResult = NtQueryInformationProcess(processIn, 0, &pbi, sizeof(pbi), NULL);
	if (ntQueryResult != 0) {
		LOGGER->LogLine("Fatal: NtQueryInformationProcess failed with NT_ERROR: 0x%x", ntQueryResult);
		return ntQueryResult;
	}

	PEB peb = {};
	BOOL readProcessMemoryResult = ReadProcessMemory(processIn, pbi.PebBaseAddress, &peb, sizeof(peb), NULL);
	if (!readProcessMemoryResult) {
		DWORD error = GetLastError();
		LOGGER->LogLine("Fatal: Could not extract ImageBaseAddress from PEB. ReadProcessMemory failed with error: 0x%x", error);
		return error;
	}

	baseImageAddressOut = peb.ImageBaseAddress;
	return ERROR_SUCCESS;
}

DWORD SanitizeImportAddressTable(HANDLE processIn, void* baseImageAddressIn) {
	IMAGE_DOS_HEADER dos_header;
	BOOL readDosResult = ReadProcessMemory(processIn, baseImageAddressIn, &dos_header, sizeof(dos_header), NULL);
	if (!readDosResult) {
		DWORD error = GetLastError();
		LOGGER->LogLine("Fatal: Could not read DOS Header. ReadProcessMemory failed with error: 0x%x", error);
		return error;
	}

	IMAGE_NT_HEADERS nt_headers;
	void* nt_headers_addr = (char*)baseImageAddressIn + dos_header.e_lfanew;
	BOOL readNtResult = ReadProcessMemory(processIn, nt_headers_addr, &nt_headers, sizeof(nt_headers), NULL);
	if (!readNtResult) {
		DWORD error = GetLastError();
		LOGGER->LogLine("Fatal: Could not read NT Header. ReadProcessMemory failed with error: 0x%x", error);
		return error;
	}

	IMAGE_DATA_DIRECTORY imageDataDirectory = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (imageDataDirectory.Size == 0) {
		//We know that our target binary has an import table so, fail here.
		LOGGER->LogLine("Fatal: Could not find Import Directory in NT Header");
		return ERROR_APP_INIT_FAILURE;
	}

	void* currentImportDescriptorAddress = (char*)baseImageAddressIn + imageDataDirectory.VirtualAddress;
	IMAGE_IMPORT_DESCRIPTOR currentImportDescriptor;

	DWORD passedCount = 0;
	for (;;) {
		BOOL readImportDescriptorResult = ReadProcessMemory(processIn, currentImportDescriptorAddress, &currentImportDescriptor, sizeof(currentImportDescriptor), NULL);
		if (!readImportDescriptorResult) {
			DWORD error = GetLastError();
			LOGGER->LogLine("Fatal: Could not read Import Descriptor. ReadProcessMemory failed with error: 0x%x", error);
			return error;
		}

		if (currentImportDescriptor.Name == 0 && currentImportDescriptor.FirstThunk == 0)
			break;

		char dllName[256] = {};
		void* dllNameAddress = (char*)baseImageAddressIn + currentImportDescriptor.Name;
		BOOL readDllNameResult = ReadProcessMemory(processIn, dllNameAddress, dllName, sizeof(dllName) - 1, NULL);
		if (!readDllNameResult) {
			DWORD error = GetLastError();
			LOGGER->LogLine("Fatal: Could not read DllName in Import Descriptor. ReadProcessMemory failed with error: 0x%x", error);
			return error;
		}

		if (IsDllBlacklisted(dllName)) {
			LOGGER->LogLine("Stripping DLL: %s imageDataDirectorySize: %d passedCount: %d", dllName, imageDataDirectory.Size, passedCount);

			DWORD imageDataDirectoryCount = imageDataDirectory.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
			SIZE_T remainingBytes = (imageDataDirectoryCount - passedCount) * sizeof(IMAGE_IMPORT_DESCRIPTOR);

			IMAGE_IMPORT_DESCRIPTOR zeroed = { 0 };
			BOOL removeDllResult = WriteProcessMemory(processIn, currentImportDescriptorAddress, &zeroed, sizeof(zeroed), NULL);
			if (!removeDllResult) {
				DWORD error = GetLastError();
				LOGGER->LogLine("Fatal: Could not remove Import Descriptor for DLL %s. WriteProcessMemory failed with error: 0x%x", dllName, error);
				return error;
			}

			if (remainingBytes != 0) {
				LOGGER->LogLine("Shifting remaining entries... remainingBytes: %d", remainingBytes);
				//Shifting remaining entries

				void* nextDescriptorAddress = (char*)currentImportDescriptorAddress + sizeof(IMAGE_IMPORT_DESCRIPTOR);
				std::vector<BYTE> buffer(remainingBytes);
				BOOL readRemainingImageDataDirectoryResult = ReadProcessMemory(processIn, nextDescriptorAddress, buffer.data(), remainingBytes, NULL);
				if (!readRemainingImageDataDirectoryResult) {
					DWORD error = GetLastError();
					LOGGER->LogLine("Fatal: Could not read remaining Image Data Directory to shift. ReadProcessMemory failed with error: 0x%x", error);
					return error;
				}

				LOGGER->LogLine("Buffer size %d...", buffer.size());

				BOOL writeRemainingImageDataDirectoryResult = WriteProcessMemory(processIn, currentImportDescriptorAddress, buffer.data(), remainingBytes, NULL);
				if (!writeRemainingImageDataDirectoryResult) {
					DWORD error = GetLastError();
					LOGGER->LogLine("Fatal: Could not write remaining Image Data Directory to shift. WriteProcessMemory failed with error: 0x%x", error);
					return error;
				}

				//Replay current offset because we shifted
				continue;
			}
		}
		else {
			LOGGER->LogLine("Keeping DLL: %s", dllName);
		}

		passedCount++;
		currentImportDescriptorAddress = (char*)currentImportDescriptorAddress + sizeof(IMAGE_IMPORT_DESCRIPTOR);

	}

	return ERROR_SUCCESS;
}

DWORD InjectLibrary(HANDLE processIn, LPCSTR dllName) {

	LOGGER->LogLine("Injecting DLL: %s...", dllName);

	BOOL result = DetourUpdateProcessWithDll(processIn, &dllName, 1);
	if (!result) {
		DWORD error = GetLastError();
		LOGGER->LogLine("Fatal: Could not inject %s in process. DetourUpdateProcessWithDll failed with error: 0x%x", dllName, error);
		return error;
	}

	return ERROR_SUCCESS;
}


bool IsDllBlacklisted(const char* dllName) {
	for (int i = 0; DLL_BLACKLIST[i] != NULL; i++) {
		if (_stricmp(dllName, DLL_BLACKLIST[i]) == 0)
			return true;
	}
	return false;
}


void SetupLogger() {
	LOGGER = new Logger("C:\\temp\\draal.txt", true);

	LOGGER->LogLine("          A   A   A");
	LOGGER->LogLine("         | | | | | |");
	LOGGER->LogLine("       __| |_| |_| |___nnnnnn_____----____-===-----");
	LOGGER->LogLine("  _    __/--| |-| |-|_|---~~~-------~~~---\\==/~~\\.");
	LOGGER->LogLine("O=|-|OOOOO--<=X===X===X=>-| | |-----| | |>  HHK   |");
	LOGGER->LogLine("  ~    ~~\\--| |-| |-|~|---___-------___---/==\\__/'");
	LOGGER->LogLine("         | | | | | |");
	LOGGER->LogLine("         | | | | | |     DRAAL");
	LOGGER->LogLine("          V   V   V");
}

void Cleanup() {
	CloseHandle(mainProcessInfo.hProcess);
	CloseHandle(mainProcessInfo.hThread);
	CloseHandle(supportingProcessInfo.hProcess);
	CloseHandle(supportingProcessInfo.hThread);
	CloseHandle(job);

	if (supportingProcessMutex != NULL) {
		ReleaseMutex(supportingProcessMutex);
		CloseHandle(supportingProcessMutex);
	}

	if (LOGGER != nullptr) {
		delete LOGGER;
	}
}