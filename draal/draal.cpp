// draal.cpp : Ce fichier contient la fonction 'main'. L'exécution du programme commence et se termine à cet endroit.
//
#define WIN32_LEAN_AND_MEAN 

#include <iostream>
#include <windows.h>
#include "logger.h"
#include "draal.h"
#include <detours.h>
#include <vector>
#pragma comment(lib, "detours")


Logger* LOGGER = nullptr;

const char* DLL_BLACKLIST[] = {
	"escargot.dll",
	"reroute.dll",
	"zathras.dll",
	NULL
};


int main(int argc, char* argv[])
{
	SetupLogger();

	PROCESS_INFORMATION processInfo = {};

	DWORD createMsnProcessResult = CreateMsnMsgrProcess(&processInfo);
	if (createMsnProcessResult != ERROR_SUCCESS) {
		CloseHandle(processInfo.hProcess);
		CloseHandle(processInfo.hThread);
		Cleanup();
		return createMsnProcessResult;
	}

	void* baseImageAddress = nullptr;
	DWORD baseImageAddressResult = GetRemoteBaseImageAddressFromPEB(processInfo.hProcess, baseImageAddress);
	if (baseImageAddressResult != ERROR_SUCCESS) {
		CloseHandle(processInfo.hProcess);
		CloseHandle(processInfo.hThread);
		Cleanup();
		return baseImageAddressResult;
	}

	LOGGER->LogLine("Got base Image Addr: 0x%x", baseImageAddress);

	DWORD sanitizeIATResult = SanitizeImportAddressTable(processInfo.hProcess, baseImageAddress);
	if (baseImageAddressResult != ERROR_SUCCESS) {
		CloseHandle(processInfo.hProcess);
		CloseHandle(processInfo.hThread);
		Cleanup();
		return sanitizeIATResult;
	}

	DWORD injectResult = InjectLibrary(processInfo.hProcess, "zathras.dll");
	if (injectResult != ERROR_SUCCESS) {
		CloseHandle(processInfo.hProcess);
		CloseHandle(processInfo.hThread);
		Cleanup();
		return injectResult;
	}


	DWORD resumeResult = ResumeThread(processInfo.hThread);
	if (resumeResult  == -1) {
		LOGGER->LogLine("Fatal: Failed to ResumeThread: 0x%x", GetLastError());
		CloseHandle(processInfo.hProcess);
		CloseHandle(processInfo.hThread);
		Cleanup();
		return resumeResult;
	}



	//TODO inject our dll with detours
	//TODO start tachyon

	//TerminateProcess(processInfo.hProcess, 0);

	CloseHandle(processInfo.hProcess);
	CloseHandle(processInfo.hThread);
	Cleanup();

	return EXIT_SUCCESS;
}

DWORD CreateMsnMsgrProcess(LPPROCESS_INFORMATION processInfo) {
	STARTUPINFOA startupInfo = {};
	startupInfo.cb = sizeof(STARTUPINFOA);

	BOOL result = CreateProcessA(
		"msnmsgr.exe",
		NULL,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED,
		NULL,
		NULL,
		&startupInfo,
		processInfo
	);

	if (!result) {
		DWORD error = GetLastError();
		LOGGER->LogLine("Could not create msnmsgr.exe process. Error Code: 0x%x", error);
		return error;
	}

	LOGGER->LogLine("msnmsgr.exe started suspended (pid %lu)", processInfo->dwProcessId);
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
	if (LOGGER != nullptr) {
		delete LOGGER;
	}
}