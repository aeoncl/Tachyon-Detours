// draal.cpp : Ce fichier contient la fonction 'main'. L'exécution du programme commence et se termine à cet endroit.
//
#define WIN32_LEAN_AND_MEAN 

#include <iostream>
#include <windows.h>
#include "logger.h"
#include "draal.h"


Logger* LOGGER = nullptr;


int main()
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

	TerminateProcess(processInfo.hProcess, 0);

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

DWORD GetRemoteBaseImageAddressFromPEB(HANDLE processIn, void*& addressOut)
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

	addressOut = peb.ImageBaseAddress;
	return ERROR_SUCCESS;
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