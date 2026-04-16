#define WIN32_LEAN_AND_MEAN 

#include <iostream>
#include <windows.h>
#include "../libs/logger.h"
#include "../libs/directoryUtils.h"
#include "draal.h"
#include <detours.h>
#include "config.h"
#pragma comment(lib, "detours")

Logger* LOGGER = nullptr;
PROCESS_INFORMATION PROCESS_INFO = {};

int main(int argc, char* argv[])
{
	Logger* bootstrapLogger = CreateLogger(true, "init");
	DWORD configError = ERROR_SUCCESS;
	DraalConfig config = DraalConfig::LoadConfig(bootstrapLogger, configError);
	if (configError != ERROR_SUCCESS) {
		bootstrapLogger->LogLine("Failed to load config: %d", configError);
		return configError;
	}
	delete bootstrapLogger;

	SetupLogger(config.loggingEnabled, config.targetExecutable.c_str());

	DWORD createMainProcessResult = CreateSuspendedProcess(config.targetExecutable.c_str(), PROCESS_INFO, argc, argv);
	if (createMainProcessResult != ERROR_SUCCESS) {
		Cleanup();
		return createMainProcessResult;
	}

	void* baseImageAddress = nullptr;
	DWORD baseImageAddressResult = GetRemoteBaseImageAddressFromPEB(PROCESS_INFO.hProcess, baseImageAddress);
	if (baseImageAddressResult != ERROR_SUCCESS) {
		Cleanup();
		return baseImageAddressResult;
	}

	LOGGER->LogLine("Got base Image Addr: 0x%x", baseImageAddress);

	DWORD sanitizeIATResult = SanitizeImportAddressTable(PROCESS_INFO.hProcess, baseImageAddress, config.dllsToRemove);
	if (baseImageAddressResult != ERROR_SUCCESS) {
		Cleanup();
		return sanitizeIATResult;
	}

	DWORD injectResult = InjectLibrairies(PROCESS_INFO.hProcess, config.dllsToInject);
	if (injectResult != ERROR_SUCCESS) {
		Cleanup();
		return injectResult;
	}

	DWORD resumeResult = ResumeThread(PROCESS_INFO.hThread);
	if (resumeResult == -1) {
		LOGGER->LogLine("Fatal: Failed to ResumeThread: 0x%x", GetLastError());
		Cleanup();
		return resumeResult;
	}

	Cleanup();
	return EXIT_SUCCESS;
}

DWORD CreateSuspendedProcess(LPCSTR processNameIn, PROCESS_INFORMATION& processInfoOut, int argc, char* argv[]) {
	std::string exeDir = GetProcessDirectory();
	std::string targetPath = exeDir + processNameIn;

	std::string commandLine = "\"" + targetPath + "\"";
	for (int i = 1; i < argc; i++) {
		commandLine += " ";
		commandLine += "\"";
		commandLine += argv[i];
		commandLine += "\"";
	}

	LOGGER->LogLine("Command line args to passthrough: %s", commandLine.c_str());

	std::vector<char> commandLineBuffer(commandLine.begin(), commandLine.end());
	commandLineBuffer.push_back('\0');

	STARTUPINFOA startupInfo = {};
	startupInfo.cb = sizeof(STARTUPINFOA);

	BOOL result = CreateProcessA(
		targetPath.c_str(),
		commandLine.empty() ? NULL : commandLineBuffer.data(),
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED,
		NULL,
		exeDir.c_str(),
		&startupInfo,
		&processInfoOut
	);

	if (!result) {
		DWORD error = GetLastError();
		LOGGER->LogLine("Could not create %s process. Error Code: 0x%x", processNameIn,  error);
		return error;
	}

	LOGGER->LogLine("%s started suspended (pid %lu)",processNameIn, processInfoOut.dwProcessId);
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

DWORD SanitizeImportAddressTable(HANDLE processIn, void* baseImageAddressIn, const std::vector<std::string>& dllsToRemove) {
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

		if (IsDllBlacklisted(dllName, dllsToRemove)) {
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

DWORD InjectLibrairies(HANDLE processIn, const std::vector<std::string>& dllNames) {

	std::vector<LPCSTR> ptrs;
	for (const auto& dll : dllNames) {
		LOGGER->LogLine("Injecting DLL: %s...", dll.c_str());
		ptrs.push_back(dll.c_str());
	}

	BOOL result = DetourUpdateProcessWithDll(processIn, ptrs.data(), ptrs.size());
	if (!result) {
		DWORD error = GetLastError();
		LOGGER->LogLine("Fatal: Could not inject DLLS in process. DetourUpdateProcessWithDll failed with error: 0x%x", error);
		return error;
	}

	return ERROR_SUCCESS;
}


bool IsDllBlacklisted(const char* dllName, const std::vector<std::string>& dllsToRemove) {
	for (const auto& dllToRemove : dllsToRemove) {
		if (_stricmp(dllName, dllToRemove.c_str()) == 0)
			return true;
	}
	return false;
}


void SetupLogger(bool enabled, const char* name) {
	LOGGER = CreateLogger(enabled, name);

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
	CloseHandle(PROCESS_INFO.hProcess);
	CloseHandle(PROCESS_INFO.hThread);

	if (LOGGER != nullptr) {
		delete LOGGER;
	}
}