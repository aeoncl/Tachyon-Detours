#pragma once
#include <string>
#include <Windows.h>
#include <ShlObj.h>

inline bool IsDirectory(const std::string& path)
{
	DWORD attrs = GetFileAttributesA(path.c_str());
	return (attrs != INVALID_FILE_ATTRIBUTES) && (attrs & FILE_ATTRIBUTE_DIRECTORY);
}


inline std::string GetParentDirectory(const std::string& path)
{
	size_t slashPos = path.find_last_of("\\/");
	if (slashPos == std::string::npos)
		return std::string();
	return path.substr(0, slashPos);
}



inline bool EnsureDirectoryExists(const std::string& path, DWORD& errorCode)
{
	if (IsDirectory(path))
		return true;

	std::string parent = GetParentDirectory(path);
	if (!parent.empty() && !EnsureDirectoryExists(parent, errorCode))
		return false;

	if (!CreateDirectoryA(path.c_str(), NULL))
	{
		DWORD err = GetLastError();
		if (err != ERROR_ALREADY_EXISTS)
		{
			errorCode = err;
			return false;
		}
	}

	return true;
}

inline std::string ResolveSpecialDirectory(DWORD& errorCode, int csidl, const char* subDirectoryPath)
{
	char appdataBuffer[MAX_PATH];

	BOOL result = SHGetSpecialFolderPathA(NULL, appdataBuffer, csidl, false);
	if (!result) {
		errorCode = GetLastError();
		return std::string();
	}

	std::string specialDirectoryPath(appdataBuffer);
	specialDirectoryPath.append("\\");
	specialDirectoryPath.append(subDirectoryPath);

	DWORD ensureDirectoryExistsError = ERROR_SUCCESS;
	bool ensureDirectoryResult = EnsureDirectoryExists(specialDirectoryPath, ensureDirectoryExistsError);
	if (!ensureDirectoryResult) {
		errorCode = ensureDirectoryExistsError;
		return std::string();
	}

	return specialDirectoryPath;
}

inline bool PathExists(const std::string& path)
{
	return GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

inline std::string GetProcessName() {
	char processPath[MAX_PATH] = {};
	GetModuleFileNameA(nullptr, processPath, MAX_PATH);
	char* processName = strrchr(processPath, '\\');
	processName = processName ? processName + 1 : processPath;

	return std::string(processName);
}

inline std::string GetProcessDirectory()
{
	char path[MAX_PATH] = { 0 };
	GetModuleFileNameA(NULL, path, MAX_PATH);

	char* lastSlash = strrchr(path, '\\');
	if (lastSlash) *(lastSlash + 1) = '\0';

	return std::string(path);
}