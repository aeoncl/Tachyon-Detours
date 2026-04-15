#pragma once
#include <string>
#include "logger.h"

class TachyonConfig {
public:
	int notificationServerPort;
	int switchboardServerPort;
	int httpServerPort;
	bool matrixStrictSSL;
	bool zathrasLogsEnabled;
	static TachyonConfig LoadConfig(Logger* LOGGER, DWORD& errorCode);
	static TachyonConfig Empty();


};

Logger* CreateLogger(bool enabled);
std::string ResolveSpecialDirectory(DWORD& errorCode, int csidl, const char* subDirectoryPath);
std::string ResolveConfigDirectory(DWORD &errorCode);
std::string ResolveDefaultLogDirectory(DWORD& errorCode);
std::string GetParentDirectory(const std::string& path);
bool PathExists(const std::string& path);
bool IsDirectory(const std::string& path);
bool EnsureDirectoryExists(const std::string& path, DWORD& errorCode);
