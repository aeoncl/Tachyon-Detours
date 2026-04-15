#pragma once
#include "pch.h"
#include "config.h"
#include <ShlObj.h>
#include "SimpleIni.h"


TachyonConfig TachyonConfig::Empty()
{
	return TachyonConfig();
}


TachyonConfig TachyonConfig::LoadConfig(Logger* LOGGER, DWORD& errorCode)
{
	LOGGER->LogLine("Loading config file...");
	DWORD configPathError = ERROR_SUCCESS;
	std::string configDirectory = ResolveConfigDirectory(configPathError);
	if (configPathError != ERROR_SUCCESS) {
		LOGGER->LogLine("Could not resolve config file path. ErrorCode: 0x%x", configPathError);
		errorCode = configPathError;
		return TachyonConfig::Empty();
	}

	std::string configPath(configDirectory);
	configPath.append("\\config.ini");

	CSimpleIniA ini;
	SI_Error loadResult = ini.LoadFile(configPath.c_str());
	if (loadResult != SI_OK) {
		LOGGER->LogLine("Could not load config file, using defaults... ErrorCode: 0x%x", loadResult);
		ini.SetLongValue("server", "notification_port", 1863);
		ini.SetLongValue("server", "switchboard_port", 1864);
		ini.SetLongValue("server", "http_port", 8080);
		ini.SetBoolValue("matrix", "strict_ssl", true);
		ini.SetBoolValue("zathras_logs", "enabled", false);
		ini.SaveFile(configPath.c_str());
	}


	long notificationPort = ini.GetLongValue("server", "notification_port", 1863, false);
	long switchboardPort = ini.GetLongValue("server", "switchboard_port", 1864, false);
	long httpPort = ini.GetLongValue("server", "http_port", 8080, false);
	bool strictSSL = ini.GetBoolValue("matrix", "strict_ssl", true, false);
	bool logsEnabled = ini.GetBoolValue("zathras_logs", "enabled", false, false);

	TachyonConfig config;
	config.notificationServerPort = notificationPort;
	config.switchboardServerPort = switchboardPort;
	config.httpServerPort = httpPort;
	config.matrixStrictSSL = strictSSL;
	config.zathrasLogsEnabled = logsEnabled;

	LOGGER->LogLine("Successfully loaded config:");
	LOGGER->LogLine("\tnotificationServerPort: %ld", config.notificationServerPort);
	LOGGER->LogLine("\tswitchboardServerPort: %ld", config.switchboardServerPort);
	LOGGER->LogLine("\thttpPort: %ld", config.httpServerPort);
	LOGGER->LogLine("\tstrictSSL: %s", config.matrixStrictSSL ? "true" : "false");
	LOGGER->LogLine("\tzathrasLogsEnabled: %s", config.zathrasLogsEnabled ? "true" : "false");
	return config;
}


Logger* CreateLogger(bool enabled)
{

		char processPath[MAX_PATH] = {};
		GetModuleFileNameA(nullptr, processPath, MAX_PATH);
		char* processName = strrchr(processPath, '\\');
		processName = processName ? processName + 1 : processPath;

		DWORD logPathError = ERROR_SUCCESS;
		std::string logPath = ResolveDefaultLogDirectory(logPathError);
		if (logPathError != ERROR_SUCCESS) {
			logPath = std::string("C:\\temp");
		}

		logPath.append("\\zathras-");
		logPath.append(processName);
		logPath.append(".log");

		return new Logger(logPath.c_str(), enabled);
}

std::string ResolveSpecialDirectory(DWORD& errorCode, int csidl, const char* subDirectoryPath)
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

std::string ResolveConfigDirectory(DWORD &errorCode)
{
	return ResolveSpecialDirectory(errorCode, CSIDL_APPDATA, "Tachyon\\config");
}

std::string ResolveDefaultLogDirectory(DWORD& errorCode)
{
	return ResolveSpecialDirectory(errorCode, CSIDL_APPDATA, "Tachyon");
}

bool PathExists(const std::string& path)
{
    return GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

std::string GetParentDirectory(const std::string& path)
{
	size_t slashPos = path.find_last_of("\\/");
	if (slashPos == std::string::npos)
		return std::string();
	return path.substr(0, slashPos);
}

bool IsDirectory(const std::string& path)
{
    DWORD attrs = GetFileAttributesA(path.c_str());
    return (attrs != INVALID_FILE_ATTRIBUTES) && (attrs & FILE_ATTRIBUTE_DIRECTORY);
}

bool EnsureDirectoryExists(const std::string& path, DWORD& errorCode)
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