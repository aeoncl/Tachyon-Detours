#pragma once
#include "pch.h"
#include "config.h"
#include <ShlObj.h>
#include "../libs/SimpleIni.h"
#include "../libs/directoryUtils.h"

const long DEFAULT_NS_PORT = 11863;
const long DEFAULT_SB_PORT = 11864;
const long DEFAULT_HTTP_PORT = 11866;
const bool DEFAULT_STRICT_SSL = true;
const bool DEFAULT_ZATHRAS_LOGS_ENABLED = false;

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
		ini.SetLongValue("server", "notification_port", DEFAULT_NS_PORT);
		ini.SetLongValue("server", "switchboard_port", DEFAULT_SB_PORT);
		ini.SetLongValue("server", "http_port", DEFAULT_HTTP_PORT);
		ini.SetBoolValue("matrix", "strict_ssl", DEFAULT_STRICT_SSL);
		ini.SetBoolValue("zathras_logs", "enabled", DEFAULT_ZATHRAS_LOGS_ENABLED);
		ini.SaveFile(configPath.c_str());
	}


	long notificationPort = ini.GetLongValue("server", "notification_port", DEFAULT_NS_PORT, false);
	long switchboardPort = ini.GetLongValue("server", "switchboard_port", DEFAULT_SB_PORT, false);
	long httpPort = ini.GetLongValue("server", "http_port", DEFAULT_HTTP_PORT, false);
	bool strictSSL = ini.GetBoolValue("matrix", "strict_ssl", DEFAULT_STRICT_SSL, false);
	bool logsEnabled = ini.GetBoolValue("zathras_logs", "enabled", DEFAULT_ZATHRAS_LOGS_ENABLED, false);

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
	std::string processName = GetProcessName();

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


std::string ResolveConfigDirectory(DWORD &errorCode)
{
	return ResolveSpecialDirectory(errorCode, CSIDL_APPDATA, "Tachyon\\config");
}

std::string ResolveDefaultLogDirectory(DWORD& errorCode)
{
	return ResolveSpecialDirectory(errorCode, CSIDL_APPDATA, "Tachyon");
}
