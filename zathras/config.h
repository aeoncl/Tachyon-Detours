#pragma once
#include <string>
#include "../libs/logger.h"

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

std::string ResolveConfigDirectory(DWORD& errorCode);
std::string ResolveDefaultLogDirectory(DWORD& errorCode);
Logger* CreateLogger(bool enabled);