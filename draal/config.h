#include "../libs/logger.h"
#include <Windows.h>
#include <string>
#include <vector>

class DraalConfig {

public: 
	std::string targetExecutable;
	std::vector<std::string> dllsToRemove;
	std::vector<std::string> dllsToInject;
	bool loggingEnabled;
	static DraalConfig LoadConfig(Logger* LOGGER, DWORD& errorCode);
	static DraalConfig Empty();

};

std::string ResolveDefaultLogDirectory(DWORD& errorCode);
Logger* CreateLogger(bool enabled, const char* name);