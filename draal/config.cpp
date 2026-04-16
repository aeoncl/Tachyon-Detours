#pragma once
#include "config.h"
#include "../libs/SimpleIni.h"
#include "../libs/directoryUtils.h"
#include <list>


DraalConfig DraalConfig::LoadConfig(Logger* LOGGER, DWORD& errorCode)
{
	CSimpleIniA ini;
	ini.SetMultiKey(true);
	ini.SetQuotes(true);

	std::string iniPath = GetProcessDirectory() + "draal.ini";
	SI_Error loadResult = ini.LoadFile(iniPath.c_str());
	if (loadResult != SI_OK) {
		errorCode = loadResult;
		return DraalConfig::Empty();
	}

	DraalConfig out;

	const char* targetExecutable = ini.GetValue("draal", "target_executable", NULL, false);
	if (targetExecutable == NULL) {
		errorCode = ERROR_FILE_NOT_FOUND;
		return DraalConfig::Empty();
	}
	out.targetExecutable = std::string(targetExecutable);
	out.loggingEnabled = ini.GetBoolValue("logs", "enabled", false, false);

	CSimpleIniA::TNamesDepend dllsToRemove;
	ini.GetAllValues("draal", "dll_to_remove", dllsToRemove);

	for (auto entry : dllsToRemove) {
		out.dllsToRemove.push_back(std::string(entry.pItem));
	}

	CSimpleIniA::TNamesDepend dllsToInject;
	ini.GetAllValues("draal", "dll_to_inject", dllsToInject);

	for (auto entry : dllsToInject) {
		out.dllsToInject.push_back(std::string(entry.pItem));
	}

	return out;
}

DraalConfig DraalConfig::Empty()
{
	return DraalConfig();
}



Logger* CreateLogger(bool enabled, const char* name)
{
	DWORD logPathError = ERROR_SUCCESS;
	std::string logPath = ResolveDefaultLogDirectory(logPathError);
	if (logPathError != ERROR_SUCCESS) {
		logPath = std::string("C:\\temp");
	}

	logPath.append("\\draal-");
	logPath.append(name);
	logPath.append(".log");

	return new Logger(logPath.c_str(), enabled);
}

std::string ResolveDefaultLogDirectory(DWORD& errorCode)
{
	return ResolveSpecialDirectory(errorCode, CSIDL_APPDATA, "Draal");
}
