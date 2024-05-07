#pragma once
#include <stdio.h>
#include <fstream>

class Logger {
	private:
		FILE* LogFile = nullptr;
		bool enabled = false;

	public:
		Logger(const char* filepath, bool enabled);
		~Logger();
		void Log(const char* format, ...);
		void Log(const wchar_t* format, ...);
};