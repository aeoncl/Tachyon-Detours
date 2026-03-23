#include "logger.h"
#include <cstdarg>

Logger::Logger(const char* filepath, bool enabled)
{
    if (enabled) {
        LogFile = _fsopen(filepath, "a+", _SH_DENYWR);
        this->enabled = enabled;
    }
}

Logger::~Logger()
{
    this->LogLine("Freeing Logger");
    if (LogFile != nullptr) {
        this->LogLine("Closing logfile...");
        fclose(LogFile);
    }
}

void Logger::Log(const char* format, ...)
{
    if (enabled && LogFile != nullptr) {
        va_list args;
        va_start(args, format);

        vfprintf_s(LogFile, format, args);
        fflush(LogFile);
        va_end(args);
    }
}

void Logger::Log(const wchar_t* format, ...)
{
    if (enabled && LogFile != nullptr) {
        va_list args;
        va_start(args, format);


        vfwprintf_s(LogFile, format, args);
        fflush(LogFile);
        va_end(args);
    }
}

void Logger::LogLine(const char* format, ...)
{
    if (enabled && LogFile != nullptr) {
        va_list args;
        va_start(args, format);

        size_t formatCharCount = strlen(format) + 1;
        size_t charByteSize = sizeof(char);

        char* formatNewLine = new char[formatCharCount + 2];
        strcpy_s(formatNewLine, formatCharCount + 2, format);
        strcat_s(formatNewLine, formatCharCount + 2, "\n");

        vfprintf_s(LogFile, formatNewLine, args);
        fflush(LogFile);
        va_end(args);

        delete[] formatNewLine;
    }
}

void Logger::LogLine(const wchar_t* format, ...)
{
    if (enabled && LogFile != nullptr) {
        va_list args;
        va_start(args, format);

        size_t formatCharCount = wcslen(format) + 1;
        size_t charByteSize = sizeof(wchar_t);

        wchar_t* formatNewLine = new wchar_t[formatCharCount + 2];
        wcscpy_s(formatNewLine, formatCharCount + 2, format);
        wcscat_s(formatNewLine, formatCharCount + 2, L"\n");

        vfwprintf_s(LogFile, formatNewLine, args);
        fflush(LogFile);
        va_end(args);

        delete[] formatNewLine;
    }
}
