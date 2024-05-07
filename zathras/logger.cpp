#include "pch.h"
#include "logger.h"

Logger::Logger(const char* filepath, bool enabled)
{
    if (enabled) {
        LogFile = _fsopen(filepath, "a+", _SH_DENYWR);
        this->enabled = enabled;
    }
}

Logger::~Logger()
{
    this->Log("Freeing Logger");
    if (LogFile != nullptr) {
        this->Log("Closing logfile...");
        fclose(LogFile);
    }
}


void Logger::Log(const char* format, ...)
{
    if (enabled && LogFile != nullptr) {
        va_list args;
        va_start(args, format);

        size_t formatCharCount = strlen(format) + 1;
        size_t charByteSize = sizeof(char);

        char* formatNewLine = new char[formatCharCount + 2];
        strcpy_s(formatNewLine, formatCharCount + 2, format);
        strcat_s(formatNewLine, formatCharCount + 2, "\n");

        vfprintf(LogFile, formatNewLine, args);
        fflush(LogFile);
        va_end(args);

        delete[] formatNewLine;
    }
}

void Logger::Log(const wchar_t* format, ...)
{
    if (enabled && LogFile != nullptr) {
        va_list args;
        va_start(args, format);

        size_t formatCharCount = wcslen(format) + 1;
        size_t charByteSize = sizeof(wchar_t);

        wchar_t* formatNewLine = new wchar_t[formatCharCount + 2];
        wcscpy_s(formatNewLine, formatCharCount + 2, format);
        wcscat_s(formatNewLine, formatCharCount + 2, L"\n");

        vfwprintf(LogFile, formatNewLine, args);
        fflush(LogFile);
        va_end(args);

        delete[] formatNewLine;
    }
}
