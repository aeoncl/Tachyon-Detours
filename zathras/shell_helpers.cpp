#pragma once
#include "pch.h"
#include "shell_helpers.h"
#include <string>

bool IsHttpUrlA(const char* s, size_t* prefixLen) {
    if (s == nullptr) return false;
    if (_strnicmp(s, "http://", 7) == 0) { *prefixLen = 7;  return true; }
    if (_strnicmp(s, "https://", 8) == 0) { *prefixLen = 8;  return true; }
    return false;
}

bool IsHttpUrlW(const wchar_t* s, size_t* prefixLen) {
    if (s == nullptr) return false;
    if (_wcsnicmp(s, L"http://", 7) == 0) { *prefixLen = 7;  return true; }
    if (_wcsnicmp(s, L"https://", 8) == 0) { *prefixLen = 8;  return true; }
    return false;
}

std::wstring RewriteUrlWithPortW(const wchar_t* url, long port) {
    size_t prefixLen = 0;
    if (!IsHttpUrlW(url, &prefixLen)) {
        return std::wstring();
    }

    std::wstring s(url);
    size_t hostStart = prefixLen;
    size_t hostEnd = s.find(L'/', hostStart);
    if (hostEnd == std::wstring::npos) {
        hostEnd = s.length();
    }

    std::wstring host = s.substr(hostStart, hostEnd - hostStart);
    if (host.find(L':') != std::wstring::npos) {
        return s;
    }

    wchar_t portBuf[16];
    swprintf(portBuf, 16, L":%d", port);

    std::wstring result;
    result.reserve(s.length() + 8);
    result.append(s, 0, hostEnd);
    result.append(portBuf);
    result.append(s, hostEnd, std::wstring::npos);
    return result;
}

std::string RewriteUrlWithPortA(const char* url, long port) {
    size_t prefixLen = 0;
    if (!IsHttpUrlA(url, &prefixLen)) {
        return std::string();
    }

    std::string s(url);
    size_t hostStart = prefixLen;
    size_t hostEnd = s.find('/', hostStart);
    if (hostEnd == std::string::npos) {
        hostEnd = s.length();
    }

    std::string host = s.substr(hostStart, hostEnd - hostStart);
    if (host.find(':') != std::string::npos) {
        return s;
    }

    char portBuf[16];
    sprintf_s(portBuf, 16, ":%d", port);

    std::string result;
    result.reserve(s.length() + 8);
    result.append(s, 0, hostEnd);
    result.append(portBuf);
    result.append(s, hostEnd, std::string::npos);
    return result;
}