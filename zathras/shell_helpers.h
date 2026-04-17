#pragma once
#include <string>

bool IsHttpUrlA(const char* s, size_t* prefixLen);
bool IsHttpUrlW(const wchar_t* s, size_t* prefixLen);
std::wstring RewriteUrlWithPortW(const wchar_t* url, long port);
std::string RewriteUrlWithPortA(const char* url, long port);