#pragma once
#include <WinTrust.h>
#include <WinInet.h>
#include <WS2tcpip.h>

//WinTrust
typedef long(WINAPI* WinVerifyTrustEx_type)(HWND hwnd, GUID* pgActionID, WINTRUST_DATA* pWinTrustData);

//WinInet
typedef HINTERNET(WINAPI* HttpOpenRequestA_type)(HINTERNET hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer, LPCSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);
typedef HINTERNET(WINAPI* HttpOpenRequestW_type)(HINTERNET hConnect, LPCWSTR lpszVerb, LPCWSTR lpszObjectName, LPCWSTR lpszVersion, LPCWSTR lpszReferrer, LPCWSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);
typedef HINTERNET(WINAPI* InternetConnectA_type)(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);
typedef HINTERNET(WINAPI* InternetConnectW_type)(HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort, LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);

//WS2tcpip
typedef int (WINAPI* getaddrinfo_type)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);


typedef int(WSAAPI* connect_type)(SOCKET s, const sockaddr* name, int namelen);