#pragma once
#include <WinTrust.h>
#include <WinInet.h>
#include <WS2tcpip.h>
#include "idcrl.h"

//WinTrust
typedef long(WINAPI* WinVerifyTrustEx_type)(HWND hwnd, GUID* pgActionID, WINTRUST_DATA* pWinTrustData);

//WinInet
typedef HINTERNET(WINAPI* HttpOpenRequestA_type)(HINTERNET hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer, LPCSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);
typedef HINTERNET(WINAPI* HttpOpenRequestW_type)(HINTERNET hConnect, LPCWSTR lpszVerb, LPCWSTR lpszObjectName, LPCWSTR lpszVersion, LPCWSTR lpszReferrer, LPCWSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);
typedef HINTERNET(WINAPI* InternetConnectA_type)(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);
typedef HINTERNET(WINAPI* InternetConnectW_type)(HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort, LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);
typedef BOOL(WINAPI* InternetCrackUrlW_type)(LPCWSTR lpszUrl, DWORD dwUrlLength, DWORD dwFlags, LPURL_COMPONENTSW lpUrlComponents);
//WS2tcpip
typedef int(WINAPI* getaddrinfo_type)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
typedef int(WSAAPI* connect_type)(SOCKET s, const sockaddr* name, int namelen);

typedef LSTATUS(WINAPI* RegQueryValueExW_type)(HKEY hkey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);


//Hooks
long WINAPI hook_WinVerifyTrustEx(HWND hwnd, GUID* pgActionID, WINTRUST_DATA* pWinTrustData);
HINTERNET WINAPI hook_HttpOpenRequestA(HINTERNET hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer, LPCSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);
HINTERNET WINAPI hook_HttpOpenRequestW(HINTERNET hConnect, LPCWSTR lpszVerb, LPCWSTR lpszObjectName, LPCWSTR lpszVersion, LPCWSTR lpszReferrer, LPCWSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);
HINTERNET WINAPI hook_InternetConnectA(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);
HINTERNET WINAPI hook_InternetConnectW(HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort, LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);
int WINAPI hook_getaddrinfo(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFO* pHints, PADDRINFOA* ppResult);
LSTATUS WINAPI hook_RegQueryValueExW(HKEY hkey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
BOOL WINAPI hook_InternetCrackUrlW(LPCWSTR lpszUrl, DWORD dwUrlLength, DWORD dwFlags, LPURL_COMPONENTSW lpUrlComponents);
HRESULT __stdcall hook_GetWebAuthUrlEx (VOID* hExternalIdentity, IDCRL_WEBAUTHOPTION dwFlags, LPCWSTR szTargetServiceUrl, LPCWSTR wszServicePolicy, LPCWSTR wszAdditionalPostParams, LPCWSTR* pszSHA1UrlOut, LPCWSTR* pszSHA1PostDataOut);


void SetupLogger();
void Cleanup();
void Hook();
void Unhook();
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved);
void WINAPI ImportMe();