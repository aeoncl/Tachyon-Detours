#pragma once
#include <WinTrust.h>
#include <WinInet.h>
#include <WS2tcpip.h>
#include "idcrl.h"
#include <Ole2.h>
#include <shellapi.h>

//WinTrust
typedef long(WINAPI* WinVerifyTrustEx_type)(HWND hwnd, GUID* pgActionID, WINTRUST_DATA* pWinTrustData);

//WinInet
typedef HINTERNET(WINAPI* HttpOpenRequestA_type)(HINTERNET hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer, LPCSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);
typedef HINTERNET(WINAPI* HttpOpenRequestW_type)(HINTERNET hConnect, LPCWSTR lpszVerb, LPCWSTR lpszObjectName, LPCWSTR lpszVersion, LPCWSTR lpszReferrer, LPCWSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);
typedef HINTERNET(WINAPI* InternetConnectA_type)(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);
typedef HINTERNET(WINAPI* InternetConnectW_type)(HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort, LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);
typedef HINTERNET(WINAPI* InternetSetOptionA_type)(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD lpdwBufferLength);
typedef HINTERNET(WINAPI* InternetSetOptionW_type)(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD lpdwBufferLength);
typedef HINTERNET(WINAPI* InternetQueryOptionA_type)(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, LPDWORD lpdwBufferLength);
typedef HINTERNET(WINAPI* InternetQueryOptionW_type)(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, LPDWORD lpdwBufferLength);

typedef BOOL(WINAPI* InternetCrackUrlW_type)(LPCWSTR lpszUrl, DWORD dwUrlLength, DWORD dwFlags, LPURL_COMPONENTSW lpUrlComponents);
//WS2tcpip
typedef int(WINAPI* getaddrinfo_type)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
typedef int(WSAAPI* connect_type)(SOCKET s, const sockaddr* name, int namelen);

typedef LSTATUS(WINAPI* RegQueryValueExW_type)(HKEY hkey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);

//ole32
typedef HRESULT(__stdcall* CoRegisterClassObject_type)(REFCLSID rclsid, LPUNKNOWN pUnk, CLSCTX dwClsContext, DWORD flags, LPDWORD lpdwRegister);
typedef HRESULT(__stdcall* CoCreateInstance_type)(REFCLSID rclsid, LPUNKNOWN pUnkOuter, CLSCTX dwClsContext, REFIID riid, LPVOID* ppv);

//ShlObj
typedef HINSTANCE(WINAPI* ShellExecuteA_type)(HWND hwnd, LPCSTR lpOperation, LPCSTR lpFile, LPCSTR lpParameters, LPCSTR lpDirectory, INT nShowCmd);
typedef HINSTANCE(WINAPI* ShellExecuteW_type)(HWND hwnd, LPCWSTR lpOperation, LPCWSTR lpFile, LPCWSTR lpParameters, LPCWSTR lpDirectory, INT nShowCmd);
typedef BOOL(WINAPI* ShellExecuteExW_type)(SHELLEXECUTEINFOW* pExecInfo);

//Hooks
long WINAPI hook_WinVerifyTrustEx(HWND hwnd, GUID* pgActionID, WINTRUST_DATA* pWinTrustData);
HINTERNET WINAPI hook_HttpOpenRequestA(HINTERNET hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer, LPCSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);
HINTERNET WINAPI hook_HttpOpenRequestW(HINTERNET hConnect, LPCWSTR lpszVerb, LPCWSTR lpszObjectName, LPCWSTR lpszVersion, LPCWSTR lpszReferrer, LPCWSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);
HINTERNET WINAPI hook_InternetConnectA(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);
HINTERNET WINAPI hook_InternetConnectW(HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort, LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);
int WINAPI hook_getaddrinfo(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFO* pHints, PADDRINFOA* ppResult);
int WSAAPI hook_connect(SOCKET s, const sockaddr* name, int namelen);

//HINSTANCE WINAPI hook_ShellExecuteA(HWND hwnd, LPCSTR lpOperation, LPCSTR lpFile, LPCSTR lpParameters, LPCSTR lpDirectory, INT nShowCmd);
//HINSTANCE WINAPI hook_ShellExecuteW(HWND hwnd, LPCWSTR lpOperation, LPCWSTR lpFile, LPCWSTR lpParameters, LPCWSTR lpDirectory, INT nShowCmd);
//BOOL WINAPI hook_ShellExecuteExW(SHELLEXECUTEINFOW* pExecInfo);

//ole32
HRESULT __stdcall hook_CoRegisterClassObject(REFCLSID rclsid, LPUNKNOWN pUnk, CLSCTX dwClsContext, DWORD flags, LPDWORD lpdwRegister);
HRESULT __stdcall hook_CoCreateInstance(REFCLSID rclsid, LPUNKNOWN pUnkOuter, CLSCTX dwClsContext, REFIID riid, LPVOID* ppv);

LSTATUS WINAPI hook_RegQueryValueExW(HKEY hkey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
//BOOL WINAPI hook_InternetCrackUrlW(LPCWSTR lpszUrl, DWORD dwUrlLength, DWORD dwFlags, LPURL_COMPONENTSW lpUrlComponents);
HRESULT __stdcall hook_GetWebAuthUrlEx (VOID* hExternalIdentity, IDCRL_WEBAUTHOPTION dwFlags, LPCWSTR szTargetServiceUrl, LPCWSTR wszServicePolicy, LPCWSTR wszAdditionalPostParams, LPCWSTR* pszSHA1UrlOut, LPCWSTR* pszSHA1PostDataOut);
HRESULT __stdcall hook_InitializeExMsid(REFGUID appId, long idclrVersion, UPDATE_FLAG dwflags, IDCRL_OPTION pOptions[], DWORD dwOptions);

BOOL SetupConfig();
void SetupLogger();
void Cleanup();
void Hook();
void Unhook();
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved);
void WINAPI ImportMe();
void DumpRawMemory(DWORD_PTR dwContext, SIZE_T dumpSize);