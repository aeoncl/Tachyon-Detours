#include "pch.h"
#include "dllmain.h"
#include "../libs/logger.h"
#include <string.h>
#include <detours.h>
#include "config.h"
#include "shell_helpers.h"
#pragma comment(lib, "detours")
//For ntoa
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Shell32.lib")


#define IGNORE_MAGIC 0xDEADBEEF

BOOL Hooked = FALSE;
Logger *LOGGER = nullptr;
TachyonConfig config;

static const char* OVERRIDE_URL = "127.0.0.1";
static const wchar_t* OVERRIDE_URL_W = L"127.0.0.1";

static int ORIGINAL_NS_PORT = 1863;

static const CLSID ORIGINAL_CONTACT_CLSID = { 0x380689D0,0xAFAA,0x47E6,{0xB8,0x0E,0xA3,0x34,0x36,0xFE,0x31,0x4B} };
static const CLSID NEW_CONTACT_CLSID = { 0xD86BCC3A,0x303F,0x41C9,{0xAF,0x6B,0x5E,0x30,0xC3,0x8F,0xAF,0x36} };


WinVerifyTrustEx_type og_WinVerifyTrustEx = nullptr;
HttpOpenRequestA_type og_HttpOpenRequestA = nullptr;
HttpOpenRequestW_type og_HttpOpenRequestW = nullptr;
InternetConnectA_type og_InternetConnectA = nullptr;
InternetConnectW_type og_InternetConnectW = nullptr;
InternetSetOptionA_type og_InternetSetOptionA = nullptr;
InternetSetOptionW_type og_InternetSetOptionW = nullptr;
InternetQueryOptionA_type og_InternetQueryOptionA = nullptr;
InternetQueryOptionW_type og_InternetQueryOptionW = nullptr;
getaddrinfo_type og_getaddrinfo = nullptr;
connect_type og_connect = nullptr;

ShellExecuteA_type og_ShellExecuteA = nullptr;
ShellExecuteW_type og_ShellExecuteW = nullptr;
ShellExecuteExW_type og_ShellExecuteExW = nullptr;

RegQueryValueExW_type og_RegQueryValueExW = nullptr;

CoRegisterClassObject_type og_CoRegisterClassObject = nullptr;
CoCreateInstance_type og_CoCreateInstance = nullptr;

InitializeEx_type og_InitializeExMsid = nullptr;
Initialize_type og_InitializeMsid = nullptr;
SetIdcrlOptions_type og_SetIdcrlOptions = nullptr;
GetWebAuthUrlEx_type og_GetWebAuthUrlEx = nullptr;
 
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    DWORD configError = ERROR_SUCCESS;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        SetupConfig();
        SetupLogger();
        Hook();
        break;
        //    case DLL_THREAD_ATTACH:
        //        break;
        //    case DLL_THREAD_DETACH:
        //        break;
    case DLL_PROCESS_DETACH:
        Unhook();
        break;
    }
    return TRUE;
}

void WINAPI ImportMe() {}

BOOL SetupConfig() {
    DWORD configError = ERROR_SUCCESS;
    Logger* bootstrapLogger = CreateLogger(true);
    config = TachyonConfig::LoadConfig(bootstrapLogger, configError);
    if (configError != ERROR_SUCCESS) {
        bootstrapLogger->LogLine("Error while loading config: %d", configError);
        delete bootstrapLogger;
        return FALSE;
    }
    delete bootstrapLogger;
    return TRUE;
}

void SetupLogger() {
    LOGGER = CreateLogger(config.zathrasLogsEnabled);
}

void Cleanup() {
    if (LOGGER != nullptr) {
        delete LOGGER;
    }
}

void Hook() {
    DetourRestoreAfterWith();
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    og_WinVerifyTrustEx = (WinVerifyTrustEx_type)DetourFindFunction("wintrust.dll", "WinVerifyTrustEx");
    DetourAttach(&(PVOID&)og_WinVerifyTrustEx, hook_WinVerifyTrustEx);

    og_HttpOpenRequestA = (HttpOpenRequestA_type)DetourFindFunction("wininet.dll", "HttpOpenRequestA");
    DetourAttach(&(PVOID&)og_HttpOpenRequestA, hook_HttpOpenRequestA);

    og_HttpOpenRequestW = (HttpOpenRequestW_type)DetourFindFunction("wininet.dll", "HttpOpenRequestW");
    DetourAttach(&(PVOID&)og_HttpOpenRequestW, hook_HttpOpenRequestW);

    og_InternetConnectA = (InternetConnectA_type)DetourFindFunction("wininet.dll", "InternetConnectA");
    DetourAttach(&(PVOID&)og_InternetConnectA, hook_InternetConnectA);

    og_InternetConnectW = (InternetConnectW_type)DetourFindFunction("wininet.dll", "InternetConnectW");
    DetourAttach(&(PVOID&)og_InternetConnectW, hook_InternetConnectW);

    og_InternetSetOptionA = (InternetSetOptionA_type)DetourFindFunction("wininet.dll", "InternetSetOptionA");
    og_InternetSetOptionW = (InternetSetOptionW_type)DetourFindFunction("wininet.dll", "InternetSetOptionW");
    og_InternetQueryOptionA = (InternetQueryOptionA_type)DetourFindFunction("wininet.dll", "InternetQueryOptionA");
    og_InternetQueryOptionW = (InternetQueryOptionW_type)DetourFindFunction("wininet.dll", "InternetQueryOptionW");



    og_getaddrinfo = (getaddrinfo_type)DetourFindFunction("Ws2_32.dll", "getaddrinfo");
    DetourAttach(&(PVOID&)og_getaddrinfo, hook_getaddrinfo);

    og_connect = (connect_type)DetourFindFunction("Ws2_32.dll", "connect");
    DetourAttach(&(PVOID&)og_connect, hook_connect);

    og_RegQueryValueExW = (RegQueryValueExW_type)DetourFindFunction("Kernelbase.dll", "RegQueryValueExW");
    DetourAttach(&(PVOID&)og_RegQueryValueExW, hook_RegQueryValueExW);

    //OLE32
    og_CoRegisterClassObject = (CoRegisterClassObject_type)DetourFindFunction("ole32.dll", "CoRegisterClassObject");
    DetourAttach(&(PVOID&)og_CoRegisterClassObject, hook_CoRegisterClassObject);

    og_CoCreateInstance = (CoCreateInstance_type)DetourFindFunction("ole32.dll", "CoCreateInstance");
    DetourAttach(&(PVOID&)og_CoCreateInstance, hook_CoCreateInstance);

    og_ShellExecuteA = (ShellExecuteA_type)DetourFindFunction("shell32.dll", "ShellExecuteA");
    if (og_ShellExecuteA != nullptr) {
        DetourAttach(&(PVOID&)og_ShellExecuteA, hook_ShellExecuteA);
    }

    og_ShellExecuteW = (ShellExecuteW_type)DetourFindFunction("shell32.dll", "ShellExecuteW");
    if (og_ShellExecuteW != nullptr) {
        DetourAttach(&(PVOID&)og_ShellExecuteW, hook_ShellExecuteW);
    }
    
    og_ShellExecuteExW = (ShellExecuteExW_type)DetourFindFunction("shell32.dll", "ShellExecuteExW");
    if (og_ShellExecuteExW != nullptr) {
        DetourAttach(&(PVOID&)og_ShellExecuteExW, hook_ShellExecuteExW);
    }
    
    //MSIDCRL
    og_InitializeExMsid = (InitializeEx_type)DetourFindFunction("msidcrl40.dll", "InitializeEx");
    if (og_InitializeExMsid != nullptr) {
        DetourAttach(&(PVOID&)og_InitializeExMsid, hook_InitializeExMsid);
    }

    og_InitializeMsid = (Initialize_type)DetourFindFunction("msidcrl40.dll", "Initialize");
    og_SetIdcrlOptions = (SetIdcrlOptions_type)DetourFindFunction("msidcrl40.dll", "SetIdcrlOptions");


    og_GetWebAuthUrlEx = (GetWebAuthUrlEx_type)DetourFindFunction("msidcrl40.dll", "GetWebAuthUrlEx");
    if (og_GetWebAuthUrlEx != nullptr) {
        DetourAttach(&(PVOID&)og_GetWebAuthUrlEx, hook_GetWebAuthUrlEx);
    }

    LONG result = DetourTransactionCommit();
    if (result == NO_ERROR) {
        Hooked = true;
        LOGGER->LogLine("Hooking successfull");
    }
    else {
        LOGGER->LogLine("Hooking unsuccessfull with error: %d", result);
    }
}

void Unhook() {

    if (!Hooked) {
        return;
    }

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourDetach(&(PVOID&)og_WinVerifyTrustEx, hook_WinVerifyTrustEx);
    DetourDetach(&(PVOID&)og_HttpOpenRequestA, hook_HttpOpenRequestA);
    DetourDetach(&(PVOID&)og_HttpOpenRequestW, hook_HttpOpenRequestW);
    DetourDetach(&(PVOID&)og_InternetConnectA, hook_InternetConnectA);
    DetourDetach(&(PVOID&)og_InternetConnectW, hook_InternetConnectW);
    DetourDetach(&(PVOID&)og_getaddrinfo, hook_getaddrinfo);
    DetourDetach(&(PVOID&)og_connect, hook_connect);

    DetourDetach(&(PVOID&)og_RegQueryValueExW, hook_RegQueryValueExW);

    //OLE32
    DetourDetach(&(PVOID&)og_CoRegisterClassObject, hook_CoRegisterClassObject);
    DetourDetach(&(PVOID&)og_CoCreateInstance, hook_CoCreateInstance);

    if (og_ShellExecuteA != nullptr) {
        DetourDetach(&(PVOID&)og_ShellExecuteA, hook_ShellExecuteA);
    }

    if (og_ShellExecuteW != nullptr) {
        DetourDetach(&(PVOID&)og_ShellExecuteW, hook_ShellExecuteW);
    }

    if (og_ShellExecuteExW != nullptr) {
        DetourDetach(&(PVOID&)og_ShellExecuteExW, hook_ShellExecuteExW);
    }

    if (og_InitializeExMsid != nullptr) {
        DetourDetach(&(PVOID&)og_InitializeExMsid, hook_InitializeExMsid);
    }

    if (og_GetWebAuthUrlEx != nullptr) {
        DetourDetach(&(PVOID&)og_GetWebAuthUrlEx, hook_GetWebAuthUrlEx);
    }

    LONG result = DetourTransactionCommit();
    LOGGER->LogLine("Detaching Hooks result: %d", result);
    
    Hooked = !(result == NO_ERROR);
    Cleanup();
}


HRESULT __stdcall hook_InitializeExMsid(REFGUID appId, long idclrVersion, UPDATE_FLAG dwflags, IDCRL_OPTION pOptions[], DWORD dwOptions)
{
    LOGGER->LogLine("MSIDCRL_InitializeEx: idclrVersion: %d dwflags: 0x%x", idclrVersion, dwflags);

    for (DWORD i = 0; i < dwOptions; i++) {
        IDCRL_OPTION current = pOptions[i];
        if (current.dwId == IDCRL_OPTION_ID::IDCRL_OPTION_ENVIRONMENT) {
            const wchar_t* newEnv = L"Tachyon";
            wchar_t* dest = (wchar_t*)current.pValue;
            LOGGER->LogLine(L"MSIDCRL_InitializeEx: ENV: %s", dest);
            errno_t error = wcscpy_s(dest, current.cbValue, newEnv);
            LOGGER->LogLine(L"MSIDCRL_InitializeEx: Replace Environment... err string copy: %d - Value: %s", error, dest);
        }
    }

    HRESULT result = og_InitializeExMsid(appId, idclrVersion, dwflags, pOptions, dwOptions);

    LOGGER->LogLine("MSIDCRL_InitializeEx: Result: InitializeMsidEx: 0x%x", result);
    return result;
}


long WINAPI hook_WinVerifyTrustEx(HWND hwnd, GUID* pgActionID, WINTRUST_DATA* pWinTrustData) {

    LOGGER->LogLine(L"WinVerifyTrustEx - pcwszFilePath: %s", pWinTrustData->pFile->pcwszFilePath);

    if (wcsstr(pWinTrustData->pFile->pcwszFilePath, L"ppcrlconfig.dll") != nullptr || wcsstr(pWinTrustData->pFile->pcwszFilePath, L"msnmsgr.exe") != nullptr) {
        LOGGER->LogLine("WinVerifyTrustEx - Bypass");
        return ERROR_SUCCESS;
    }

    return og_WinVerifyTrustEx(hwnd, pgActionID, pWinTrustData);
};

HINTERNET WINAPI hook_HttpOpenRequestA(HINTERNET hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer, LPCSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext) {
    LOGGER->LogLine("HttpOpenRequestA: lpszVerb: %s lpszObjectName: %s dwFlags: 0x%x lpszReferrer: %s dwContext: 0x%x", lpszVerb, lpszObjectName, dwFlags, lpszReferrer, dwContext);

    DWORD flag = 0;
    DWORD size = sizeof(flag);
    og_InternetQueryOptionA(hConnect, INTERNET_OPTION_DATA_SEND_TIMEOUT, &flag, &size);
    if (flag == IGNORE_MAGIC) {
        return og_HttpOpenRequestA(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext);
    }

    //Unset INTERNET_SECURE_FLAG = disable SSL
    return og_HttpOpenRequestA(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags & ~INTERNET_FLAG_SECURE, dwContext);
}

HINTERNET WINAPI hook_HttpOpenRequestW(HINTERNET hConnect, LPCWSTR lpszVerb, LPCWSTR lpszObjectName, LPCWSTR lpszVersion, LPCWSTR lpszReferrer, LPCWSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext) {
    //Disables SSL
    LOGGER->LogLine(L"HttpOpenRequestW: lpszVerb: %s lpszObjectName: %s: dwFlags: 0x%x lpszReferrer: %s, dwContext: 0x%x", lpszVerb, lpszObjectName, dwFlags, lpszReferrer, dwContext);

    DWORD flag = 0;
    DWORD size = sizeof(flag);
    og_InternetQueryOptionW(hConnect, INTERNET_OPTION_DATA_SEND_TIMEOUT, &flag, &size);
    if (flag == IGNORE_MAGIC) {
        return og_HttpOpenRequestW(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext);
    }

    //Unset INTERNET_SECURE_FLAG = disable SSL
    return og_HttpOpenRequestW(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags & ~INTERNET_FLAG_SECURE, dwContext);
}

/*
the INTERNET_OPTION_DATA_SEND_TIMEOUT flag is unused in HTTP connections (only in FTP). we use it as a magic value to disable the bypass in HttpOpenRequest, where we don't have access to the url.
*/

HINTERNET WINAPI hook_InternetConnectA(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext) {
    LOGGER->LogLine("InternetConnectA: lpswServerName: %s nServerPort: %d dwFlags: 0x%x dwContext: 0x%x", lpszServerName, nServerPort, dwFlags, dwContext);

    if (strcmp(lpszServerName, "matrix.org") == 0 || strcmp(lpszServerName, "tachyon.chat") == 0 || strcmp(lpszServerName, "git.federated.nexus") == 0) {
        LOGGER->LogLine("InternetConnectA: Bypass: lpswServerName: %s nServerPort: %d dwFlags: 0x%x", lpszServerName, nServerPort, dwFlags);

        DWORD flag = IGNORE_MAGIC;
        HINTERNET handle = og_InternetConnectA(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
        DWORD error = GetLastError();
        if (error == ERROR_SUCCESS) {
            LOGGER->LogLine("InternetConnectA: Setting bypass option.");
            HINTERNET handleSetOption = og_InternetSetOptionA(handle, INTERNET_OPTION_DATA_SEND_TIMEOUT, &flag, sizeof(flag));
        }
        LOGGER->LogLine("InternetConnectA error: %d", error);
        return handle;
    }
    else {
        HINTERNET handle = og_InternetConnectA(hInternet, OVERRIDE_URL, config.httpServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
        DWORD error = GetLastError();
        LOGGER->LogLine("InternetConnectA error: %d", error);
        return handle;
    }
}

HINTERNET WINAPI hook_InternetConnectW(HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort, LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext) {
    LOGGER->LogLine(L"InternetConnectW: lpswServerName: %s nServerPort: %d dwFlags: 0x%x  dwContext: 0x%x", lpszServerName, nServerPort, dwFlags, dwContext);

    if (wcscmp(lpszServerName, L"matrix.org") == 0 || wcscmp(lpszServerName, L"tachyon.chat") == 0 || wcscmp(lpszServerName, L"git.federated.nexus") == 0) {
        LOGGER->LogLine(L"InternetConnectW: Bypass: lpswServerName: %s nServerPort: %d dwFlags: 0x%x", lpszServerName, nServerPort, dwFlags);

        DWORD flag = IGNORE_MAGIC;
        HINTERNET handle = og_InternetConnectW(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
        DWORD error = GetLastError();
        if (error == ERROR_SUCCESS) {
            LOGGER->LogLine(L"InternetConnectW: Setting bypass option.");
            HINTERNET handleSetOption = og_InternetSetOptionW(handle, INTERNET_OPTION_DATA_SEND_TIMEOUT, &flag, sizeof(flag));
        }
        LOGGER->LogLine(L"InternetConnectW error: %d", error);
        return handle;
    }
    else {
        HINTERNET handle = og_InternetConnectW(hInternet, OVERRIDE_URL_W, config.httpServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
        DWORD error = GetLastError();
        LOGGER->LogLine(L"InternetConnectW error: %d", error);
        return handle;
    }
}

int WINAPI hook_getaddrinfo(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFO* pHints, PADDRINFOA* ppResult) {
    LOGGER->LogLine("getaddrinfo: pNodeName: %s  pServiceName: %s ", pNodeName, pServiceName);
    LOGGER->LogLine("pHints");
    LOGGER->LogLine("  ai_flags: %d", pHints->ai_flags);
    LOGGER->LogLine("  ai_family: %d", pHints->ai_family);
    LOGGER->LogLine("  ai_socktype: %d", pHints->ai_socktype);
    LOGGER->LogLine("  ai_protocol: %d", pHints->ai_protocol);
    LOGGER->LogLine("  ai_addrlen: %d", pHints->ai_addrlen);
    LOGGER->LogLine("  ai_canonname: %s", pHints->ai_canonname);

    //&& strcmp(pNodeName, "www.microsoft.com") != 0
    if (pNodeName != nullptr) {
        PCSTR og = pNodeName;
        pNodeName = OVERRIDE_URL;
    }

    int result = og_getaddrinfo(pNodeName, pServiceName, pHints, ppResult);


    struct addrinfo* ptr = NULL;
    int count = 0;
    for (ptr = (addrinfo*)*ppResult; ptr != NULL; ptr = ptr->ai_next) {
        LOGGER->LogLine("Result %d", count);
        LOGGER->LogLine("  ai_flags: %d", ptr->ai_flags);
        LOGGER->LogLine("  ai_family: %d", ptr->ai_family);
        LOGGER->LogLine("  ai_socktype: %d", ptr->ai_socktype);
        LOGGER->LogLine("  ai_protocol: %d", ptr->ai_protocol);
        LOGGER->LogLine("  ai_addrlen: %d", ptr->ai_addrlen);
        LOGGER->LogLine("  ai_canonname: %s", ptr->ai_canonname);

        sockaddr_in* sockaddr_ipv4 = (sockaddr_in*)ptr->ai_addr;
        LOGGER->LogLine("  IPv4 address: %s", inet_ntoa(sockaddr_ipv4->sin_addr));
        LOGGER->LogLine("  IPv4 port: %hu", htons(sockaddr_ipv4->sin_port));
        LOGGER->LogLine("  IPv4 family: 0x%x", sockaddr_ipv4->sin_family);

        count++;
    }


    return result;
}

int WSAAPI hook_connect(SOCKET s, const sockaddr* name, int namelen)
{
    sockaddr_in* sockaddr_ipv4 = (sockaddr_in*)name;
    
    u_short targetPort = htons(sockaddr_ipv4->sin_port);

    LOGGER->LogLine("connect: namelen: %d", namelen);
    LOGGER->LogLine("  IPv4 address: %s", inet_ntoa(sockaddr_ipv4->sin_addr));
    LOGGER->LogLine("  IPv4 port: %hu", htons(sockaddr_ipv4->sin_port));
    LOGGER->LogLine("  IPv4 family: 0x%x", sockaddr_ipv4->sin_family);

    if (targetPort == 80) {
        LOGGER->LogLine("connect: redirect microsoft.com TCP Ping to Notification Server");
        sockaddr_ipv4->sin_port = htons(config.notificationServerPort);
    }

    if (targetPort == ORIGINAL_NS_PORT) {
        LOGGER->LogLine("connect: redirect original Notification Server port");
        sockaddr_ipv4->sin_port = htons(config.notificationServerPort);
    }
    
    int result = og_connect(s, name, namelen);
    LOGGER->LogLine("connect result: 0x%x", result);
    return result;
}

LSTATUS handleRegValueStrW(const wchar_t* dataIn, LPBYTE lpData, LPDWORD lpcbData, LPDWORD lpType) {
    size_t newLengthInBytes = (wcslen(dataIn) + 1) * sizeof(wchar_t);
    if (lpType != nullptr) {
        //Always set field type
        *lpType = REG_SZ;
    }

    if (lpData == nullptr && lpcbData != nullptr) {
        //Call queries for length
        *lpcbData = (DWORD)newLengthInBytes;
        return ERROR_SUCCESS;
    }
    else if (lpData != nullptr && lpcbData != nullptr) {
        if (*lpcbData < newLengthInBytes) {
            // Should never happen since we lied on the size in the previous call
            *lpcbData = (DWORD)newLengthInBytes;
            return ERROR_MORE_DATA;
        }
        *lpcbData = (DWORD)newLengthInBytes;
        size_t newLengthInChars = newLengthInBytes / sizeof(wchar_t);
        wcscpy_s((wchar_t*)lpData, newLengthInChars, dataIn);
        return ERROR_SUCCESS;
    }
    else {
        return ERROR_BAD_ARGUMENTS;
    }
}

LSTATUS WINAPI hook_RegQueryValueExW(HKEY hkey, LPCWSTR lpValueName, LPDWORD lpReserved,
    LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
    if (lpValueName != nullptr) {
        if (wcscmp(lpValueName, L"ppstshost") == 0)
            return handleRegValueStrW(OVERRIDE_URL_W, lpData, lpcbData, lpType);
        else if (wcscmp(lpValueName, L"RemoteFile") == 0) {
            wchar_t remoteFile[256];
            swprintf(remoteFile, 256, L"http://%s:%d/PPCRLconfig.srf", OVERRIDE_URL_W, config.httpServerPort);
            return handleRegValueStrW(remoteFile, lpData, lpcbData, lpType);
        }
    }
    return og_RegQueryValueExW(hkey, lpValueName, lpReserved, lpType, lpData, lpcbData);
}

HRESULT __stdcall hook_CoRegisterClassObject(REFCLSID rclsid, LPUNKNOWN pUnk, CLSCTX dwClsContext, DWORD flags, LPDWORD lpdwRegister)
{
    if (IsEqualCLSID(rclsid, ORIGINAL_CONTACT_CLSID))
    {
        LOGGER->LogLine(L"CoRegisterClassObject: Redirecting ORIGINAL_CONTACT_CLSID -> NEW_CONTACT_CLSID");
        return og_CoRegisterClassObject(NEW_CONTACT_CLSID, pUnk, dwClsContext, flags, lpdwRegister);
    }

    LOGGER->LogLine(L"CoRegisterClassObject: Passing through unmanaged CLSID");
    return og_CoRegisterClassObject(rclsid, pUnk, dwClsContext, flags, lpdwRegister);
}

HRESULT __stdcall hook_CoCreateInstance(REFCLSID rclsid, LPUNKNOWN pUnkOuter, CLSCTX dwClsContext, REFIID riid, LPVOID* ppv)
{
    LPOLESTR clsidStr = nullptr;
    if (StringFromCLSID(rclsid, &clsidStr) == S_OK) {
        LOGGER->LogLine(L"CoCreateInstance: rclsid: %s", clsidStr);
        CoTaskMemFree(clsidStr);
    }

    if (IsEqualCLSID(rclsid, ORIGINAL_CONTACT_CLSID))
    {
        LOGGER->LogLine("CoCreateInstance: Redirecting ORIGINAL_CONTACT_CLSID -> NEW_CONTACT_CLSID");
        HRESULT result = og_CoCreateInstance(NEW_CONTACT_CLSID, pUnkOuter, dwClsContext, riid, ppv);
        LOGGER->LogLine("CoCreateInstance: Result hr=0x%08X", result);
        return result;
    }

    return og_CoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv);
}

HINSTANCE __stdcall hook_ShellExecuteA(HWND hwnd, LPCSTR lpOperation, LPCSTR lpFile, LPCSTR lpParameters, LPCSTR lpDirectory, INT nShowCmd)
{
    LOGGER->LogLine("ShellExecuteA: lpOperation: %s lpFile: %s lpParameters: %s",
        lpOperation, lpFile, lpParameters);

    std::string rewritten = RewriteUrlWithPortA(lpFile, config.httpServerPort);
    if (!rewritten.empty()) {
        LOGGER->LogLine("ShellExecuteA: rewriting URL -> %s", rewritten.c_str());
        return og_ShellExecuteA(hwnd, lpOperation, rewritten.c_str(),
            lpParameters, lpDirectory, nShowCmd);
    }

    return og_ShellExecuteA(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
}

HINSTANCE __stdcall hook_ShellExecuteW(HWND hwnd, LPCWSTR lpOperation, LPCWSTR lpFile, LPCWSTR lpParameters, LPCWSTR lpDirectory, INT nShowCmd)
{
    LOGGER->LogLine(L"ShellExecuteW: lpOperation: %s lpFile: %s lpParameters: %s",
        lpOperation, lpFile, lpParameters);

    std::wstring rewritten = RewriteUrlWithPortW(lpFile, config.httpServerPort);
    if (!rewritten.empty()) {
        LOGGER->LogLine(L"ShellExecuteW: rewriting URL -> %s", rewritten.c_str());
        return og_ShellExecuteW(hwnd, lpOperation, rewritten.c_str(),
            lpParameters, lpDirectory, nShowCmd);
    }

    return og_ShellExecuteW(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
}

BOOL __stdcall hook_ShellExecuteExW(SHELLEXECUTEINFOW* pExecInfo)
{
    if (pExecInfo == nullptr) {
        return og_ShellExecuteExW(pExecInfo);
    }

    LOGGER->LogLine(L"ShellExecuteExW: lpVerb: %s lpFile: %s lpParameters: %s",
        pExecInfo->lpVerb, pExecInfo->lpFile, pExecInfo->lpParameters);

    std::wstring rewritten = RewriteUrlWithPortW(pExecInfo->lpFile, config.httpServerPort);
    if (!rewritten.empty()) {
        LOGGER->LogLine(L"ShellExecuteExW: rewriting URL -> %s", rewritten.c_str());
        // Swap lpFile for the duration of the call. The struct is caller-owned
        // and only read by ShellExecuteEx, so restoring it afterwards.
        LPCWSTR original = pExecInfo->lpFile;
        pExecInfo->lpFile = rewritten.c_str();
        BOOL result = og_ShellExecuteExW(pExecInfo);
        pExecInfo->lpFile = original;
        return result;
    }

    return og_ShellExecuteExW(pExecInfo);
}

HRESULT __stdcall hook_GetWebAuthUrlEx(VOID* hExternalIdentity, IDCRL_WEBAUTHOPTION dwFlags, LPCWSTR szTargetServiceUrl, LPCWSTR wszServicePolicy, LPCWSTR wszAdditionalPostParams, LPCWSTR* pszSHA1UrlOut, LPCWSTR* pszSHA1PostDataOut)
{
    LOGGER->LogLine(L"GetWebAuthUrlEx: szTargetServiceUrl: %s wszServicePolicy: %s wszAdditionalPostParams: %s", szTargetServiceUrl, wszServicePolicy, wszAdditionalPostParams);
    HRESULT result = og_GetWebAuthUrlEx(hExternalIdentity, dwFlags, szTargetServiceUrl, wszServicePolicy, wszAdditionalPostParams, pszSHA1UrlOut, pszSHA1PostDataOut);
    if (result != 0) {
        return result;
    }

    std::wstring proxyUrlFilled(*pszSHA1UrlOut);
    size_t startPathIndex = proxyUrlFilled.find('/', 8);

    std::wstring newUrl(L"http://");
    newUrl.append(OVERRIDE_URL_W);
    newUrl.append(L":");
    newUrl.append(std::to_wstring(config.httpServerPort));

    if (startPathIndex != std::wstring::npos) {
        newUrl.append(proxyUrlFilled.substr(startPathIndex));
    }

    //this is an unchecked copy: if our custom url is bigger than the default pszSHA1UrlOut size, the process will crash.
    //pszSHA1UrlOut is allocated using a custom heap allocator inside msidcrl40.dll
    //It would be a pain to try to free it and allocate a new string in the same space
    //I know that my overidden will always be smaller than the default one, so i'll leave it like this
    wcscpy((wchar_t*)*pszSHA1UrlOut, newUrl.c_str());
    
    LOGGER->LogLine(L"GetWebAuthUrlEx: url: %s postData: %s", *pszSHA1UrlOut, *pszSHA1PostDataOut);
    return ERROR_SUCCESS;
}

