#include "pch.h"
#include "dllmain.h"
#include "logger.h"

#include <detours.h>
#pragma comment(lib, "detours")
//For ntoa TODO remove
#pragma comment(lib, "Ws2_32.lib")

BOOL Hooked = FALSE;
Logger *LOGGER = nullptr;

static const char* OVERRIDE_URL = "127.0.0.1";
static const wchar_t* OVERRIDE_URL_W = L"127.0.0.1";
static const char* OVERRIDE_WEB_PORT = "8080";
static const wchar_t* OVERRIDE_WEB_PORT_W = L"8080";

WinVerifyTrustEx_type og_WinVerifyTrustEx = nullptr;
HttpOpenRequestA_type og_HttpOpenRequestA = nullptr;
HttpOpenRequestW_type og_HttpOpenRequestW = nullptr;
InternetConnectA_type og_InternetConnectA = nullptr;
InternetConnectW_type og_InternetConnectW = nullptr;

getaddrinfo_type og_getaddrinfo = nullptr;
connect_type og_connect = nullptr;

RegQueryValueExW_type og_RegQueryValueExW = nullptr;

GetWebAuthUrlEx_type og_GetWebAuthUrlEx = nullptr;
 
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
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


void SetupLogger() {
    LOGGER = new Logger("C:\\temp\\all.log", true);
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

    og_getaddrinfo = (getaddrinfo_type)DetourFindFunction("Ws2_32.dll", "getaddrinfo");
    DetourAttach(&(PVOID&)og_getaddrinfo, hook_getaddrinfo);

    og_connect = (connect_type)DetourFindFunction("Ws2_32.dll", "connect");
    DetourAttach(&(PVOID&)og_connect, hook_connect);

    og_RegQueryValueExW = (RegQueryValueExW_type)DetourFindFunction("Kernelbase.dll", "RegQueryValueExW");
    DetourAttach(&(PVOID&)og_RegQueryValueExW, hook_RegQueryValueExW);

    og_GetWebAuthUrlEx = (GetWebAuthUrlEx_type)DetourFindFunction("msidcrl40.dll", "GetWebAuthUrlEx");
    if (og_GetWebAuthUrlEx != nullptr) {
        DetourAttach(&(PVOID&)og_GetWebAuthUrlEx, hook_GetWebAuthUrlEx);
    }

    LONG result = DetourTransactionCommit();
    if (result == NO_ERROR) {
        Hooked = true;
        LOGGER->Log("Hooking successfull");
    }
    else {
        LOGGER->Log("Hooking unsuccessfull with error: %d", result);
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

    if (og_GetWebAuthUrlEx != nullptr) {
        DetourDetach(&(PVOID&)og_GetWebAuthUrlEx, hook_GetWebAuthUrlEx);
    }

    LONG result = DetourTransactionCommit();
    LOGGER->Log("Detaching Hooks result: %d", result);
    
    Hooked = !(result == NO_ERROR);
    Cleanup();
}


long WINAPI hook_WinVerifyTrustEx(HWND hwnd, GUID* pgActionID, WINTRUST_DATA* pWinTrustData) {

    LOGGER->Log(L"WinVerifyTrustEx - pcwszFilePath: %s", pWinTrustData->pFile->pcwszFilePath);

    if (wcsstr(pWinTrustData->pFile->pcwszFilePath, L"ppcrlconfig.dll") != nullptr || wcsstr(pWinTrustData->pFile->pcwszFilePath, L"msnmsgr.exe") != nullptr) {
        LOGGER->Log("WinVerifyTrustEx - Bypass");
        return ERROR_SUCCESS;
    }

    return og_WinVerifyTrustEx(hwnd, pgActionID, pWinTrustData);
};

HINTERNET WINAPI hook_HttpOpenRequestA(HINTERNET hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer, LPCSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext) {
    //Disables SSL
    LOGGER->Log("HttpOpenRequestA - Hook Called");
    return og_HttpOpenRequestA(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, 0x0, dwContext);
}

HINTERNET WINAPI hook_HttpOpenRequestW(HINTERNET hConnect, LPCWSTR lpszVerb, LPCWSTR lpszObjectName, LPCWSTR lpszVersion, LPCWSTR lpszReferrer, LPCWSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext) {
    //Disables SSL
    LOGGER->Log("HttpOpenRequestA - Hook Called");
    return og_HttpOpenRequestW(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, 0x0, dwContext);
}

HINTERNET WINAPI hook_InternetConnectA(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext) {
    LOGGER->Log("InternetConnectA: lpswServerName: %s nServerPort: %d dwFlags: 0x%x", lpszServerName, nServerPort, dwFlags);
    HINTERNET handle = og_InternetConnectA(hInternet, "127.0.0.1", 8080, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);

    DWORD error = GetLastError();
    LOGGER->Log("InternetConnectA error: %d", error);

    return handle;
}

HINTERNET WINAPI hook_InternetConnectW(HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort, LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext) {
    LOGGER->Log(L"InternetConnectA: lpswServerName: %s nServerPort: %d", lpszServerName, nServerPort);
    return og_InternetConnectW(hInternet, L"127.0.0.1", 8080, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
}

int WINAPI hook_getaddrinfo(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFO* pHints, PADDRINFOA* ppResult) {
    LOGGER->Log("getaddrinfo: pNodeName: %s  pServiceName: %s ", pNodeName, pServiceName);
    LOGGER->Log("pHints");
    LOGGER->Log("  ai_flags: %d", pHints->ai_flags);
    LOGGER->Log("  ai_family: %d", pHints->ai_family);
    LOGGER->Log("  ai_socktype: %d", pHints->ai_socktype);
    LOGGER->Log("  ai_protocol: %d", pHints->ai_protocol);
    LOGGER->Log("  ai_addrlen: %d", pHints->ai_addrlen);
    LOGGER->Log("  ai_canonname: %s", pHints->ai_canonname);

    //&& strcmp(pNodeName, "www.microsoft.com") != 0
    if (pNodeName != nullptr) {
        PCSTR og = pNodeName;
        pNodeName = "127.0.0.1";
    }

    if (pServiceName != nullptr && strcmp(pServiceName, "1863") == 0) {
        LOGGER->Log("getaddrinfo - Replace NS port");
        //TODO Replace NS Port
    }

    int result = og_getaddrinfo(pNodeName, pServiceName, pHints, ppResult);


    struct addrinfo* ptr = NULL;
    int count = 0;
    for (ptr = (addrinfo*)*ppResult; ptr != NULL; ptr = ptr->ai_next) {
        LOGGER->Log("Result %d", count);
        LOGGER->Log("  ai_flags: %d", ptr->ai_flags);
        LOGGER->Log("  ai_family: %d", ptr->ai_family);
        LOGGER->Log("  ai_socktype: %d", ptr->ai_socktype);
        LOGGER->Log("  ai_protocol: %d", ptr->ai_protocol);
        LOGGER->Log("  ai_addrlen: %d", ptr->ai_addrlen);
        LOGGER->Log("  ai_canonname: %s", ptr->ai_canonname);

        sockaddr_in* sockaddr_ipv4 = (sockaddr_in*)ptr->ai_addr;
        LOGGER->Log("  IPv4 address: %s", inet_ntoa(sockaddr_ipv4->sin_addr));
        LOGGER->Log("  IPv4 port: %hu", htons(sockaddr_ipv4->sin_port));
        LOGGER->Log("  IPv4 family: 0x%x", sockaddr_ipv4->sin_family);

        count++;
    }


    return result;
}

int WSAAPI hook_connect(SOCKET s, const sockaddr* name, int namelen)
{
    sockaddr_in* sockaddr_ipv4 = (sockaddr_in*)name;
    
    u_short targetPort = htons(sockaddr_ipv4->sin_port);

    LOGGER->Log("connect: namelen: %d", namelen);
    LOGGER->Log("  IPv4 address: %s", inet_ntoa(sockaddr_ipv4->sin_addr));
    LOGGER->Log("  IPv4 port: %hu", htons(sockaddr_ipv4->sin_port));
    LOGGER->Log("  IPv4 family: 0x%x", sockaddr_ipv4->sin_family);

    if (targetPort == 80) {
        LOGGER->Log("connect: redirect microsoft.com TCP Ping to Notification Server");
        sockaddr_ipv4->sin_port = ntohs(1863);
    }
    
    int result = og_connect(s, name, namelen);
    LOGGER->Log("connect result: 0x%x", result);
    return result;
}

LSTATUS handleRegValueStrW(const wchar_t* dataIn, LPBYTE lpData, LPDWORD lpcbData) {
    size_t newLength = (wcslen(dataIn) + 1) * sizeof(wchar_t);

    if (lpData == nullptr && lpcbData != nullptr) {
        //Return the length of data;
        *lpcbData = newLength + 20;
        LOGGER->Log("Override reg string length: %d", *lpcbData);
        return ERROR_SUCCESS;
    }
    else if (lpData != nullptr && lpcbData != nullptr) {
        //return data;
        *lpcbData = newLength;
        wcscpy_s((wchar_t*)lpData, *lpcbData, dataIn);
        LOGGER->Log(L"Override reg string data: %s", (wchar_t*)lpData);
        return ERROR_SUCCESS;
    }
    else {
        return ERROR_BAD_ARGUMENTS;
    }
}

//hi ani :D
LSTATUS WINAPI hook_RegQueryValueExW(HKEY hkey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
    //LOGGER->Log(L"RegQueryValueExW: lpValueName: %s lpType: isNull: %d lpData isNull: %d lpcbData isNull: %d", lpValueName, lpType == nullptr, lpData == nullptr, lpcbData == nullptr);
    LSTATUS result = og_RegQueryValueExW(hkey, lpValueName, lpReserved, lpType, lpData, lpcbData);

    if (result != ERROR_SUCCESS) {
        return result;
    }

    if (lpValueName != nullptr) {
        if (wcscmp(lpValueName, L"ppstshost") == 0) {
            return handleRegValueStrW(OVERRIDE_URL_W, lpData, lpcbData);
        }
        else if (wcscmp(lpValueName, L"RemoteFile") == 0) {
            return handleRegValueStrW(L"http://127.0.0.1:8080/PPCRLconfig.srf", lpData, lpcbData);
        }
    }
    return result;
}

HRESULT __stdcall hook_GetWebAuthUrlEx(VOID* hExternalIdentity, IDCRL_WEBAUTHOPTION dwFlags, LPCWSTR szTargetServiceUrl, LPCWSTR wszServicePolicy, LPCWSTR wszAdditionalPostParams, LPCWSTR* pszSHA1UrlOut, LPCWSTR* pszSHA1PostDataOut)
{
    LOGGER->Log(L"GetWebAuthUrlEx: szTargetServiceUrl: %s wszServicePolicy: %s wszAdditionalPostParams: %s", szTargetServiceUrl, wszServicePolicy, wszAdditionalPostParams);
    HRESULT result = og_GetWebAuthUrlEx(hExternalIdentity, dwFlags, szTargetServiceUrl, wszServicePolicy, wszAdditionalPostParams, pszSHA1UrlOut, pszSHA1PostDataOut);
    if (result != 0) {
        return result;
    }

    std::wstring proxyUrlFilled(*pszSHA1UrlOut);
    size_t startPathIndex = proxyUrlFilled.find('/', 8);

    std::wstring newUrl(L"http://");
    newUrl.append(OVERRIDE_URL_W);
    newUrl.append(L":");
    newUrl.append(OVERRIDE_WEB_PORT_W);

    if (startPathIndex > 0) {
        newUrl.append(proxyUrlFilled.substr(startPathIndex, -1));
    }

    wcscpy((wchar_t*)*pszSHA1UrlOut, newUrl.c_str());
    
    LOGGER->Log(L"GetWebAuthUrlEx: url: %s postData: %s", *pszSHA1UrlOut, *pszSHA1PostDataOut);
    return ERROR_SUCCESS;
}

