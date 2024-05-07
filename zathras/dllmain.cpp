#include "pch.h"
#include "dllmain.h"
#include "logger.h"

#include <detours.h>
#pragma comment(lib, "detours")

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
InternetCrackUrlW_type og_InternetCrackUrlW = nullptr;

getaddrinfo_type og_getaddrinfo = nullptr;
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

    og_InternetCrackUrlW = (InternetCrackUrlW_type)DetourFindFunction("wininet.dll", "InternetCrackUrlW");
    DetourAttach(&(PVOID&)og_InternetCrackUrlW, hook_InternetCrackUrlW);

    og_getaddrinfo = (getaddrinfo_type)DetourFindFunction("Ws2_32.dll", "getaddrinfo");
    DetourAttach(&(PVOID&)og_getaddrinfo, hook_getaddrinfo);

    og_RegQueryValueExW = (RegQueryValueExW_type)DetourFindFunction("kernelbase.dll", "RegQueryValueExW");
    DetourAttach(&(PVOID&)og_RegQueryValueExW, hook_RegQueryValueExW);

    og_GetWebAuthUrlEx = (GetWebAuthUrlEx_type)DetourFindFunction("msidcrl40.dll", "GetWebAuthUrlEx");
    DetourAttach(&(PVOID&)og_GetWebAuthUrlEx, hook_GetWebAuthUrlEx);

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
    DetourDetach(&(PVOID&)og_InternetCrackUrlW, hook_InternetCrackUrlW);
    DetourDetach(&(PVOID&)og_getaddrinfo, hook_getaddrinfo);
    DetourDetach(&(PVOID&)og_RegQueryValueExW, hook_RegQueryValueExW);
    DetourDetach(&(PVOID&)og_GetWebAuthUrlEx, hook_GetWebAuthUrlEx);


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
    LOGGER->Log("InternetConnectA: lpswServerName: %s nServerPort: %d", lpszServerName, nServerPort);
    return og_InternetConnectA(hInternet, "127.0.0.1", 8080, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
}

HINTERNET WINAPI hook_InternetConnectW(HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort, LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext) {
    LOGGER->Log(L"InternetConnectA: lpswServerName: %s nServerPort: %d", lpszServerName, nServerPort);
    return og_InternetConnectW(hInternet, L"127.0.0.1", 8080, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
}

int WINAPI hook_getaddrinfo(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFO* pHints, PADDRINFOA* ppResult) {
    LOGGER->Log("getaddrinfo: pNodeName: %s  pServiceName: %s ", pNodeName, pServiceName);
    if (pNodeName != nullptr) {
        PCSTR og = pNodeName;
        pNodeName = "127.0.0.1";
    }

    if (pServiceName != nullptr && strcmp(pServiceName, "1863") == 0) {
        LOGGER->Log("getaddrinfo - Replace NS port");
        //TODO Replace NS Port
    }

    return og_getaddrinfo(pNodeName, pServiceName, pHints, ppResult);
}

LSTATUS handleRegValueStrW(const wchar_t* dataIn, LPBYTE lpData, LPDWORD lpcbData) {
    if (lpData == nullptr && lpcbData != nullptr) {
        //Return the length of data;
        *lpcbData = ((wcslen(dataIn) + 1) * sizeof(wchar_t)) + 20;
        LOGGER->Log("Override reg string length: %d", *lpcbData);
        return ERROR_SUCCESS;
    }
    else if (lpData != nullptr && lpcbData != nullptr) {
        //return data;
        wcscpy_s((wchar_t*)lpData, *lpcbData, dataIn);
        *lpcbData = ((wcslen(dataIn) + 1) * sizeof(wchar_t));
        LOGGER->Log(L"Override reg string data: %s", (wchar_t*)lpData);
        return ERROR_SUCCESS;
    }
}

LSTATUS WINAPI hook_RegQueryValueExW(HKEY hkey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
    LOGGER->Log(L"RegQueryValueExW: lpValueName: %s lpType: isNull: %d lpData isNull: %d lpcbData isNull: %d", lpValueName, lpType == nullptr, lpData == nullptr, lpcbData == nullptr);
    LSTATUS result = og_RegQueryValueExW(hkey, lpValueName, lpReserved, lpType, lpData, lpcbData);

    if (result != ERROR_SUCCESS) {
        return result;
    }

    if (lpValueName != nullptr) {
        if (wcscmp(lpValueName, L"ppstshost") == 0)
        {
            return handleRegValueStrW(L"127.0.0.1:8080", lpData, lpcbData);
        }
        else if (wcscmp(lpValueName, L"ppstsport") == 0) {
            return handleRegValueStrW(OVERRIDE_WEB_PORT_W, lpData, lpcbData);
        }
        else if (wcscmp(lpValueName, L"RemoteFile") == 0) {
            return handleRegValueStrW(L"http://127.0.0.1:8080/PPCRLconfig.srf", lpData, lpcbData);
        }
    }
    return result;
}

BOOL __stdcall hook_InternetCrackUrlW(LPCWSTR lpszUrl, DWORD dwUrlLength, DWORD dwFlags, LPURL_COMPONENTSW lpUrlComponents)
{
    LOGGER->Log(L"InternetCrackUrlW: %s dwFlags: %d", lpszUrl, dwFlags);
    return og_InternetCrackUrlW(lpszUrl, dwUrlLength, dwFlags, lpUrlComponents);
    /*
    URL_COMPONENTSW lpUrlComponents2 = *lpUrlComponents;

    LOGGER->Log(L"InternetCrackUrlW: %s dwFlags: %d", lpszUrl, dwFlags);
    BOOL result = og_InternetCrackUrlW(lpszUrl, dwUrlLength, dwFlags, &lpUrlComponents2);
    if (result == FALSE) {
        return result;
    }

    std::wstring newUrl(L"http://");
    newUrl.append(OVERRIDE_URL_W);
    newUrl.append(L":");
    newUrl.append(OVERRIDE_WEB_PORT_W);
    newUrl.append(lpUrlComponents2.lpszUrlPath);

    BOOL result2 = og_InternetCrackUrlW(newUrl.c_str(), newUrl.length(), dwFlags, lpUrlComponents);
    LOGGER->Log(L"InternetCrackUrlW: newUrl: %s newResult(T is 1): %d", newUrl.c_str(), result2);

    if (result2 == FALSE){
        LOGGER->Log("InternetCrackUrlW: Error: 0x%x", GetLastError());
    }

    return result2;
    */
}




HRESULT __stdcall hook_GetWebAuthUrlEx(VOID* hExternalIdentity, IDCRL_WEBAUTHOPTION dwFlags, LPCWSTR szTargetServiceUrl, LPCWSTR wszServicePolicy, LPCWSTR wszAdditionalPostParams, LPCWSTR* pszSHA1UrlOut, LPCWSTR* pszSHA1PostDataOut)
{
    //Change https to http for sha1 url
    LOGGER->Log(L"GetWebAuthUrlEx: szTargetServiceUrl: %s wszServicePolicy: %s wszAdditionalPostParams: %s", szTargetServiceUrl, wszServicePolicy, wszAdditionalPostParams);
    HRESULT result = og_GetWebAuthUrlEx(hExternalIdentity, dwFlags, szTargetServiceUrl, wszServicePolicy, wszAdditionalPostParams, pszSHA1UrlOut, pszSHA1PostDataOut);
    if (result != 0) {
        return result;
    }

    std::wstring httpSanitizedUrl(*pszSHA1UrlOut);

    size_t httpsIndexOf = httpSanitizedUrl.find(L"https");
    if (httpsIndexOf >= 0) {
        httpSanitizedUrl.replace(httpsIndexOf, 5, L"http");
    }

    //HRESULT cpyResult = wcscpy_s((wchar_t*)*pszSHA1UrlOut, (wcslen((wchar_t*)*pszSHA1UrlOut) + 1) * sizeof(wchar_t), httpSanitizedUrl.c_str());
    wcscpy((wchar_t*)*pszSHA1UrlOut, httpSanitizedUrl.c_str());

    LOGGER->Log(L"GetWebAuthUrlEx: url: %s postData: %s cpyResult: 0x%x", *pszSHA1UrlOut, *pszSHA1PostDataOut, 0);
    return ERROR_SUCCESS;
}


