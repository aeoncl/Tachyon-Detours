// dllmain.cpp : Définit le point d'entrée de l'application DLL.
#include "pch.h"
#include "func_types.h"
#include <stdio.h>
#include <fstream>

#include <detours.h>
#pragma comment(lib, "detours")

static BOOL Hooked = FALSE;
static FILE* LogFile = nullptr;

WinVerifyTrustEx_type og_WinVerifyTrustEx = nullptr;
HttpOpenRequestA_type og_HttpOpenRequestA = nullptr;
HttpOpenRequestW_type og_HttpOpenRequestW = nullptr;
InternetConnectA_type og_InternetConnectA = nullptr;
InternetConnectW_type og_InternetConnectW = nullptr;
getaddrinfo_type og_getaddrinfo = nullptr;
connect_type og_connect = nullptr;

void Log(const char* str) {
    if (LogFile != nullptr) {
        fprintf(LogFile, "%s\r\n", str);
        fflush(LogFile);
    }

}

void Log(const wchar_t* str) {
    if (LogFile != nullptr) {
        fwprintf(LogFile, L"%s\r\n", str);
        fflush(LogFile);
    }
}


long WINAPI hook_WinVerifyTrustEx(HWND hwnd, GUID* pgActionID, WINTRUST_DATA* pWinTrustData) {
    Log("WinVerifyTrustEx - pcwszFilePath: ");
    Log(pWinTrustData->pFile->pcwszFilePath);

    if (wcsstr(pWinTrustData->pFile->pcwszFilePath, L"ppcrlconfig.dll") != nullptr) {
        Log("WinVerifyTrustEx - Bypass");
        return ERROR_SUCCESS;
    }

    return og_WinVerifyTrustEx(hwnd, pgActionID, pWinTrustData);
};

HINTERNET WINAPI hook_HttpOpenRequestA(HINTERNET hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer, LPCSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext) {
    //Disables SSL
    Log("HttpOpenRequestA - Hook Called");
    return og_HttpOpenRequestA(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, 0x0, dwContext);
}

HINTERNET WINAPI hook_HttpOpenRequestW(HINTERNET hConnect, LPCWSTR lpszVerb, LPCWSTR lpszObjectName, LPCWSTR lpszVersion, LPCWSTR lpszReferrer, LPCWSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext) {
    //Disables SSL
    Log("HttpOpenRequestA - Hook Called");
    return og_HttpOpenRequestW(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, 0x0, dwContext);
}

HINTERNET WINAPI hook_InternetConnectA(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext) {
    fprintf(LogFile, "InternetConnectA: lpswServerName: %s nServerPort: %d\r\n", lpszServerName, nServerPort);
    fflush(LogFile);
    return og_InternetConnectA(hInternet, "127.0.0.1", 8080, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
}

HINTERNET WINAPI hook_InternetConnectW(HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort, LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext) {
    fwprintf(LogFile, L"InternetConnectA: lpswServerName: %s nServerPort: %d\r\n", lpszServerName, nServerPort);
    fflush(LogFile);
    return og_InternetConnectW(hInternet, L"127.0.0.1", 8080, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
}

int WINAPI hook_getaddrinfo(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFO* pHints, PADDRINFOA* ppResult) {
    fprintf(LogFile, "getaddrinfo: pNodeName: %s  pServiceName: %s \r\n", pNodeName, pServiceName);
    fflush(LogFile);
    if (pNodeName != nullptr) {
        PCSTR og = pNodeName;
        pNodeName = "127.0.0.1";
    }

    if (pServiceName != nullptr && strcmp(pServiceName, "1863") == 0) {
        Log("getaddrinfo - Replace NS port");
        //TODO Replace NS Port
    }

    return og_getaddrinfo(pNodeName, pServiceName, pHints, ppResult);
}

void SetupLogger() {
    LogFile = _fsopen("C:\\temp\\all.log", "a+", _SH_DENYWR);
    Log("Hi");
}

void CleanUp() {
    if (LogFile != nullptr) {
        fclose(LogFile);
    }
}

void Hook() {
    DetourRestoreAfterWith();
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());



    og_WinVerifyTrustEx = (WinVerifyTrustEx_type) DetourFindFunction("wintrust.dll", "WinVerifyTrustEx");
    DetourAttach(&(PVOID&)og_WinVerifyTrustEx, hook_WinVerifyTrustEx);

    og_HttpOpenRequestA = (HttpOpenRequestA_type) DetourFindFunction("wininet.dll", "HttpOpenRequestA");
    DetourAttach(&(PVOID&)og_HttpOpenRequestA, hook_HttpOpenRequestA);

    og_HttpOpenRequestW = (HttpOpenRequestW_type) DetourFindFunction("wininet.dll", "HttpOpenRequestW");
    DetourAttach(&(PVOID&)og_HttpOpenRequestW, hook_HttpOpenRequestW);

    og_InternetConnectA = (InternetConnectA_type) DetourFindFunction("wininet.dll", "InternetConnectA");
    DetourAttach(&(PVOID&)og_InternetConnectA, hook_InternetConnectA);

    og_InternetConnectW = (InternetConnectW_type) DetourFindFunction("wininet.dll", "InternetConnectW");
    DetourAttach(&(PVOID&)og_InternetConnectW, hook_InternetConnectW);

    og_getaddrinfo = (getaddrinfo_type) DetourFindFunction("Ws2_32.dll", "getaddrinfo");
    DetourAttach(&(PVOID&)og_getaddrinfo, hook_getaddrinfo);

    LONG result = DetourTransactionCommit();
    if (result == NO_ERROR) {
        Log("NO ERROR HOOK");

    } else {
        Log("ERROR HOOK");

    }

    Hooked = result == NO_ERROR;
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

    LONG result = DetourTransactionCommit();
    Hooked = !(result == NO_ERROR);
    CleanUp();
}

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