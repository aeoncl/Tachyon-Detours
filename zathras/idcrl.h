#pragma once
#include <WinDef.h>

enum IDCRL_OPTION_ID {
	IDCRL_OPTION_PROXY = 0x00000001,
	IDCRL_OPTION_CONNECT_TIMEOUT = 0x00000002,
	IDCRL_OPTION_SEND_TIMEOUT = 0x00000004,
	IDCRL_OPTION_RECEIVE_TIMEOUT = 0x00000008,
	IDCRL_OPTION_PROXY_PASSWORD = 0x00000010,
	IDCRL_OPTION_PROXY_USERNAME = 0x00000020,
	IDCRL_OPTION_ENVIRONMENT = 0x00000040,
	IDCRL_OPTION_ALL_BIT = 0x0000007F,
	IDCRL_OPTION_MSC_TIMEOUT = 0x00000080
};

enum UPDATE_FLAG {
	DEFAULT_UPDATE_POLICY = 0x00000000,
	UPDATE_DEFAULT = 0x00000000,
	OFFLINE_MODE_ALLOWED = 0x00000001,
	NO_UI = 0x00000002,
	SKIP_CONNECTION_CHECK = 0x00000004,
	SET_EXTENDED_ERROR = 0x00000008,
	SET_INITIALIZATION_COOKIES = 0x00000010,
	UPDATE_FLAG_ALL_BIT = 0x0000001F
};

enum IDCRL_WEBAUTHOPTION {
	IDCRL_WEBAUTH_NONE = 0,
	IDCRL_WEBAUTH_REAUTH = 1,
	IDCRL_WEBAUTH_PERSISTENT = 2
};

struct IDCRL_OPTION {
	IDCRL_OPTION_ID dwId;
	PBYTE pValue;
	size_t cbValue;
};




//msidcrl40
typedef HRESULT(__stdcall* GetUserExtendedProperty_type)(LPCWSTR wszUserName, LPCWSTR wszPropertyName, LPBYTE pwzPropertyValue);
typedef HRESULT(__stdcall* InitializeEx_type)(REFGUID appId, long idclrVersion, UPDATE_FLAG dwflags, IDCRL_OPTION pOptions[], DWORD dwOptions);
typedef HRESULT(__stdcall* Initialize_type)(REFGUID appId, long idclrVersion, UPDATE_FLAG dwflags);
typedef HRESULT(__stdcall* SetIdcrlOptions_type)(IDCRL_OPTION pOptions[], DWORD dwOptions, UPDATE_FLAG dwflags);
typedef HRESULT(__stdcall* GetWebAuthUrlEx_type)(VOID* hExternalIdentity, IDCRL_WEBAUTHOPTION dwFlags, LPCWSTR szTargetServiceUrl, LPCWSTR wszServicePolicy, LPCWSTR wszAdditionalPostParams, LPCWSTR* pszSHA1UrlOut, LPCWSTR* pszSHA1PostDataOut);
/*
Too bad this causes a deadlock 8 times out of 10 
Detouuuurs :@@@@@

HRESULT __stdcall hook_InitializeEx(REFGUID appId, long idclrVersion, UPDATE_FLAG dwflags, IDCRL_OPTION pOptions[], DWORD dwOptions)
{
	LOGGER->Log("MSIDCRL InitializeEx");

	for (DWORD i = 0; i < dwOptions; i++) {
		IDCRL_OPTION current = pOptions[i];
		if (current.dwId == IDCRL_OPTION_ID::IDCRL_OPTION_ENVIRONMENT) {
			const wchar_t* newEnv = L"Tachyon";
			wchar_t* dest = (wchar_t*)current.pValue;
			LOGGER->Log(L"ENV: %s", dest);
			errno_t error = wcscpy_s(dest, current.cbValue, newEnv);
			LOGGER->Log(L"Replace Environment... err string copy: %d - Value: %s", error, dest);
		}
	}

	HRESULT test = og_Initialize(appId, idclrVersion, dwflags);
	HRESULT test2 = og_SetIdcrlOptions(pOptions, dwOptions, dwflags);

	return test;
}
*/

/*
* Leaving this here in case it's useful later
HRESULT __stdcall hook_GetUserExtendedProperty(LPCWSTR wszUserName, LPCWSTR wszPropertyName, LPBYTE pwzPropertyValue)
{
	LOGGER->Log(L"GetExtendedProperty: username: %s - propertyName: %s", wszUserName, wszPropertyName);
	int result = og_GetUserExtendedProperty(wszUserName, wszPropertyName, pwzPropertyValue);



	std::wstring Test((LPCWSTR)pwzPropertyValue);

	LOGGER->Log(L"Result: %d Len: %s", result, Test.c_str());

	printString(pwzPropertyValue);

	//LOGGER->Log(L"GetExtendedProperty: %s", test);
	//LOGGER->Log(L"GetExtendedProperty: %x", test);

	return result;
}
*/

/*

HRESULT __stdcall hook_GetWebAuthUrlEx(VOID* hExternalIdentity, IDCRL_WEBAUTHOPTION dwFlags, LPCWSTR szTargetServiceUrl, LPCWSTR wszServicePolicy, LPCWSTR wszAdditionalPostParams, LPCWSTR* pszSHA1UrlOut, LPCWSTR* pszSHA1PostDataOut)
{
	//Works only if the output string
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

	LOGGER->Log(L"GERTTTTT DEBUG: %s", (wchar_t*)*pszSHA1UrlOut);

	memset((wchar_t*)*pszSHA1UrlOut, 0, wcslen(*pszSHA1UrlOut) * sizeof(wchar_t));
	LOGGER->Log(L"GERTTTTT DEBUG2: %s", (wchar_t*)*pszSHA1UrlOut);

	wcscpy((wchar_t*)*pszSHA1UrlOut, newUrl.c_str());
	LOGGER->Log(L"GERTTTTT DEBUG3: %s", (wchar_t*)*pszSHA1UrlOut);

	LOGGER->Log(L"GetWebAuthUrlEx: url: %s postData: %s", *pszSHA1UrlOut, *pszSHA1PostDataOut);
	return ERROR_SUCCESS;
}
*/