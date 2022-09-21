#pragma once
#include "Windows.h"
#include "winternl.h"

#define DEFAULT_BUFLEN 8192

void InitComServer();
HRESULT UnmarshallIStorage(PWCHAR clsidStr);
void PotatoTrigger(PWCHAR clsidStr, PWCHAR comPort, HANDLE hEventWait);
void base64Decode(PWCHAR b64Text, int b64TextLen, char* buffer, DWORD* bufferLen);

typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);