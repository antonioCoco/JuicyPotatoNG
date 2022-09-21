#define SECURITY_WIN32 

#pragma once
#include "Windows.h"

void HookSSPIForTokenStealing(wchar_t* clsid);
