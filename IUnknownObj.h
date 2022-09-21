#pragma once
#include "Objidl.h"

class IUnknownObj : public IUnknown {
private:
	int m_cRef;
public:
	IUnknownObj();
	HRESULT STDMETHODCALLTYPE QueryInterface(const IID& riid, void** ppvObject);
	ULONG STDMETHODCALLTYPE AddRef();
	ULONG STDMETHODCALLTYPE Release();
};