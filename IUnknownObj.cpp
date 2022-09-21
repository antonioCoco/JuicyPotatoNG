#include "IUnknownObj.h"

IUnknownObj::IUnknownObj() {
	m_cRef = 1;
	return;
}

///////////////////////IUknown Interface
HRESULT IUnknownObj::QueryInterface(const IID& riid, void** ppvObj) {
	// Always set out parameter to NULL, validating it first.
	if (!ppvObj) {
		//printf("QueryInterface INVALID\n");
		return E_INVALIDARG;
	}
	if (riid == IID_IUnknown)
	{
		*ppvObj = static_cast<IUnknownObj*>(this);
		reinterpret_cast<IUnknown*>(*ppvObj)->AddRef();
	}
	else
	{
		*ppvObj = NULL;
		//printf("QueryInterface NOINT\n");
		return E_NOINTERFACE;
	}
	// Increment the reference count and return the pointer.
	return S_OK;
}

ULONG IUnknownObj::AddRef() {
	m_cRef++;
	return m_cRef;
}

ULONG IUnknownObj::Release() {
	// Decrement the object's internal counter.
	ULONG ulRefCount = m_cRef--;
	return ulRefCount;
}