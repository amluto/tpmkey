/* -*- mode: c++; c-file-style: "bsd" -*-

TSPI helpers for TPMKey

Copyright (c) 2011 Andrew Lutomirski.  All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY ANDREW LUTOMIRSKI ``AS IS'' AND ANY EXPRESS
OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL ANDREW LUTOMIRSKI OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
THE POSSIBILITY OF SUCH DAMAGE.

*/

#pragma once
#include <tss/tspi.h>
#include <tr1/memory>
#include <stdexcept>
#include <malloc.h>
#include <sstream>

class TPMError : public std::runtime_error
{
public:
	TSS_RESULT code;
	const char *failing_call;

	explicit TPMError(TSS_RESULT code, const char *failing_call)
		: std::runtime_error("TSPI error"),
		  code(code), failing_call(failing_call)
	{
		std::ostringstream ss;
		ss << "TSPI call " << failing_call << " failed with code " << (void*)(uintptr_t)code;
		what_val = ss.str();
	}

	~TPMError() throw() {}

	const char *what() const throw() { return what_val.c_str(); }

private:
	std::string what_val;
};

#define CHECK_TSPI_CALL(fn, ...) do {					\
	TSS_RESULT result = fn(__VA_ARGS__);				\
	if (result != TSS_SUCCESS) {					\
		throw TPMError(result, #fn);				\
	}								\
} while(0)


class TPMNoncopyable
{
public:
	TPMNoncopyable() {}

private:
	TPMNoncopyable(const TPMNoncopyable &);
	void operator = (const TPMNoncopyable &);
};

class FD : TPMNoncopyable
{
public:
	int fd;

	FD() : fd(-1) {}
	~FD() { if (fd != -1) close(fd); }
};

class TPMOwnerObj;  // An HTPM

class TPMContext
	: public std::tr1::enable_shared_from_this<TPMContext>, TPMNoncopyable
{
public:
	TSS_HCONTEXT handle;

	void Connect()
	{
		CHECK_TSPI_CALL(Tspi_Context_Connect, handle, 0);
	}

	TPMContext() : htpm_(0)
	{
		CHECK_TSPI_CALL(Tspi_Context_Create, &handle);
	}

	~TPMContext()
	{
		Tspi_Context_Close(handle);
	}

	typedef std::tr1::shared_ptr<TPMContext> Ptr;

	TSS_HTPM get_htpm()
	{
		if (htpm_)
			return htpm_;

		CHECK_TSPI_CALL(Tspi_Context_GetTpmObject, handle, &htpm_);
		return htpm_;
	}

	std::tr1::shared_ptr<class TPMBuffer> GetRandom(UINT32 len);

private:
	TSS_HTPM htpm_;
};

class TPMBuffer : TPMNoncopyable
{
public:
	void *data;
	UINT32 len, alloc_len;
	TPMContext::Ptr context;  // May be null; if so, free() is used.

	typedef std::tr1::shared_ptr<TPMBuffer> Ptr;

	explicit TPMBuffer(TPMContext::Ptr context) : data(0), len(0), alloc_len(0), context(context) {}

	explicit TPMBuffer(UINT32 alloc_len) : data(malloc(alloc_len)), len(0), alloc_len(alloc_len)
	{
	}

	~TPMBuffer()
	{
		if (data) {
			if (context)
				Tspi_Context_FreeMemory(context->handle, (BYTE*)data);
			else
				free(data);
		}
	}
};

class TPMObjectBase : TPMNoncopyable
{
public:
	std::tr1::shared_ptr<TPMContext> context;
	TSS_HOBJECT handle;

	~TPMObjectBase()
	{
		Tspi_Context_CloseObject(context->handle, handle);
	}

	TPMBuffer::Ptr GetAttribData(TSS_FLAG attr, TSS_FLAG sub)
	{
		BYTE *data;
		UINT32 len;
		CHECK_TSPI_CALL(Tspi_GetAttribData,
				handle, attr, sub, &len, &data);
		TPMBuffer::Ptr ret(new TPMBuffer(context));
		ret->data = data;
		ret->len = len;
		ret->alloc_len = len;
		return ret;
	}

	UINT32 GetAttribUint32(TSS_FLAG attr, TSS_FLAG sub)
	{
		UINT32 ret;
		CHECK_TSPI_CALL(Tspi_GetAttribUint32,
				handle, attr, sub, &ret);
		return ret;
	}

	void SetAttribUint32(TSS_FLAG attr, TSS_FLAG sub, UINT32 val)
	{
		CHECK_TSPI_CALL(Tspi_SetAttribUint32, handle,
				attr, sub, val);

	}

	void SetAttribData(TSS_FLAG attr, TSS_FLAG sub, const void *data, UINT32 len)
	{
		CHECK_TSPI_CALL(Tspi_SetAttribData, handle,
				attr, sub, len, reinterpret_cast<BYTE *>(const_cast<void *>(data)));

	}

protected:
	explicit TPMObjectBase(TPMContext::Ptr context, TSS_HOBJECT handle)
		: context(context), handle(handle)
	{}
};

class TPMHash : public TPMObjectBase
{
public:
	typedef std::tr1::shared_ptr<TPMHash> Ptr;

	static Ptr Create(TPMContext::Ptr context, TSS_FLAG type)
	{
		TSS_HPOLICY hash;
		CHECK_TSPI_CALL(Tspi_Context_CreateObject,
				context->handle, TSS_OBJECT_TYPE_HASH,
				type, &hash);
		return Ptr(new TPMHash(context, hash));
	}

private:
	explicit TPMHash(TPMContext::Ptr context, TSS_HOBJECT handle)
		: TPMObjectBase(context, handle)
	{}
};

class TPMPolicy : public TPMObjectBase
{
public:
	typedef std::tr1::shared_ptr<TPMPolicy> Ptr;

	static Ptr Create(TPMContext::Ptr context, TSS_FLAG type)
	{
		TSS_HPOLICY policy;
		CHECK_TSPI_CALL(Tspi_Context_CreateObject,
				context->handle, TSS_OBJECT_TYPE_POLICY,
				type, &policy);
		return Ptr(new TPMPolicy(context, policy));
	}

private:
	explicit TPMPolicy(TPMContext::Ptr context, TSS_HOBJECT handle)
		: TPMObjectBase(context, handle)
	{}
};

class TPMRsaKey : public TPMObjectBase
{
public:
	typedef std::tr1::shared_ptr<TPMRsaKey> Ptr;

	static Ptr GetSRK(TPMContext::Ptr context)
	{
		TSS_HKEY srk;
		TSS_UUID srk_uuid = TSS_UUID_SRK;
		CHECK_TSPI_CALL(Tspi_Context_LoadKeyByUUID,
				context->handle, TSS_PS_TYPE_SYSTEM,
				srk_uuid, &srk);
		return Ptr(new TPMRsaKey(context, srk));
	}

	static Ptr Create(TPMContext::Ptr context, TSS_FLAG keyflags)
	{
		TSS_HKEY handle;
		CHECK_TSPI_CALL(Tspi_Context_CreateObject,
				context->handle, TSS_OBJECT_TYPE_RSAKEY,
				keyflags, &handle);
		return Ptr(new TPMRsaKey(context, handle));
	}

	void SetUsageSecret(TSS_FLAG mode, const void *data, size_t len)
	{
		TPMPolicy::Ptr new_policy =
			TPMPolicy::Create(context, TSS_POLICY_USAGE);
		CHECK_TSPI_CALL(Tspi_Policy_SetSecret, new_policy->handle,
				mode, len,
				reinterpret_cast<BYTE *>(const_cast<void *>(data)));

		usage_policy.reset();
		CHECK_TSPI_CALL(Tspi_Policy_AssignToObject,
				new_policy->handle, handle);
		usage_policy = new_policy;
	}

	void SetUsageWKS()
	{
		BYTE wks[20] = TSS_WELL_KNOWN_SECRET;
		SetUsageSecret(TSS_SECRET_MODE_SHA1, wks, sizeof(wks));
	}

	void SetUsagePopup()
	{
		SetUsageSecret(TSS_SECRET_MODE_POPUP, 0, 0);
	}

	TPMBuffer::Ptr GetPubKey()
	{
		BYTE *data;
		UINT32 len;
		CHECK_TSPI_CALL(Tspi_Key_GetPubKey, handle, &len, &data);
		TPMBuffer::Ptr ret(new TPMBuffer(context));
		ret->data = data;
		ret->len = len;
		return ret;
	}

	TPMBuffer::Ptr Sign(TSS_FLAG hashtype, const void *data, size_t len)
	{
		TPMHash::Ptr hashobj =
			TPMHash::Create(context, hashtype);
		if (len != (UINT32)len)
			throw std::runtime_error("Input too large");
		CHECK_TSPI_CALL(Tspi_Hash_SetHashValue, hashobj->handle,
				len, const_cast<BYTE*>((BYTE*)data));
		BYTE *outdata;
		UINT32 outlen;
		CHECK_TSPI_CALL(Tspi_Hash_Sign, hashobj->handle, handle,
				&outlen, &outdata);
		TPMBuffer::Ptr ret(new TPMBuffer(context));
		ret->data = outdata;
		ret->len = outlen;
		return ret;
	}

private:
	explicit TPMRsaKey(TPMContext::Ptr context, TSS_HOBJECT handle)
		: TPMObjectBase(context, handle)
	{}

	TPMPolicy::Ptr usage_policy;
};

#define V(prefix, flag) if (x != (prefix##flag)) {} else return #flag

inline const char *keyinfo_usage_to_string(TSS_FLAG x)
{
	V(TSS_KEYUSAGE_, BIND);
	V(TSS_KEYUSAGE_, IDENTITY);
	V(TSS_KEYUSAGE_, LEGACY);
	V(TSS_KEYUSAGE_, SIGN);
	V(TSS_KEYUSAGE_, STORAGE);
	V(TSS_KEYUSAGE_, AUTHCHANGE);
	V(TSS_KEYUSAGE_, MIGRATE);

	return "[unknown]";
}

#undef V
