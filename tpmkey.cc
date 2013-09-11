/* -*- mode: c++; c-file-style: "bsd" -*-

TPMKey conversion commands

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

Some licensing-related things to be aware of:

 - trousers is CPL.
 - opencryptoki (which I might want to interoperate with someday) is CPL
 - libgcrypt is LPGL.
 - openssl (which I probably won't use) has a messy license.
 - The TSPI interface itself is just a specification.  This code
   as it stands right now is developed using the spec as a reference, not
   the trousers implementation of the spec (except for testing).
 - PKCS #11 is a spec.  Its associated header file is available under a
   a license that I don't understand.
 - GnuPG has political and/or ideological issues with PKCS #11.  I do *not*
   want tpmkey to get mired in the same issues.  Interoperating with GnuPG
   will probably always be a giant PITA, but I don't interoperating with
   normal PKCS #11 clients to be a similar mess.

*/

#include "tspi_helpers.h"
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <malloc.h>
#include <argp.h>


class TpmKeyContext
{
public:
	int dirfd;
	TPMContext::Ptr tpm_context;
};

class Buffer
{
public:
	void *data;
	size_t len, alloc_len;

	Buffer() : data(0), len(0), alloc_len(0) {}
	explicit Buffer(size_t alloc_len)
		: data(malloc(alloc_len)), len(0), alloc_len(alloc_len)
	{
	}
	~Buffer() { free(data); }

	typedef std::tr1::shared_ptr<Buffer> Ptr;
};

namespace TpmKey {

void InitDir(const char *path)
{
	TPMContext::Ptr context(new TPMContext);
	context->Connect();
	TPMRsaKey::Ptr srk = TPMRsaKey::GetSRK(context);
	srk->SetUsageWKS();

	FD dirfd;
	if (mkdir(path, 0700) != 0)
		throw std::runtime_error("Failed to create directory");
	dirfd.fd = open(path, O_RDONLY | O_DIRECTORY, 0);
	if (dirfd.fd == -1)
		throw std::runtime_error("Failed to open directory");

	WriteNewFile(dirfd.fd, "_srk_auth", 0600, "wks\n", 4);

	try {
		TPMBuffer::Ptr pk = srk->GetPubKey();
		WriteNewFile(dirfd.fd, "_public_key", 0666, pk->data, pk->len);
	} catch (TPMError) {
		// No public blob.  Sad.
	}

	// Create a default ring
	TPMRsaKey::Ptr subkey =
		TPMRsaKey::Create(context, TSS_KEY_SIZE_DEFAULT | TSS_KEY_TYPE_STORAGE);
	subkey->SetUsageWKS();
	CHECK_TSPI_CALL(Tspi_Key_CreateKey, subkey->handle, srk->handle, 0);

	mkdirat(dirfd.fd, "default_ring", 0755);
	{
		TPMBuffer::Ptr pubkey = subkey->GetAttribData(TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY);
		WriteNewFile(dirfd.fd, "default_ring/_public_key", 0666, pubkey->data, pubkey->len);

		TPMBuffer::Ptr privkey = subkey->GetAttribData(TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY);
		WriteNewFile(dirfd.fd, "default_ring/_private_key", 0600, privkey->data, privkey->len);
	}

	CHECK_TSPI_CALL(Tspi_Key_LoadKey, subkey->handle, srk->handle);
}

void Wrap(const char *wrapping_key, const char *privkey)
{
	FD dirfd;
	dirfd.fd = open(wrapping_key, O_RDONLY | O_DIRECTORY, 0);
	if (dirfd.fd == -1)
		throw std::runtime_error("sad");
	Buffer::Ptr pub_wrapping_key = ReadFile(dirfd.fd, "_public_key", 4096);
	Buffer::Ptr priv_wrapping_key = ReadFile(dirfd.fd, "_private_key", 4096);

	TPMContext::Ptr context(new TPMContext);
	context->Connect();
	TPMRsaKey::Ptr srk = TPMRsaKey::GetSRK(context);
	srk->SetUsageWKS();

	TPMRsaKey::Ptr subkey =
		TPMRsaKey::Create(context, 0);
	subkey->SetAttribData(TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, pub_wrapping_key->data, pub_wrapping_key->len);
	subkey->SetAttribData(TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY, priv_wrapping_key->data, priv_wrapping_key->len);
	subkey->SetUsageWKS();
	CHECK_TSPI_CALL(Tspi_Key_LoadKey, subkey->handle, srk->handle);

	UINT32 usage = subkey->GetAttribUint32(TSS_TSPATTRIB_KEY_INFO, TSS_TSPATTRIB_KEYINFO_USAGE);
	printf("usage = %x %s\n", usage, keyinfo_usage_to_string(usage));

}

}

int foo()
{
	try {
		TPMContext::Ptr context(new TPMContext);
		context->Connect();
		TPMRsaKey::Ptr srk = TPMRsaKey::GetSRK(context);
		srk->SetUsageWKS();

		TPMBuffer::Ptr public_srk_blob = srk->GetPubKey();
		printf("srk public blob len = %ld\n", (long)public_srk_blob->len);

		TPMRsaKey::Ptr subkey =
			TPMRsaKey::Create(context, TSS_KEY_SIZE_DEFAULT | TSS_KEY_TYPE_LEGACY);
		subkey->SetAttribUint32(TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
					TSS_SS_RSASSAPKCS1V15_DER);
		CHECK_TSPI_CALL(Tspi_Key_CreateKey, subkey->handle, srk->handle, 0);

		TPMBuffer::Ptr public_blob = subkey->GetAttribData(TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY);
		printf("public blob len = %ld\n", (long)public_blob->len);
	} catch (TPMError &e) {
		printf("Error calling %s: %lx\n", e.failing_call, (long)e.code);
		return 1;
	}

	return 0;
}
