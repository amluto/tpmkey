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

*/

#include "cli.h"
#include "tspi_helpers.h"
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <malloc.h>
#include <limits>
#include "utils.h"
#include "tpmkey_files.h"
#include "keyfile.h"
#include <arpa/inet.h>

extern "C" {
#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
}

namespace TPMKey {

int cmd_raw_convert_pubkey(struct global_args &args)
{
	gnutls_global_init();

	TPMBuffer::Ptr blob = ReadFile(AT_FDCWD, args.sub_argv[1], 4096);

	if (blob->len < sizeof(TPMKey_private_key))
		throw std::runtime_error("File is too short");

	const TPMKey_private_key *key = reinterpret_cast<TPMKey_private_key*>(blob->data);

	if (memcmp(key->magic, TPMKey_private_key_magic, sizeof(key->magic)))
		throw std::runtime_error("File is not a TPMKey private key");

	// Find the TPM_KEY structure
	size_t tpm_key_size = blob->len - sizeof(TPMKey_private_key);
	if (tpm_key_size > std::numeric_limits<uint32_t>::max() - 16)
		throw std::runtime_error("File is too large");
	const void *enc_tpm_key = key + 1;

	// Use TSPI to parse it.  No need to decrypt first -- we won't
	// try to load the key
	TPMContext::Ptr context(new TPMContext);
	TPMRsaKey::Ptr rsakey = TPMRsaKey::Create(context, 0);
	rsakey->SetAttribData(TSS_TSPATTRIB_KEY_BLOB,
			      TSS_TSPATTRIB_KEYBLOB_BLOB,
			      enc_tpm_key, tpm_key_size);

	// Start writing the results
	printf("TPMKey keypair\n");

	// Read out flags
	uint32_t flags = ntohl(key->flags);
	printf("  Extra privkey encryption:");
	bool need_and = false;
	if (flags & TPMKey_PRIVATE_KEY_SCRYPT) {
		printf(" password (scrypt)");
		need_and = true;
	}
	if (flags & TPMKey_PRIVATE_KEY_PARENT_SECRET) {
		if (need_and)
			printf(" and");
		printf(" parent key symmetric secret");
		need_and = true;
	}
	if (!need_and) {
		printf(" not encrypted");
	}
	printf("\n");

	// Read out basic attributes
	UINT32 keysize = rsakey->GetAttribUint32(TSS_TSPATTRIB_RSAKEY_INFO,
						 TSS_TSPATTRIB_KEYINFO_RSA_KEYSIZE);
	printf("  Size: %lu\n", (long)keysize);
	UINT32 usage = rsakey->GetAttribUint32(TSS_TSPATTRIB_KEY_INFO,
					       TSS_TSPATTRIB_KEYINFO_USAGE);
	printf("  Usage: %s\n", keyinfo_usage_to_string(usage));
	UINT32 keyflags = rsakey->GetAttribUint32(TSS_TSPATTRIB_KEY_INFO,
						  TSS_TSPATTRIB_KEYINFO_KEYFLAGS);
	printf("  Migratable: %s\n", (keyflags & TSS_KEYFLAG_MIGRATABLE) ? "yes" : "no (key known only to TPM)");

	UINT32 ss = rsakey->GetAttribUint32(TSS_TSPATTRIB_KEY_INFO,
					    TSS_TSPATTRIB_KEYINFO_SIGSCHEME);
	if (ss == TSS_SS_NONE)
		printf("  Signature scheme: none\n");
	else if (ss == TSS_SS_RSASSAPKCS1V15_SHA1)
		printf("  Signature scheme: PKCS#1 v1.5 SHA1\n");
	else if (ss == TSS_SS_RSASSAPKCS1V15_DER)
		printf("  Signature scheme: PKCS#1 v1.5 unrestricted (TSS DER)\n");
	else if (ss == TSS_SS_RSASSAPKCS1V15_INFO)
		printf("  Signature scheme: PKCS#1 v1.5 TPM_SIGN_INFO\n");
	else
		printf("  Signature scheme: unknown (0x%X)\n", (unsigned int)ss);

	UINT32 es = rsakey->GetAttribUint32(TSS_TSPATTRIB_KEY_INFO,
					    TSS_TSPATTRIB_KEYINFO_ENCSCHEME);
	if (es == TSS_ES_NONE)
		printf("  Encryption scheme: none\n");
	else if (es == TSS_ES_RSAESPKCSV15)
		printf("  Encryption scheme: PKCS#1 v1.5\n");
	else if (es == TSS_ES_RSAESOAEP_SHA1_MGF1)
		printf("  Encryption scheme: PKCS#1 v2.0 OAEP P=TCPA\n");
	else
		printf("  Encryption scheme: unknown (0x%X)\n", (unsigned int)es);

	// Read out authDataUsage.  We have to do this manually -- I don't
	// know how to get it from TSPI
	if (tpm_key_size >= sizeof(TPM_KEY_header)) {
		const TPM_KEY_header *header = reinterpret_cast<const TPM_KEY_header *>(enc_tpm_key);
		if (header->authDataUsage == TPM_AUTH_NEVER)
			printf("  TPM auth usage required: never [dangerous]\n");
		else if (header->authDataUsage == TPM_AUTH_ALWAYS)
			printf("  TPM auth usage required: always\n");
		else if (header->authDataUsage == TPM_AUTH_PRIV_USE_ONLY)
			printf("  TPM auth usage required: private use only\n");
		else
			printf("  TPM auth usage required: unknown value 0x%02x\n", (unsigned int)header->authDataUsage);
	}

	// Read out the RSA parameters
	TPMBuffer::Ptr e = rsakey->GetAttribData(TSS_TSPATTRIB_RSAKEY_INFO,
						 TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT);
	TPMBuffer::Ptr n = rsakey->GetAttribData(TSS_TSPATTRIB_RSAKEY_INFO,
						 TSS_TSPATTRIB_KEYINFO_RSA_MODULUS);

	gnutls_pubkey_t gtls_pubkey;
	if (gnutls_pubkey_init(&gtls_pubkey) != 0) {
		fprintf(stderr, "gnutls failure\n");
		return 1;
	}
	gnutls_datum_t gtls_n = {(unsigned char *)n->data, n->len};
	gnutls_datum_t gtls_e = {(unsigned char *)e->data, e->len};
	if (gnutls_pubkey_import_rsa_raw(gtls_pubkey, &gtls_n, &gtls_e) != 0) {
		fprintf(stderr, "gnutls import failure\n");
		return 1;
	}

	TPMBuffer outbuf(8192);
	size_t outsize = outbuf.alloc_len;
	if (int err = gnutls_pubkey_export(gtls_pubkey, GNUTLS_X509_FMT_PEM,
				 outbuf.data, &outsize)) {
		fprintf(stderr, "Conversion failed: %d\n", err);
		return 1;
	}
	gnutls_pubkey_deinit(gtls_pubkey);

	fwrite(outbuf.data, outsize, 1, stdout);

	gnutls_global_deinit();

	return 0;
}

}
