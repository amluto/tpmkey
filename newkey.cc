/* -*- mode: c++; c-file-style: "bsd" -*-

TPMKey newkey command

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
#include "utils.h"
#include "keyring.h"
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <malloc.h>
#include "keyfile.h"

using namespace TPMKey;

bool GetNewPassword(std::string *out, const std::string &desc, void *)
{
	std::string prompt = std::string("Enter new password for ") + desc + ": ";
	char *pw = getpass(prompt.c_str());
	if (!pw)
		return false;
	*out = pw;
	return true;
}

bool GetOldPassword(std::string *out, const std::string &desc, void *)
{
	std::string prompt = std::string("Enter password for ") + desc + ": ";
	char *pw = getpass(prompt.c_str());
	if (!pw)
		return false;
	*out = pw;
	return true;
}

int cmd_newkey(struct global_args &args)
{
	using namespace TPMKey;
	if (args.sub_argc != 3) {
		fprintf(stderr, "Usage: tpmkey newkey </keypath/name> <type>\n");
		return 1;
	}

	const char *key_name = args.sub_argv[1];
	const char *type_name = args.sub_argv[2];

	if (!TPMKeyring::name_is_valid_non_srk(args.sub_argv[1])) {
		fprintf(stderr, "Invalid key name\n");
		return 1;
	}

	TSS_FLAG type;
	bool is_container = false;
	if (!strcmp(type_name, "storage")) {
		type = TSS_KEY_TYPE_STORAGE;
	} else if (!strcmp(type_name, "sign")) {
		type = TSS_KEY_TYPE_SIGNING;
	} else if (!strcmp(type_name, "encrypt_and_sign")) {
		type = TSS_KEY_TYPE_LEGACY;
	} else if (!strcmp(type_name, "container")) {
		type = 0;
		is_container = true;
	} else {
		fprintf(stderr, "Unknown key type\n");
		return 1;
	}

	TPMKeyring keyring(find_default_keyring().c_str());
	TPMKeypair::Ptr parent = keyring.LoadKey(TPMKeyring::parent_key(key_name), GetOldPassword, 0);
	std::string subkey_name = TPMKeyring::subkey_name(key_name);

	// Create the new key
	DecodedKey key;
	GetRand160(key.auth_usage);
	GetRand128(key.secret);

	if (type == TSS_KEY_TYPE_STORAGE || is_container) {
		key.flags = TPMKey_PRIVATE_KEY_SCRYPT;
		key.scrypt_r = 8;
		key.scrypt_p = 1;
		key.scrypt_N = 2048;
	} else {
		key.flags = 0;
		key.scrypt_p = key.scrypt_r = key.scrypt_N = 0;
	}
	if (parent->secret_valid)
		key.flags |= TPMKey_PRIVATE_KEY_PARENT_SECRET;

	if (!is_container) {
		printf("Parent key loaded; generating new key on TPM\n");
		TPMRsaKey::Ptr subkey =
			TPMRsaKey::Create(keyring.tpmctx,
					  type | TSS_KEY_SIZE_DEFAULT
					  | TSS_KEY_AUTHORIZATION);
		subkey->SetUsageSecret(TSS_SECRET_MODE_SHA1, key.auth_usage, sizeof(key.auth_usage));
		if (type == TSS_KEY_TYPE_SIGNING || type == TSS_KEY_TYPE_LEGACY)
			subkey->SetAttribUint32(TSS_TSPATTRIB_KEY_INFO,
						TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
						TSS_SS_RSASSAPKCS1V15_DER);
		if (type == TSS_KEY_TYPE_BIND || type == TSS_KEY_TYPE_LEGACY)
			subkey->SetAttribUint32(TSS_TSPATTRIB_KEY_INFO,
						TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
						TSS_ES_RSAESPKCSV15);

		CHECK_TSPI_CALL(Tspi_Key_CreateKey, subkey->handle,
				parent->rsakey->handle, 0);

		key.tpm_key =
			subkey->GetAttribData(TSS_TSPATTRIB_KEY_BLOB,
					      TSS_TSPATTRIB_KEYBLOB_BLOB);
	} else {
		key.flags |= TPMKey_PRIVATE_KEY_NOKEY;
	}

	TPMBuffer::Ptr keyfile = EncodeKey(&key, parent->public_modulus,
					   parent->secret_valid
					   ? parent->secret : 0,
					   key_name, GetNewPassword, 0);
	if (mkdirat(keyring.dirfd.fd, key_name + 1, 0777) != 0)
		throw std::runtime_error("Failed to create directory for new key");
	TPMKey::WriteNewFile(keyring.dirfd.fd,
			     (std::string(key_name + 1) + "/_private_key").c_str(),
			     0600, keyfile->data, keyfile->len);

	return 0;
}

