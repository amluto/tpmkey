/* -*- mode: c++; c-file-style: "bsd" -*-

TPMKey keyring handling

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

#include "keyring.h"
#include <stdlib.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>

namespace TPMKey {


std::string find_default_keyring()
{
	struct passwd pwdbuf;
	size_t buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
	char *buf = (char*)alloca(buflen);
	struct passwd *pwd;
	getpwuid_r(getuid(), &pwdbuf, buf, buflen, &pwd);
	const char *home = 0;
	if (pwd)
		home = pwd->pw_dir;
	else
		home = getenv("HOME");

	if (home)
		return std::string(home) + "/.tpmkey";
	else
		throw std::runtime_error("Failed to find home directory");
}

/*
static std::string last_component(const std::string &name)
{
	size_t last_slash = name.find_last_of('/');
	if (last_slash == name.npos) {
	} // ...
}
*/

std::string TPMKeyring::parent_key(const std::string &name)
{
	if (name.size() < 2)
		abort();

	size_t last_slash = name.find_last_of('/');
	if (last_slash == name.npos)
		abort();  // This is impossible.
	else if (last_slash == 0)
		return "/";
	else
		return name.substr(0, last_slash);	
}

bool TPMKeyring::name_is_srk(const std::string &name)
{
	return name == "/";
}

bool TPMKeyring::name_is_valid_non_srk(const std::string &name)
{
	if (!(name.size() > 1 && name[0] == '/' &&
	      name[name.size() - 1] != '/'))
		return false;

	// We don't want blank names in the path or confusing things
	// like "." and "..".
	if (name.find("//", 0, 2) != name.npos
	    || name.find("/.", 0, 2) != name.npos)
		return false;

	return true;
}

std::string TPMKeyring::subkey_name(const std::string &name)
{
	size_t last_slash = name.find_last_of('/');
	if (last_slash == name.npos)
		abort();  // This is impossible.
	else
		return name.substr(last_slash + 1);
}

TPMKeypair::Ptr TPMKeyring::LoadKey(const std::string &name, PasswordCallback pwcb, void *opaque)
{
	if (name.size() == 0 || name[0] != '/' || (name.size() > 1 && name[name.size() - 1] == '/'))
		throw std::runtime_error("Invalid key name");

	KeyCache::iterator it = key_cache_.find(name);
	if (it != key_cache_.end()) {
		if (TPMKeypair::Ptr ptr = it->second.lock())
			return ptr;
		else
			key_cache_.erase(it);  // And continue...
	}

	if (name == "/") {
		// Load the SRK.
		TPMKeypair::Ptr srk(new TPMKeypair);
		srk->secret_valid = false;
		srk->rsakey = TPMRsaKey::GetSRK(tpmctx);
		srk->rsakey->SetUsageWKS();

		// We need to get the public modulus.
		TPMBuffer::Ptr srk_public_key = ReadFile(dirfd.fd, "_public_key", 4096);
		TPMRsaKey::Ptr fake_srk = TPMRsaKey::Create(tpmctx, 0);
		fake_srk->SetAttribData(TSS_TSPATTRIB_KEY_BLOB,
					TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY,
					srk_public_key->data, srk_public_key->len);
		srk->public_modulus = fake_srk->GetAttribData(
			TSS_TSPATTRIB_RSAKEY_INFO,
			TSS_TSPATTRIB_KEYINFO_RSA_MODULUS);
		srk->public_exponent = fake_srk->GetAttribData(
			TSS_TSPATTRIB_RSAKEY_INFO,
			TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT);

		key_cache_.insert(std::make_pair(name, srk));
		return srk;
	}

	// Load a non-SRK key

	TPMKeypair::Ptr parent = LoadKey(parent_key(name), pwcb, opaque);

	TPMBuffer::Ptr enc_key = ReadFile(dirfd.fd, (name + "/_private_key").c_str() + 1, 4096);
	DecodedKey key;
	DecodeKey(&key, enc_key, parent->public_modulus,
		  (parent->secret_valid ? parent->secret : 0),
		  name, pwcb, opaque);

	TPMKeypair::Ptr ret = TPMKeypair::Ptr(new TPMKeypair);
	ret->parent = parent;

	if (key.flags & TPMKey_PRIVATE_KEY_NOKEY) {
		ret->rsakey = parent->rsakey;
		ret->public_modulus = parent->public_modulus;
		ret->public_exponent = parent->public_exponent;
	} else {
		ret->rsakey = TPMRsaKey::Create(tpmctx, 0);
		ret->rsakey->SetAttribData(TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_BLOB, key.tpm_key->data, key.tpm_key->len);
		ret->rsakey->SetUsageSecret(TSS_SECRET_MODE_SHA1, key.auth_usage, sizeof(key.auth_usage));
		CHECK_TSPI_CALL(Tspi_Key_LoadKey, ret->rsakey->handle, parent->rsakey->handle);
		ret->public_modulus = ret->rsakey->GetAttribData(
			TSS_TSPATTRIB_RSAKEY_INFO,
			TSS_TSPATTRIB_KEYINFO_RSA_MODULUS);
		ret->public_exponent = ret->rsakey->GetAttribData(
			TSS_TSPATTRIB_RSAKEY_INFO,
			TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT);
	}

	ret->secret_valid = true;
	memcpy(ret->secret, key.secret, sizeof(ret->secret));

	key_cache_.insert(std::make_pair(name, ret));
	return ret;
}

TPMKeyring::TPMKeyring(const char *path)
{
	dirfd.fd = open(path, O_DIRECTORY | O_RDONLY);
	if (dirfd.fd == -1)
		throw std::runtime_error("Failed to open keyring directory");

	tpmctx = TPMContext::Ptr(new TPMContext);
	tpmctx->Connect();
}

std::vector<std::string> TPMKeyring::list_subkeys(const std::string &name)
{
	if (!name_is_srk(name) && !name_is_valid_non_srk(name))
		throw std::runtime_error("Bad key name");

	int dfd = openat(dirfd.fd, name.c_str() + 1, O_DIRECTORY | O_RDONLY);
	if (dfd == -1)
		throw std::runtime_error("Failed to open directory");

	DIR *d = fdopendir(dfd);
	if (!d) {
		close(dfd);
		throw std::runtime_error("fdopendir failed");
	}

	std::vector<std::string> ret;

	while(dirent *e = readdir(d)) {
		if (e->d_name[0] == '.' || e->d_name[0] == '_')
			continue;
		if (e->d_type != DT_UNKNOWN && e->d_type != DT_DIR)
			continue;

		ret.push_back(e->d_name);
	}

	closedir(d);
	return ret;
}

}
