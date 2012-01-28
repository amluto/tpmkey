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

#pragma once

#include "tspi_helpers.h"
#include <string>
#include <tr1/memory>
#include "keyfile.h"
#include <map>
#include <vector>

namespace TPMKey {

std::string find_default_keyring();

struct TPMKeypair
{
	typedef std::tr1::shared_ptr<TPMKeypair> Ptr;

	// Any or all of these fields might not be set.
	TPMRsaKey::Ptr rsakey;
	TPMKeypair::Ptr parent;
	TPMBuffer::Ptr public_modulus;  // Needed for SRK
	TPMBuffer::Ptr public_exponent;

	bool secret_valid;
	uint8_t secret[16];
};

TPMBuffer::Ptr ReadFile(int dirfd, const char *path, size_t maxlen);

class TPMKeyring : TPMNoncopyable
{
public:
	explicit TPMKeyring(const char *path);

	FD dirfd;
	TPMContext::Ptr tpmctx;

	TPMKeypair::Ptr LoadKey(const std::string &name, PasswordCallback pwcb, void *opaque);
	std::vector<std::string> list_subkeys(const std::string &name);

	static std::string parent_key(const std::string &name);
	static std::string subkey_name(const std::string &name);
	static bool name_is_srk(const std::string &name);
	static bool name_is_valid_non_srk(const std::string &name);

	typedef std::tr1::shared_ptr<TPMKeyring> Ptr;

private:
	bool tpm_is_connected_;
	typedef std::map<std::string, std::tr1::weak_ptr<TPMKeypair> > KeyCache;
	KeyCache key_cache_;
};

}
