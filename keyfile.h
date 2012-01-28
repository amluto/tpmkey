/* -*- mode: c++; c-file-style: "bsd" -*-

TPMKey file encoders and decoders

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
#include "tpmkey_files.h"

namespace TPMKey {

typedef bool (*PasswordCallback)(std::string *out, const std::string &desc, void *opaque);

struct DecodedKey
{
	uint8_t parent_pubkey_sha256[32];

	uint32_t flags;
	uint32_t scrypt_p, scrypt_r, scrypt_N;

	uint8_t secret[16];
	uint8_t auth_usage[20];

	TPMBuffer::Ptr tpm_key;
};

void GetRand128(uint8_t out[16]);
void GetRand160(uint8_t out[20]);

void DecodeKey(DecodedKey *out,
	       TPMBuffer::Ptr in,
	       TPMBuffer::Ptr parent_rsa_modulus,
	       const uint8_t *parent_secret,
	       std::string description,
	       PasswordCallback callback,
	       void *opaque);

TPMBuffer::Ptr EncodeKey(const DecodedKey *in,
			 TPMBuffer::Ptr parent_rsa_modulus,
			 const uint8_t *parent_secret,
			 std::string description,
			 PasswordCallback callback,
			 void *opaque);

struct __attribute__((packed)) TPM_KEY_header
{
	TPM_STRUCT_VER ver;
	TPM_KEY_USAGE keyUsage;
	TPM_KEY_FLAGS keyFlags;
	TPM_AUTH_DATA_USAGE authDataUsage;
	TPM_ALGORITHM_ID kp_algorithmID;
	TPM_ENC_SCHEME kp_encScheme;
	TPM_SIG_SCHEME kp_sigScheme;
};

/*
  TPM_KEY is:
  TPM_KEY_header
  TPM_KEY_PARAMS (len, value)
  pcr info (len, value)
  public key (len, value) -- this is the RSA modulus
  encrypted private key (len, value)
*/


}
