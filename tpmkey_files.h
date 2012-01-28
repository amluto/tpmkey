/* -*- mode: c++; c-file-style: "bsd" -*-

TPMKey keyring file definitions

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
#include <stdint.h>

/* _public_srk: The TSPI public blob for the SRK.  Not used for other keys. */

/* _private_key */

// Parent's symmetric secret is part of the key material
#define TPMKey_PRIVATE_KEY_PARENT_SECRET (1 << 0)
// This key is encrypted with a password.
#define TPMKey_PRIVATE_KEY_SCRYPT (1 << 1)
// If set, there is no RSA key -- we reuse the parent key.  The TPM key blob will not be there.
#define TPMKey_PRIVATE_KEY_NOKEY (1 << 2)  // If true, there

#define TPMKey_PRIVATE_KEY_ANY_CRYPT \
	(TPMKey_PRIVATE_KEY_PARENT_SECRET |  TPMKey_PRIVATE_KEY_SCRYPT)

struct TPMKey_private_key
{
	/* All in big-endian order */
	char magic[24];  /* TPMKey_private_key followed by nulls */

	uint32_t flags;

	/* The parent rsa modulus is always needed to encrypt or decrypt this
	   structure.  (This isn't a practical restriction -- the parent
	   private key is needed to actually use this key.)  However, using
	   the wrong password and screwing up the parent key (e.g. resetting
	   the SRK) are both detected by Tspi_Key_LoadKey failing.  To
	   distinguish the two cases, the SHA256 hash of the parent public
	   blob is optionally stored here.  If this field is all zeros, it
	   should be ignored.  (Current code will always store it.)

	   There is no point in storing the full modulus here -- the decrypted
	   TPM blob is useless without the parent *private* key, and anyone
	   who knows that also knows the modulus.  (This also means you can't
	   change the password without the parent modulus.  Oh, well.) */
	uint8_t parent_pubkey_sha256[32];

	uint8_t auth_seed[16];

	/* If TPMKey_PRIVATE_KEY_SCRYPT is set, then these are the scrypt
	   parameters.  Otherwise, they are all zero.  (The scrypt password
	   is always UTF-8.) */
	uint32_t scrypt_p, scrypt_r, scrypt_N;
	uint8_t scrypt_salt[16];

	/* If none of the crypto flags are set, then the rest of the structure
	   is in the clear.  [This is to support SRKs with unknown public keys
	   -- in that setting, the structure *can't* be encrypted.]

	   Otherwise, the rest of the structure is encrypted using an ad-hoc
	   encryption scheme.  First, flags, auth_seed, the parent secret (16
	   bytes, if the PARENT_SECRET flag is set) and 16 bytes of scrypt
	   output (if the SCRYPT flag is set) are hashed with SHA-256.  The
	   first 128 bits of output is used as an AES-128 key.  AES is used in
	   CTR mode with IV zero to encrypt this field: */
	uint8_t secret[16];

	/* This is encrypted with IV 1 */
	uint8_t auth_usage[20];

	/* The remainder of the file is the TPM key as a TPM_KEY blob.
	   Everything except the actual encData is stored in the clear.  The
	   encData is a big-endian number between zero and n-1 (where n is the
	   *parent* RSA modulus), probably.  (Technically, if the key is
	   non-migratable, the value could be anything.)  encData is further
	   encrypted using AES.  AES-128 in CTR mode (IV 3 and up) is used to
	   generate m+16 bytes of data, where m is the length *in bytes* of
	   the TPM blob.  This data is a big-endian number x.  (m will almost
	   always be 256.).  encData is replaced with x - encData mod (parent
	   modulus).  mod n to the blob.  The blob (with encData encrypted)
	   follows. */
	/* uint8_t encrypted_tspi_blob[256] */

	/* Two important notes:

	   1. There is no authentication at all.  This is intentional.  Anything
	   that uses subkey SHOULD NOT have any way to authenticate the result
	   without involving the TPM.  This is to make dictionary attacks
	   impossible without calling the TPM for each try.

	   2. The encryption here uses CTR mode with a fixed IV.  This means
	   that the key MUST NOT be reused under any circumstances (except
	   extreme bad luck).  In other words, when encoding a key, auth_seed
	   must contain 128 bits of fresh entropy each time any of this is
	   encrypted (even for password changes).  Failure to observe this
	   precaution will drastically weaken the security of the scheme.
	*/
};

static const char TPMKey_private_key_magic[24] = "TPMKey_private_key";
