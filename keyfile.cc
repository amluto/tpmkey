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

#include "tpmkey_files.h"
#include "tspi_helpers.h"
#include "keyfile.h"
#include <tss/tpm.h>
#include <gcrypt.h>
#include <arpa/inet.h>
#include <limits>
#include <assert.h>
#include "scrypt/crypto_scrypt.h"

namespace TPMKey {

struct GcryCipherHandle : TPMNoncopyable
{
	gcry_cipher_hd_t handle;
	GcryCipherHandle() : handle(0) {}
	~GcryCipherHandle() {
		if (handle)
			gcry_cipher_close(handle);
	}

	void SetCtr(uint32_t ctr)
	{
		
	}
};

struct GcryMPIReleaser : TPMNoncopyable
{
	gcry_mpi_t handle;
	explicit GcryMPIReleaser(gcry_mpi_t handle) : handle(handle) {}
	~GcryMPIReleaser() { gcry_mpi_release(handle); }
};

struct BlobDesc
{
	const void *data;
	size_t len;
};

struct TPM_KEY_blobs
{
	BlobDesc blobs[4];
};

bool tpm_key_find_boundaries(const void *buf, size_t len, TPM_KEY_blobs *blobs)
{
	if (len < sizeof(TPM_KEY_header))
		return false;

	const TPM_KEY_header *header =
		reinterpret_cast<const TPM_KEY_header *>(buf);
	if (header->ver.major != 1 || header->ver.minor != 1
	    || header->ver.revMajor != 0 || header->ver.revMinor != 0)
		return false;

	const char *pos =
		reinterpret_cast<const char *>(buf) + sizeof(TPM_KEY_header);
	size_t bytes_left = len - sizeof(TPM_KEY_header);
	for (int i = 0; i < 4; i++)
	{
		if (bytes_left < 4)
			return false;
		size_t this_len = ntohl(*(UINT32*)pos);
		pos += 4;
		bytes_left -= 4;

		if (this_len > bytes_left)
			return false;  // No space
		blobs->blobs[i].data = pos;
		blobs->blobs[i].len = this_len;
		pos += this_len;
		bytes_left -= this_len;
	}

	if (bytes_left != 0)
		return false;  // Extra data at end

	return true;
}

static void InitKeyAes(GcryCipherHandle *aes_handle,
		       const TPMKey_private_key *ekey,
		       const uint8_t *parent_secret,
		       std::string description,
		       PasswordCallback callback,
		       void *opaque)
{
	// Validate flags
	uint32_t flags = ntohl(ekey->flags);
	if (flags & ~(TPMKey_PRIVATE_KEY_PARENT_SECRET | TPMKey_PRIVATE_KEY_SCRYPT | TPMKey_PRIVATE_KEY_NOKEY))
		throw std::runtime_error("Corrupt private key");		

	uint8_t key_material[52];
	size_t key_material_len = 0;

	// Process flags
	memcpy(key_material + key_material_len, &ekey->flags, 4);
	key_material_len += 4;

	// Process the auth_seed
	memcpy(key_material + key_material_len, ekey->auth_seed, 16);
	key_material_len += 16;

	// Process parent secret
	if (flags & TPMKey_PRIVATE_KEY_PARENT_SECRET) {
		if (!parent_secret)
			throw std::runtime_error("Parent secret required but not provided");

		memcpy(key_material + key_material_len, parent_secret, 16);
		key_material_len += 16;
	}

	// Process scrypt
	if (flags & TPMKey_PRIVATE_KEY_SCRYPT) {
		uint32_t p = ntohl(ekey->scrypt_p);
		uint32_t r = ntohl(ekey->scrypt_r);
		uint32_t N = ntohl(ekey->scrypt_N);
		if (!p || !r || !N)
			throw std::runtime_error("Corrupt private key");

		std::string password;
		if (!callback(&password, description, opaque))
			throw std::runtime_error("Password is required");

		if (crypto_scrypt((const uint8_t *)password.data(),
				  password.size(),
				  ekey->scrypt_salt, sizeof(ekey->scrypt_salt),
				  N, r, p, key_material + key_material_len, 16)
		    != 0)
			throw std::runtime_error("scrypt failure");
		key_material_len += 16;
	}

	uint8_t hash_output[256 / 8];
	gcry_md_hash_buffer(GCRY_MD_SHA256, hash_output, key_material, key_material_len);

	gcry_cipher_hd_t tmp_handle;
	if (gcry_cipher_open(&tmp_handle, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CTR,
			     GCRY_CIPHER_SECURE) != 0)
		throw std::runtime_error("gcrypt internal error");

	aes_handle->handle = tmp_handle;

	if (gcry_cipher_setkey(aes_handle->handle, hash_output, 128 / 8))
		throw std::runtime_error("gcrypt internal error");
}

static void CryptTpmKey(GcryCipherHandle &aes_handle,
			TPMBuffer::Ptr parent_modulus,
			void *out, const void *in, size_t len, bool encrypt)
{
	// Parse and validate the input key blob
	TPM_KEY_blobs blobs;
	if (!tpm_key_find_boundaries(in, len, &blobs))
		throw std::runtime_error("Corrupt private key");
	size_t m = blobs.blobs[3].len;  // Number of bytes of RSA blob
	if (m != parent_modulus->len)
		throw std::runtime_error("Corrupt private key");		

	// Calculate the mask.
	TPMBuffer mask_raw(m + 16);
	mask_raw.len = m + 16;
	memset(mask_raw.data, 0, mask_raw.len);
	aes_handle.SetCtr(3);
	if (gcry_cipher_encrypt(aes_handle.handle, mask_raw.data, mask_raw.len,
				0, 0))
		throw std::runtime_error("gcrypt internal error");
	gcry_mpi_t mask;
	if (gcry_mpi_scan(&mask, GCRYMPI_FMT_USG, mask_raw.data, mask_raw.len, 0))
		throw std::runtime_error("gcrypt internal error");
	GcryMPIReleaser release_mask(mask);

	// Convert the input into an integer
	gcry_mpi_t key_in;
	if (gcry_mpi_scan(&key_in, GCRYMPI_FMT_USG, blobs.blobs[3].data, m, 0))
		throw std::runtime_error("gcrypt internal error");
	GcryMPIReleaser release_key_in(key_in);

	// Convert the modulus into an integer
	gcry_mpi_t modulus;
	if (gcry_mpi_scan(&modulus, GCRYMPI_FMT_USG,
			  parent_modulus->data, parent_modulus->len, 0))
		throw std::runtime_error("gcrypt internal error");
	GcryMPIReleaser release_modulus(modulus);

	// Validate the input relative to the modulus
	if (gcry_mpi_cmp(key_in, modulus) >= 0)
		throw std::runtime_error("Corrupt private key");

	// Encrypt or decrypt
	gcry_mpi_t key_out = gcry_mpi_new(m * 8);
	GcryMPIReleaser release_key_out(key_out);
	gcry_mpi_subm(key_out, mask, key_in, modulus);

	// Write out the result
	size_t offset_to_enc =
		(const char *)blobs.blobs[3].data - (const char *)in;
	assert(offset_to_enc + m == len);
	memcpy(out, in, offset_to_enc);
	if (gcry_mpi_print(GCRYMPI_FMT_USG, (unsigned char *)out + offset_to_enc, m, 0, key_out))
		throw std::runtime_error("gcrypt internal error");

}

void DecodeKey(DecodedKey *out,
	       TPMBuffer::Ptr in,
	       TPMBuffer::Ptr parent_rsa_modulus,
	       const uint8_t *parent_secret,
	       std::string description,
	       PasswordCallback callback,
	       void *opaque)
{
	if (in->len < sizeof(TPMKey_private_key))
		throw std::runtime_error("Corrupt private key");

	const TPMKey_private_key *ekey = reinterpret_cast<TPMKey_private_key*>(in->data);

	if (memcmp(ekey->magic, TPMKey_private_key_magic, sizeof(ekey->magic)))
		throw std::runtime_error("Corrupt private key");

	memcpy(out->parent_pubkey_sha256, ekey->parent_pubkey_sha256, sizeof(out->parent_pubkey_sha256));

	size_t tpm_key_size = in->len - sizeof(TPMKey_private_key);
	if (tpm_key_size > std::numeric_limits<uint32_t>::max() - 16)
		throw std::runtime_error("Corrupt private key");

	if ((ekey->flags & htonl(TPMKey_PRIVATE_KEY_NOKEY))
	    ? tpm_key_size != 0 : tpm_key_size == 0)
		throw std::runtime_error("Corrupt private key");

	const void *enc_tpm_key = 0;
	if (tpm_key_size) {
		enc_tpm_key = ekey + 1;
		out->tpm_key = TPMBuffer::Ptr(new TPMBuffer(tpm_key_size));
		out->tpm_key->len = tpm_key_size;
	}

	if (ekey->flags & htonl(TPMKey_PRIVATE_KEY_ANY_CRYPT)) {
		GcryCipherHandle aes_handle;
		InitKeyAes(&aes_handle, ekey, parent_secret, description,
			   callback, opaque);

		aes_handle.SetCtr(0);
		if (gcry_cipher_decrypt(aes_handle.handle, out->secret, 16, ekey->secret, 16))
			throw std::runtime_error("gcrypt internal error");

		aes_handle.SetCtr(1);
		if (gcry_cipher_decrypt(aes_handle.handle, out->auth_usage, 20, ekey->auth_usage, 20))
			throw std::runtime_error("gcrypt internal error");

		// Decrypt the tpm key
		if (tpm_key_size)
			CryptTpmKey(aes_handle, parent_rsa_modulus,
				    out->tpm_key->data, enc_tpm_key, tpm_key_size, false);
	} else {
		memcpy(out->secret, ekey->secret, 16);
		memcpy(out->auth_usage, ekey->auth_usage, 20);
		if (tpm_key_size)
			memcpy(out->tpm_key->data, enc_tpm_key, tpm_key_size);
	}

	// Copy over basic data
	out->flags = ntohl(ekey->flags);
	out->scrypt_p = ntohl(ekey->flags);
	out->scrypt_r = ntohl(ekey->scrypt_r);
	out->scrypt_N = ntohl(ekey->scrypt_N);
}

void GetRand128(uint8_t out[16])
{
	gcry_randomize(out, 16, GCRY_STRONG_RANDOM);
}

void GetRand160(uint8_t out[20])
{
	gcry_randomize(out, 16, GCRY_STRONG_RANDOM);
}

TPMBuffer::Ptr EncodeKey(const DecodedKey *in,
			 TPMBuffer::Ptr parent_rsa_modulus,
			 const uint8_t *parent_secret,
			 std::string description,
			 PasswordCallback callback,
			 void *opaque)
{
	if ((in->flags & TPMKey_PRIVATE_KEY_NOKEY)
	    ? in->tpm_key : in->tpm_key->len == 0)
		throw std::runtime_error("Corrupt private key");

	TPMBuffer::Ptr ret(new TPMBuffer(sizeof(TPMKey_private_key) + (in->tpm_key ? in->tpm_key->len : 0)));
	ret->len = ret->alloc_len;

	TPMKey_private_key *ekey = reinterpret_cast<TPMKey_private_key*>(ret->data);

	static const char magic[24] = "TPMKey_private_key";
	memcpy(ekey->magic, magic, sizeof(ekey->magic));

	ekey->flags = htonl(in->flags);
	ekey->scrypt_p = htonl(in->scrypt_p);
	ekey->scrypt_r = htonl(in->scrypt_r);
	ekey->scrypt_N = htonl(in->scrypt_N);

	GetRand128(ekey->auth_seed);
	if (in->flags & TPMKey_PRIVATE_KEY_SCRYPT)
		GetRand128(ekey->scrypt_salt);
	else
		memset(ekey->scrypt_salt, 0, sizeof(ekey->scrypt_salt));

	GcryCipherHandle aes_handle;
	InitKeyAes(&aes_handle, ekey, parent_secret,
		   description, callback, opaque);

	if (in->flags & TPMKey_PRIVATE_KEY_ANY_CRYPT) {
		aes_handle.SetCtr(0);
		if (gcry_cipher_encrypt(aes_handle.handle, ekey->secret, 16, in->secret, 16))
			throw std::runtime_error("gcrypt internal error");

		aes_handle.SetCtr(1);
		if (gcry_cipher_encrypt(aes_handle.handle, ekey->auth_usage, 20, in->auth_usage, 20))
			throw std::runtime_error("gcrypt internal error");

		if (in->tpm_key) {
			// Encrypt the tpm blob
			size_t m = in->tpm_key->len;
			if (m > std::numeric_limits<uint32_t>::max() - 16)
				throw std::runtime_error("tpm key is too large");

			CryptTpmKey(aes_handle, parent_rsa_modulus,
				    ekey + 1, in->tpm_key->data,
				    in->tpm_key->len, true);
		}
	} else {
		memcpy(ekey->secret, in->secret, 16);
		memcpy(ekey->auth_usage, in->auth_usage, 20);
		if (in->tpm_key)
			memcpy(ekey + 1, in->tpm_key->data, in->tpm_key->len);
	}

	return ret;
}

}

