/* -*- mode: c; c-file-style: "bsd" -*-

TPMKey pkcs11 C_GetFunctionList and basic C code

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

/* This is in C because C99 designated initializers make it easy. */
#define CRYPTOKI_GNU
#include "pkcs11.h"
#include <stddef.h>
#include <string.h>
#include <assert.h>

static const struct ck_info tpmkey_ck_info = {
	.cryptoki_version = { .major = 2, .minor = 30 },
	.manufacturer_id = "TPMKey                          ",
	.flags = 0,
	.library_description = "TPMKey PKCS11 provider          ",
	.library_version = { .major = 0, .minor = 1 },
};

static ck_rv_t TPMKey_C_Initialize(void *args)
{
	if (!args)
		return CKR_OK;

	// We can't reliably support weird threading models (because TSPI
	// has no concept of them), so don't even try.
	const struct ck_c_initialize_args *initargs = args;
	if (initargs->flags & CKF_LIBRARY_CANT_CREATE_OS_THREADS)
		return CKR_NEED_TO_CREATE_THREADS;
	if (!(initargs->flags & CKF_OS_LOCKING_OK)
	    && initargs->create_mutex
	    && initargs->destroy_mutex
	    && initargs->lock_mutex
	    && initargs->unlock_mutex)
		return CKR_CANT_LOCK;

	return CKR_OK;
}

static ck_rv_t TPMKey_C_Finalize(void *args)
{
	if (args)
		return CKR_ARGUMENTS_BAD;
	else
		return CKR_OK;
}

static ck_rv_t TPMKey_C_GetInfo(struct ck_info *info)
{
	*info = tpmkey_ck_info;
	return CKR_OK;
}

static ck_rv_t TPMKey_C_GetSlotList(unsigned char token_present,
			     ck_slot_id_t *slot_list,
			     unsigned long *count)
{
	if (!slot_list) {
		*count = 1;
		return CKR_OK;
	} else {
		unsigned long orig_len = *count;
		*count = 1;
		if (orig_len < 1)
			return CKR_BUFFER_TOO_SMALL;
		slot_list[0] = 0;
		return CKR_OK;
	}
}

void copy_space_pad(unsigned char *out, const char *in, size_t len)
{
	size_t inlen = strlen(in);
	memcpy((char*)out, in, len);
	assert(inlen <= len);
	memset((char*)out + inlen, ' ', len - inlen);
}

static ck_rv_t TPMKey_C_GetSlotInfo(ck_slot_id_t slot_id, struct ck_slot_info *info)
{
	if (slot_id != 0)
		return CKR_SLOT_ID_INVALID;

	copy_space_pad(info->slot_description, "token0",
		       sizeof(info->slot_description));
	copy_space_pad(info->manufacturer_id, "TPMKey",
		       sizeof(info->manufacturer_id));
	info->flags = CKF_TOKEN_PRESENT;
	info->hardware_version = (struct ck_version){ 1, 0 };
	info->firmware_version = (struct ck_version){ 0, 0 };
	return CKR_OK;
}

ck_rv_t C_GetFunctionList(struct ck_function_list **function_list);

static ck_rv_t TPMKey_C_GetTokenInfo(ck_slot_id_t slot_id, struct ck_token_info *info)
{
	copy_space_pad(info->label, "token0", sizeof(info->label));
	copy_space_pad(info->manufacturer_id, "TPMKey", sizeof(info->manufacturer_id));
	copy_space_pad(info->model, "N/A", sizeof(info->model));
	copy_space_pad(info->serial_number, "N/A", sizeof(info->serial_number));

	info->flags = CKF_RNG | CKF_WRITE_PROTECTED | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED;

	info->max_session_count = CK_EFFECTIVELY_INFINITE;
	info->session_count = CK_EFFECTIVELY_INFINITE;
	info->max_rw_session_count = CK_EFFECTIVELY_INFINITE;
	info->rw_session_count = CK_EFFECTIVELY_INFINITE;
	info->max_pin_len = 1024;  // Doesn't really matter
	info->min_pin_len = 0;
	info->total_public_memory = CK_UNAVAILABLE_INFORMATION;
	info->free_public_memory = CK_UNAVAILABLE_INFORMATION;
	info->total_private_memory = CK_UNAVAILABLE_INFORMATION;
	info->free_private_memory = CK_UNAVAILABLE_INFORMATION;
	info->hardware_version = (struct ck_version){ 1, 0 };
	info->firmware_version = (struct ck_version){ 0, 0 };

	return CKR_OK;
}

ck_rv_t TPMKey_C_WaitForSlotEvent
		      (ck_flags_t flags, ck_slot_id_t *slot, void *reserved)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_GetMechanismList(ck_slot_id_t slot_id,
				  ck_mechanism_type_t *mechanism_list,
				  unsigned long *count);
ck_rv_t TPMKey_C_GetMechanismInfo
		      (ck_slot_id_t slot_id, ck_mechanism_type_t type,
		       struct ck_mechanism_info *info)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_InitToken
		      (ck_slot_id_t slot_id, unsigned char *pin,
		       unsigned long pin_len, unsigned char *label)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_InitPIN
		      (ck_session_handle_t session, unsigned char *pin,
		       unsigned long pin_len)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_SetPIN
		      (ck_session_handle_t session, unsigned char *old_pin,
		       unsigned long old_len, unsigned char *new_pin,
		       unsigned long new_len)
{ return CKR_FUNCTION_NOT_SUPPORTED; }

ck_rv_t TPMKey_C_OpenSession
		      (ck_slot_id_t slot_id, ck_flags_t flags,
		       void *application, ck_notify_t notify,
		       ck_session_handle_t *session);

ck_rv_t TPMKey_C_CloseSession (ck_session_handle_t session);
ck_rv_t TPMKey_C_CloseAllSessions (ck_slot_id_t slot_id)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_GetSessionInfo
		      (ck_session_handle_t session,
		       struct ck_session_info *info)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_GetOperationState
		      (ck_session_handle_t session,
		       unsigned char *operation_state,
		       unsigned long *operation_state_len)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_SetOperationState
		      (ck_session_handle_t session,
		       unsigned char *operation_state,
		       unsigned long operation_state_len,
		       ck_object_handle_t encryption_key,
		       ck_object_handle_t authentiation_key)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_Login(ck_session_handle_t session, ck_user_type_t user_type,
		       unsigned char *pin, unsigned long pin_len);
ck_rv_t TPMKey_C_Logout (ck_session_handle_t session)
{ return CKR_FUNCTION_NOT_SUPPORTED; }

ck_rv_t TPMKey_C_CreateObject
		      (ck_session_handle_t session,
		       struct ck_attribute *templ,
		       unsigned long count, ck_object_handle_t *object)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_CopyObject
		      (ck_session_handle_t session, ck_object_handle_t object,
		       struct ck_attribute *templ, unsigned long count,
		       ck_object_handle_t *new_object)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_DestroyObject
		      (ck_session_handle_t session,
		       ck_object_handle_t object)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_GetObjectSize
		      (ck_session_handle_t session,
		       ck_object_handle_t object,
		       unsigned long *size)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_GetAttributeValue(ck_session_handle_t session,
				   ck_object_handle_t object,
				   struct ck_attribute *templ,
				   unsigned long count);
ck_rv_t TPMKey_C_SetAttributeValue(ck_session_handle_t session,
				   ck_object_handle_t object,
				   struct ck_attribute *templ,
				   unsigned long count)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_FindObjectsInit
		      (ck_session_handle_t session,
		       struct ck_attribute *templ,
		       unsigned long count);
ck_rv_t TPMKey_C_FindObjects
		      (ck_session_handle_t session,
		       ck_object_handle_t *object,
		       unsigned long max_object_count,
		       unsigned long *object_count);
ck_rv_t TPMKey_C_FindObjectsFinal(ck_session_handle_t session);

ck_rv_t TPMKey_C_EncryptInit
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       ck_object_handle_t key)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_Encrypt
		      (ck_session_handle_t session,
		       unsigned char *data, unsigned long data_len,
		       unsigned char *encrypted_data,
		       unsigned long *encrypted_data_len)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_EncryptUpdate
		      (ck_session_handle_t session,
		       unsigned char *part, unsigned long part_len,
		       unsigned char *encrypted_part,
		       unsigned long *encrypted_part_len)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_EncryptFinal
		      (ck_session_handle_t session,
		       unsigned char *last_encrypted_part,
		       unsigned long *last_encrypted_part_len)
{ return CKR_FUNCTION_NOT_SUPPORTED; }

ck_rv_t TPMKey_C_DecryptInit
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       ck_object_handle_t key)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_Decrypt
		      (ck_session_handle_t session,
		       unsigned char *encrypted_data,
		       unsigned long encrypted_data_len,
		       unsigned char *data, unsigned long *data_len)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_DecryptUpdate
		      (ck_session_handle_t session,
		       unsigned char *encrypted_part,
		       unsigned long encrypted_part_len,
		       unsigned char *part, unsigned long *part_len)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_DecryptFinal
		      (ck_session_handle_t session,
		       unsigned char *last_part,
		       unsigned long *last_part_len)
{ return CKR_FUNCTION_NOT_SUPPORTED; }

ck_rv_t TPMKey_C_DigestInit
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_Digest
		      (ck_session_handle_t session,
		       unsigned char *data, unsigned long data_len,
		       unsigned char *digest,
		       unsigned long *digest_len)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_DigestUpdate
		      (ck_session_handle_t session,
		       unsigned char *part, unsigned long part_len)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_DigestKey
		      (ck_session_handle_t session, ck_object_handle_t key)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_DigestFinal
		      (ck_session_handle_t session,
		       unsigned char *digest,
		       unsigned long *digest_len)
{ return CKR_FUNCTION_NOT_SUPPORTED; }

ck_rv_t TPMKey_C_SignInit(ck_session_handle_t session,
			  struct ck_mechanism *mechanism,
			  ck_object_handle_t key);
ck_rv_t TPMKey_C_Sign(ck_session_handle_t session,
		      unsigned char *data, unsigned long data_len,
		      unsigned char *signature,
		      unsigned long *signature_len);
ck_rv_t TPMKey_C_SignUpdate
		      (ck_session_handle_t session,
		       unsigned char *part, unsigned long part_len)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_SignFinal
		      (ck_session_handle_t session,
		       unsigned char *signature,
		       unsigned long *signature_len)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_SignRecoverInit
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       ck_object_handle_t key)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_SignRecover
		      (ck_session_handle_t session,
		       unsigned char *data, unsigned long data_len,
		       unsigned char *signature,
		       unsigned long *signature_len)
{ return CKR_FUNCTION_NOT_SUPPORTED; }

ck_rv_t TPMKey_C_VerifyInit
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       ck_object_handle_t key)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_Verify
		      (ck_session_handle_t session,
		       unsigned char *data, unsigned long data_len,
		       unsigned char *signature,
		       unsigned long signature_len)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_VerifyUpdate
		      (ck_session_handle_t session,
		       unsigned char *part, unsigned long part_len)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_VerifyFinal
		      (ck_session_handle_t session,
		       unsigned char *signature,
		       unsigned long signature_len)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_VerifyRecoverInit
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       ck_object_handle_t key)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_VerifyRecover
		      (ck_session_handle_t session,
		       unsigned char *signature,
		       unsigned long signature_len,
		       unsigned char *data,
		       unsigned long *data_len)
{ return CKR_FUNCTION_NOT_SUPPORTED; }

ck_rv_t TPMKey_C_DigestEncryptUpdate
		      (ck_session_handle_t session,
		       unsigned char *part, unsigned long part_len,
		       unsigned char *encrypted_part,
		       unsigned long *encrypted_part_len)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_DecryptDigestUpdate
		      (ck_session_handle_t session,
		       unsigned char *encrypted_part,
		       unsigned long encrypted_part_len,
		       unsigned char *part,
		       unsigned long *part_len)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_SignEncryptUpdate
		      (ck_session_handle_t session,
		       unsigned char *part, unsigned long part_len,
		       unsigned char *encrypted_part,
		       unsigned long *encrypted_part_len)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_DecryptVerifyUpdate
		      (ck_session_handle_t session,
		       unsigned char *encrypted_part,
		       unsigned long encrypted_part_len,
		       unsigned char *part,
		       unsigned long *part_len)
{ return CKR_FUNCTION_NOT_SUPPORTED; }

ck_rv_t TPMKey_C_GenerateKey
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       struct ck_attribute *templ,
		       unsigned long count,
		       ck_object_handle_t *key)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_GenerateKeyPair
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       struct ck_attribute *public_key_template,
		       unsigned long public_key_attribute_count,
		       struct ck_attribute *private_key_template,
		       unsigned long private_key_attribute_count,
		       ck_object_handle_t *public_key,
		       ck_object_handle_t *private_key)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_WrapKey
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       ck_object_handle_t wrapping_key,
		       ck_object_handle_t key,
		       unsigned char *wrapped_key,
		       unsigned long *wrapped_key_len)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_UnwrapKey
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       ck_object_handle_t unwrapping_key,
		       unsigned char *wrapped_key,
		       unsigned long wrapped_key_len,
		       struct ck_attribute *templ,
		       unsigned long attribute_count,
		       ck_object_handle_t *key)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_DeriveKey
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       ck_object_handle_t base_key,
		       struct ck_attribute *templ,
		       unsigned long attribute_count,
		       ck_object_handle_t *key)
{ return CKR_FUNCTION_NOT_SUPPORTED; }

ck_rv_t TPMKey_C_SeedRandom
		      (ck_session_handle_t session, unsigned char *seed,
		       unsigned long seed_len)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_GenerateRandom
		      (ck_session_handle_t session,
		       unsigned char *random_data,
		       unsigned long random_len)
{ return CKR_FUNCTION_NOT_SUPPORTED; }

ck_rv_t TPMKey_C_GetFunctionStatus (ck_session_handle_t session)
{ return CKR_FUNCTION_NOT_SUPPORTED; }
ck_rv_t TPMKey_C_CancelFunction (ck_session_handle_t session)
{ return CKR_FUNCTION_NOT_SUPPORTED; }

static const struct ck_function_list tpmkey_ck_flist = {
	.version = { .major = 2, .minor = 30 },

	.C_Initialize = TPMKey_C_Initialize,
	.C_Finalize = TPMKey_C_Finalize,
	.C_GetInfo = TPMKey_C_GetInfo,
	.C_GetFunctionList = C_GetFunctionList,
	.C_GetSlotList = TPMKey_C_GetSlotList,
	.C_GetSlotInfo = TPMKey_C_GetSlotInfo,
	.C_GetTokenInfo = TPMKey_C_GetTokenInfo,
	.C_GetMechanismList = TPMKey_C_GetMechanismList,
	.C_GetMechanismInfo = TPMKey_C_GetMechanismInfo,
	.C_InitToken = TPMKey_C_InitToken,
	.C_InitPIN = TPMKey_C_InitPIN,
	.C_SetPIN = TPMKey_C_SetPIN,
	.C_OpenSession = TPMKey_C_OpenSession,
	.C_CloseSession = TPMKey_C_CloseSession,
	.C_CloseAllSessions = TPMKey_C_CloseAllSessions,
	.C_GetSessionInfo = TPMKey_C_GetSessionInfo,
	.C_GetOperationState = TPMKey_C_GetOperationState,
	.C_SetOperationState = TPMKey_C_SetOperationState,
	.C_Login = TPMKey_C_Login,
	.C_Logout = TPMKey_C_Logout,
	.C_CreateObject = TPMKey_C_CreateObject,
	.C_CopyObject = TPMKey_C_CopyObject,
	.C_DestroyObject = TPMKey_C_DestroyObject,
	.C_GetObjectSize = TPMKey_C_GetObjectSize,
	.C_GetAttributeValue = TPMKey_C_GetAttributeValue,
	.C_SetAttributeValue = TPMKey_C_SetAttributeValue,
	.C_FindObjectsInit = TPMKey_C_FindObjectsInit,
	.C_FindObjects = TPMKey_C_FindObjects,
	.C_FindObjectsFinal = TPMKey_C_FindObjectsFinal,
	.C_EncryptInit = TPMKey_C_EncryptInit,
	.C_Encrypt = TPMKey_C_Encrypt,
	.C_EncryptUpdate = TPMKey_C_EncryptUpdate,
	.C_EncryptFinal = TPMKey_C_EncryptFinal,
	.C_DecryptInit = TPMKey_C_DecryptInit,
	.C_Decrypt = TPMKey_C_Decrypt,
	.C_DecryptUpdate = TPMKey_C_DecryptUpdate,
	.C_DecryptFinal = TPMKey_C_DecryptFinal,
	.C_DigestInit = TPMKey_C_DigestInit,
	.C_Digest = TPMKey_C_Digest,
	.C_DigestUpdate = TPMKey_C_DigestUpdate,
	.C_DigestKey = TPMKey_C_DigestKey,
	.C_DigestFinal = TPMKey_C_DigestFinal,
	.C_SignInit = TPMKey_C_SignInit,
	.C_Sign = TPMKey_C_Sign,
	.C_SignUpdate = TPMKey_C_SignUpdate,
	.C_SignFinal = TPMKey_C_SignFinal,
	.C_SignRecoverInit = TPMKey_C_SignRecoverInit,
	.C_SignRecover = TPMKey_C_SignRecover,
	.C_VerifyInit = TPMKey_C_VerifyInit,
	.C_Verify = TPMKey_C_Verify,
	.C_VerifyUpdate = TPMKey_C_VerifyUpdate,
	.C_VerifyFinal = TPMKey_C_VerifyFinal,
	.C_VerifyRecoverInit = TPMKey_C_VerifyRecoverInit,
	.C_VerifyRecover = TPMKey_C_VerifyRecover,
	.C_DigestEncryptUpdate = TPMKey_C_DigestEncryptUpdate,
	.C_DecryptDigestUpdate = TPMKey_C_DecryptDigestUpdate,
	.C_SignEncryptUpdate = TPMKey_C_SignEncryptUpdate,
	.C_DecryptVerifyUpdate = TPMKey_C_DecryptVerifyUpdate,
	.C_GenerateKey = TPMKey_C_GenerateKey,
	.C_GenerateKeyPair = TPMKey_C_GenerateKeyPair,
	.C_WrapKey = TPMKey_C_WrapKey,
	.C_UnwrapKey = TPMKey_C_UnwrapKey,
	.C_DeriveKey = TPMKey_C_DeriveKey,
	.C_SeedRandom = TPMKey_C_SeedRandom,
	.C_GenerateRandom = TPMKey_C_GenerateRandom,
	.C_GetFunctionStatus = TPMKey_C_GetFunctionStatus,
	.C_CancelFunction = TPMKey_C_CancelFunction,
	.C_WaitForSlotEvent = TPMKey_C_WaitForSlotEvent,
};

__attribute__((visibility("default")))
ck_rv_t C_GetFunctionList(struct ck_function_list **flist)
{
	*flist = (struct ck_function_list *)&tpmkey_ck_flist;
	return CKR_OK;
}
