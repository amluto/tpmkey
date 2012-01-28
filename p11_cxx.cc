/* -*- mode: c; c-file-style: "bsd" -*-

TPMKey pkcs11 C++ code

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

#define CRYPTOKI_GNU
#include "pkcs11.h"
#include "keyring.h"
#include <string.h>

namespace TPMKey {

// TODO: We should support enumerating hardware features via C_FindObjectsInit.
// Hopefully no applications care for now.

class P11Session;

class P11Object
{
public:
	ck_object_class_t objclass;

	// *not* a smart pointer.  Objects are destroyed with the session.
	P11Session *session;

	// Only set if we're a public or private key
	TPMKeypair::Ptr keypair;

	std::string name;  // just the last chunk of the name

	union AttrStorage {
		unsigned long ulong;
		unsigned char uchar;
	};
	bool get_attr(ck_attribute *attr, ck_attribute_type_t attrtype,
		      AttrStorage &storage);
	bool can_encrypt();
	bool can_sign();
};

class P11Session
{
public:
	void *app;  // Application's opaque handle
	ck_notify_t notify;  // Application's notification callback
	ck_flags_t flags;  // Flags specified at session creation

	// The list of object "handles"
	bool objects_loaded;
	std::vector<P11Object *> objects;

	bool find_in_progress;
	size_t next_find_result;
	std::vector<ck_attribute> find_template;

	P11Object *active_sign_object;

	TPMKeyring::Ptr keyring;

	bool has_password;
	std::string password;

	void ClearFindState()
	{
		find_in_progress = false;
		for (size_t i = 0; i < find_template.size(); i++)
			free(find_template[i].value);
		find_template.clear();
	}

	P11Session() : find_in_progress(false), active_sign_object(0), has_password(false) {}

	void LoadObjects();
};

static bool GetPw(std::string *out, const std::string &desc, void *opaque)
{
	P11Session *s = (P11Session*)opaque;
	if (!s->has_password)
		return false;
	*out = s->password;
	return true;
}

void P11Session::LoadObjects()
{
	if (objects_loaded)
		return;

	// Enumerate keys and generate objects
	std::vector<std::string> keys = keyring->list_subkeys("/token0");
	for (size_t i = 0; i < keys.size(); i++) {
		P11Object *privkey = new P11Object;
		privkey->keypair =
			keyring->LoadKey(std::string("/token0/") + keys[i], GetPw, this);
		privkey->objclass = CKO_PRIVATE_KEY;
		privkey->name = keys[i];
		privkey->session = this;
		objects.push_back(privkey);

		P11Object *pubkey = new P11Object;
		pubkey->keypair = privkey->keypair;
		pubkey->objclass = CKO_PUBLIC_KEY;
		pubkey->name = keys[i];
		pubkey->session = this;
		objects.push_back(pubkey);
	}

	objects_loaded = true;
}

bool P11Object::can_encrypt()
{
	UINT32 usage = keypair->rsakey->GetAttribUint32(
		TSS_TSPATTRIB_KEY_INFO, TSS_TSPATTRIB_KEYINFO_USAGE);
	if (usage != TSS_KEYUSAGE_LEGACY)
		return false;

	UINT32 es = keypair->rsakey->GetAttribUint32(
		TSS_TSPATTRIB_KEY_INFO, TSS_TSPATTRIB_KEYINFO_ENCSCHEME);
	return es == TSS_ES_RSAESPKCSV15;
}

bool P11Object::can_sign()
{
	UINT32 usage = keypair->rsakey->GetAttribUint32(
		TSS_TSPATTRIB_KEY_INFO, TSS_TSPATTRIB_KEYINFO_USAGE);
	if (usage != TSS_KEYUSAGE_LEGACY && usage != TSS_KEYUSAGE_SIGN)
		return false;

	UINT32 ss = keypair->rsakey->GetAttribUint32(
		TSS_TSPATTRIB_KEY_INFO, TSS_TSPATTRIB_KEYINFO_SIGSCHEME);
	return ss == TSS_SS_RSASSAPKCS1V15_DER;
}

bool P11Object::get_attr(ck_attribute *attr, ck_attribute_type_t attrtype,
			 P11Object::AttrStorage &storage)
{
	static const unsigned char true_val = 1;
	static const unsigned char false_val = 0;
	static const ck_key_type_t ckk_rsa_val = CKK_RSA;

	const void *val = 0;

	switch (attrtype) {
	case CKA_CLASS:
		val = &objclass;
		attr->value_len = sizeof(objclass);
		break;

	case CKA_SENSITIVE:
		val = &true_val;
		attr->value_len = sizeof(true_val);
		break;

	case CKA_KEY_TYPE:
		val = &ckk_rsa_val;
		attr->value_len = sizeof(ckk_rsa_val);
		break;

	case CKA_MODULUS_BITS:
		storage.ulong = keypair->rsakey->GetAttribUint32(
			TSS_TSPATTRIB_KEY_INFO, TSS_TSPATTRIB_KEYINFO_SIZE);
		val = &storage.ulong;
		attr->value_len = sizeof(storage.ulong);
		break;

	case CKA_MODULUS:
		val = keypair->public_modulus->data;
		attr->value_len = keypair->public_modulus->len;
		break;

	case CKA_PUBLIC_EXPONENT:
		val = keypair->public_exponent->data;
		attr->value_len = keypair->public_exponent->len;
		break;

	case CKA_LABEL:
	case CKA_ID:  // Pointless, but openssh needs it
		val = name.data();
		attr->value_len = name.size();
		break;

	case CKA_SUBJECT:
		val = 0;
		attr->value_len = 0;
		break;

	case CKA_ENCRYPT:
	case CKA_DECRYPT:
		storage.uchar = can_encrypt();
		val = &storage.uchar;
		attr->value_len = sizeof(storage.uchar);
		break;

	case CKA_SIGN:
	case CKA_VERIFY:
		storage.uchar = can_sign();
		val = &storage.uchar;
		attr->value_len = sizeof(storage.uchar);
		break;

	case CKA_WRAP:
	case CKA_UNWRAP:
	case CKA_DERIVE:
	case CKA_ALWAYS_AUTHENTICATE:
		val = &false_val;
		attr->value_len = sizeof(false_val);
		break;

	default:
		return false;
	}

	attr->type = attrtype;
	attr->value = const_cast<void*>(val);
	return true;
}

extern "C" ck_rv_t TPMKey_C_OpenSession(ck_slot_id_t slot_id, ck_flags_t flags,
					void *application, ck_notify_t notify,
					ck_session_handle_t *session)
{
	if (!(flags & CKF_SERIAL_SESSION))
		return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

	if (slot_id != 0)
		return CKR_SLOT_ID_INVALID;

	// Ignore R/W flag.  We don't care.
	P11Session *s = new P11Session;
	s->app = application;
	s->notify = notify;
	s->flags = flags;
	s->keyring = TPMKeyring::Ptr(new TPMKeyring(find_default_keyring().c_str()));
	*session = (ck_session_handle_t)s;
	return CKR_OK;
}

extern "C" ck_rv_t TPMKey_C_CloseSession(ck_session_handle_t session)
{
	P11Session *s = (P11Session*)session;

	s->ClearFindState();

	for (size_t i = 0; i < s->objects.size(); i++)
		delete s->objects[i];

	delete s;
	return CKR_OK;
}

extern "C" ck_rv_t TPMKey_C_Login(ck_session_handle_t session,
				  ck_user_type_t user_type,
				  unsigned char *pin, unsigned long pin_len)
{
	P11Session *s = (P11Session*)session;

	// TODO: This does not work at all according to the spec.
	size_t len = strnlen((char*)pin, pin_len);
	s->password = std::string((char*)pin, len);
	s->has_password = true;

	s->LoadObjects();
	return CKR_OK;
}

extern "C" ck_rv_t TPMKey_C_FindObjectsInit(ck_session_handle_t session,
					    struct ck_attribute *templ,
					    unsigned long count)
{
	P11Session *s = (P11Session*)session;

	s->LoadObjects();

	s->next_find_result = 0;
	s->find_in_progress = true;

	// Copy the template.  Sigh.
	s->find_template.clear();
	for (unsigned long i = 0; i < count; i++) {
		ck_attribute attrcopy;
		attrcopy.type = templ[i].type;
		attrcopy.value = malloc(templ[i].value_len);
		memcpy(attrcopy.value, templ[i].value, templ[i].value_len);
		attrcopy.value_len = templ[i].value_len;
		s->find_template.push_back(attrcopy);
	}

	return CKR_OK;
}

extern "C" ck_rv_t TPMKey_C_FindObjects(ck_session_handle_t session,
					ck_object_handle_t *object,
					unsigned long max_object_count,
					unsigned long *object_count)
{
	P11Session *s = (P11Session*)session;
	if (!s->find_in_progress)
		return CKR_OPERATION_NOT_INITIALIZED;

	size_t objs_left = max_object_count;
	ck_object_handle_t *out = object;
	*object_count = 0;

	while(objs_left && s->next_find_result < s->objects.size()) {
		P11Object *candidate = s->objects[s->next_find_result];
		s->next_find_result++;

		// Check whether the candidate matches.
		// TODO: For real
		if (true) {
			*out = (ck_object_handle_t)candidate;
			*object_count += 1;
			out++;
			objs_left--;
		}
	}

	return CKR_OK;
}

extern "C" ck_rv_t TPMKey_C_FindObjectsFinal(ck_session_handle_t session)
{
	P11Session *s = (P11Session*)session;
	if (!s->find_in_progress)
		return CKR_OPERATION_NOT_INITIALIZED;

	s->ClearFindState();

	return CKR_OK;
}

extern "C" ck_rv_t TPMKey_C_GetAttributeValue(ck_session_handle_t session,
				   ck_object_handle_t object,
				   struct ck_attribute *templ,
				   unsigned long count)
{
	P11Object *obj = (P11Object*)object;
	ck_rv_t ret = CKR_OK;
	P11Object::AttrStorage storage;

	for(unsigned long i = 0; i < count; i++) {
		ck_attribute val;
		if (!obj->get_attr(&val, templ[i].type, storage)) {
			ret = CKR_ATTRIBUTE_TYPE_INVALID;
			templ[i].value_len = (unsigned long)-1;
			continue;
		}

		if (!templ[i].value) {
			templ[i].value_len = val.value_len;
		} else if (val.value_len <= templ[i].value_len) {
			memcpy(templ[i].value, val.value, val.value_len);
			templ[i].value_len = val.value_len;
		} else {
			templ[i].value_len = -1;
			ret = CKR_BUFFER_TOO_SMALL;
		}

		// TODO: In theory, we should sometimes return
		// CKR_ATTRIBUTE_SENSITIVE.
	}

	return ret;
}

extern "C" ck_rv_t TPMKey_C_GetMechanismList(
	ck_slot_id_t slot_id,
	ck_mechanism_type_t *mechanism_list,
	unsigned long *count)
{
	if (!mechanism_list) {
		*count = 1;
		return CKR_OK;
	} else {
		unsigned long orig_len = *count;
		*count = 1;
		if (orig_len < 1)
			return CKR_BUFFER_TOO_SMALL;
		mechanism_list[0] = CKM_RSA_PKCS;
	}

	// We could also support CKM_SHA1_RSA_PKCS.

	return CKR_OK;
}

extern "C" ck_rv_t TPMKey_C_SignInit(ck_session_handle_t session,
				     struct ck_mechanism *mechanism,
				     ck_object_handle_t key)
{
	P11Session *s = (P11Session*)session;
	P11Object *obj = (P11Object*)key;

	if (mechanism->mechanism != CKM_RSA_PKCS)
		return CKR_MECHANISM_INVALID;

	// We don't support any mechanisms with parameters, so just ignore
	// the parameter.

	if (obj->objclass != CKO_PRIVATE_KEY)
		return CKR_KEY_TYPE_INCONSISTENT;

	s->active_sign_object = obj;
	return CKR_OK;
}

extern "C" ck_rv_t TPMKey_C_Sign(ck_session_handle_t session,
				 unsigned char *data, unsigned long data_len,
				 unsigned char *signature,
				 unsigned long *signature_len)
{
	P11Session *s = (P11Session*)session;
	if (!s->active_sign_object)
		return CKR_OPERATION_NOT_INITIALIZED;

	unsigned long sigsize =
		s->active_sign_object->keypair->public_modulus->len;
	if (!signature) {
		*signature_len = sigsize;
		return CKR_OK;
	}

	if (*signature_len < sigsize) {
		*signature_len = sigsize;
		return CKR_BUFFER_TOO_SMALL;
	}

	TPMBuffer::Ptr out =
		s->active_sign_object->keypair->rsakey->Sign(TSS_HASH_OTHER,
							     data, data_len);
	if (out->len > *signature_len) {
		// This shouldn't happen...
		*signature_len = out->len;
		return CKR_BUFFER_TOO_SMALL;
	}

	memcpy(signature, out->data, out->len);
	*signature_len = out->len;
	s->active_sign_object = 0;
	return CKR_OK;
}

}
