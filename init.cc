/* -*- mode: c++; c-file-style: "bsd" -*-

TPMKey init command

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
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <malloc.h>
#include "keyfile.h"

class TpmKeyContext
{
public:
	int dirfd;
	TPMContext::Ptr tpm_context;
};

int cmd_init(struct global_args &args)
{
	TPMContext::Ptr context(new TPMContext);
	context->Connect();
	TPMRsaKey::Ptr srk = TPMRsaKey::GetSRK(context);
	srk->SetUsageWKS();

	FD dirfd;
	if (mkdir(args.keyring_path.c_str(), 0700) != 0)
		throw std::runtime_error("Failed to create directory");
	dirfd.fd = open(args.keyring_path.c_str(), O_RDONLY | O_DIRECTORY, 0);
	if (dirfd.fd == -1)
		throw std::runtime_error("Failed to open directory");

	try {
		TPMBuffer::Ptr pk = srk->GetPubKey();
		TPMKey::WriteNewFile(dirfd.fd, "_public_key", 0666, pk->data, pk->len);
	} catch (TPMError) {
		// No public blob.  Sad.
	}

	return 0;
}
