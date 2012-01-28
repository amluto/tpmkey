/* -*- mode: c++; c-file-style: "bsd" -*-

TPMKey seedrng command

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
#include <stdlib.h>
#include <sys/ioctl.h>
#include <linux/random.h>

int cmd_seedrng(struct global_args &args)
{
	if (args.sub_argc < 2 || args.sub_argc > 3) {
		fprintf(stderr, "Usage: tpmkey seedrng BITS [BITS_TO_CREDIT]\n");
		return 1;
	}

	const char *rng_device = "/dev/random";

	int bytes_to_read = (atoi(args.sub_argv[1]) + 7) / 8; 
	if (bytes_to_read < 0)
		return 1;
	else if (bytes_to_read == 0)
		return 0;

	int bits_to_credit = 0;
	if (args.sub_argc >= 3)
		bits_to_credit = atoi(args.sub_argv[2]);

	FD fd;
	fd.fd = open(rng_device, O_RDWR);
	if (fd.fd == -1) {
		perror(rng_device);
		return 1;
	}

	int tmp;
	if (ioctl(fd.fd, RNDGETENTCNT, &tmp) != 0) {
		fprintf(stderr, "%s does not appear to be a kernel rng\n",
			rng_device);
		return 1;
	}

	TPMContext::Ptr context(new TPMContext);
	context->Connect();
	TPMBuffer::Ptr data = context->GetRandom(bytes_to_read);

	if (bits_to_credit) {
		// TODO: Check for overflow
		TPMBuffer::Ptr iobuf(new TPMBuffer(data->len + 2*sizeof(int)));
		int *p = (int*)iobuf->data;
		p[0] = bits_to_credit;
		p[1] = data->len;
		memcpy(p + 2, data->data, data->len);
		if (ioctl(fd.fd, RNDADDENTROPY, p) != 0) {
			perror("RNDADDENTROPY");
			return 1;
		}
	} else {
		if (write(fd.fd, data->data, data->len) != data->len) {
			perror("write");
			return 1;
		}
	}

	return 0;
}

