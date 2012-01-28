/* -*- mode: c++; c-file-style: "bsd" -*-

TPMKey general helper functions

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

#include "utils.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>

namespace TPMKey {

void WriteNewFile(int dirfd, const char *path, mode_t mode,
		  const void *buf, size_t len)
{
	FD fd;
	fd.fd = openat(dirfd, path, O_WRONLY | O_CREAT | O_EXCL, mode);
	if (fd.fd == -1)
		throw std::runtime_error("meh");
	if (write(fd.fd, buf, len) != (ssize_t)len) {
		close(fd.fd);
		fd.fd = -1;
		unlinkat(dirfd, path, 0);
		throw std::runtime_error("failed to write");
	}
}

TPMBuffer::Ptr ReadFile(int dirfd, const char *path, size_t maxlen)
{
	FD fd;
	fd.fd = openat(dirfd, path, O_RDONLY);
	if (fd.fd == -1)
		throw std::runtime_error("Failed to open");
	TPMBuffer::Ptr out(new TPMBuffer(maxlen));

	char garbage;
	struct iovec iov[2] = {
		{ out->data, maxlen },
		{ &garbage, 1 },
	};

	ssize_t bytes = readv(fd.fd, iov, 2);
	if (bytes < 0)
		throw std::runtime_error("Failed to read");
	if ((size_t)bytes > maxlen)
		throw std::runtime_error("File is too big");
	out->len = bytes;
	return out;
}

}
