/* -*- mode: c++; c-file-style: "bsd" -*-

TPMKey main command line interface

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

#include <stdio.h>
#include <string.h>
#include <string>
#include <argp.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>


#define opt_srk_auth 1
#define opt_keyring_path 2

static struct argp_option global_options[] =
{
	{"srk-auth", opt_srk_auth, "mode", 0, "SRK authorization mode"},
	{"keyring", opt_keyring_path, "path", 0, "Path to keyring (default ~/.tpmkey)"},
	{},
};

static error_t
global_parse_opt(int key, char *arg, struct argp_state *state)
{
	global_args *args = (global_args*)state->input;
	switch (key) {
	case opt_srk_auth:
		if (!strcmp(arg, "auto")) {
			args->srk_auth_mode = global_args::AUTO;
		} else if (!strcmp(arg, "wks")) {
			args->srk_auth_mode = global_args::WKS;
		} else if (!strcmp(arg, "skip")) {
			args->srk_auth_mode = global_args::SKIP;
		} else if (!strcmp(arg, "prompt")) {
			args->srk_auth_mode = global_args::PROMPT;
		} else {
			fprintf(stderr, "Unknown srk auth mode\n");
			argp_usage(state);
		}
		break;

	case opt_keyring_path:
		args->keyring_path = arg;
		break;

	case ARGP_KEY_NO_ARGS:
		argp_usage(state);

	case ARGP_KEY_ARGS:
		args->sub_argv = state->argv + state->next;
		args->sub_argc = state->argc - state->next;
		break;
		
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static struct argp global_argp = {
	global_options, global_parse_opt, "command [command-specific args]",
	"TPMKey documentation here" };

struct subcmd {
	const char *name;
	int (*entry)(struct global_args &args);
};

int cmd_init(struct global_args &args);
int cmd_newkey(struct global_args &args);
int cmd_seedrng(struct global_args &args);

namespace TPMKey {
int cmd_raw_convert_pubkey(struct global_args &args);
}

struct subcmd subcmds[] = {
	{ "init", cmd_init },
	{ "newkey", cmd_newkey },
	{ "seedrng", cmd_seedrng },
	{ "raw_convert_pubkey", TPMKey::cmd_raw_convert_pubkey },
};

int main(int argc, char **argv)
{
	struct global_args args;
	argp_parse(&global_argp, argc, argv, ARGP_IN_ORDER, 0, &args);

	if (args.keyring_path.empty()) {
		struct passwd *pwd = getpwuid(geteuid());
		args.keyring_path = std::string(pwd->pw_dir) + "/.tpmkey";
	}

	char *cmd = args.sub_argv[0];
	for (size_t i = 0; i < sizeof(subcmds) / sizeof(subcmds[0]); i++)
	{
		if (!strcmp(cmd, subcmds[i].name))
			return subcmds[i].entry(args);
	}

	fprintf(stderr, "Unknown command\n");
	return 1;
}
