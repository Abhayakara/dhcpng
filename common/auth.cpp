/* auth.cpp

   Subroutines having to do with authentication. */

/*
 * Copyright (c) 2002-2006 Nominum, Inc.
 * All rights reserved.
 *
 * Copyright (c) 1998-2001 Internet Software Consortium.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Nominum, Internet Software Consortium nor the
 *    names of its contributors may be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY NOMINUM, THE INTERNET SOFTWARE
 * CONSORTIUM AND CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL NOMINUM, THE INTERNET SOFTWARE CONSORTIUM OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef lint
static char copyright[] __attribute__((unused)) =
"$Id: auth.cpp,v 1.2 2006/05/12 21:51:35 mellon Exp $ Copyright 1998-2000 The Internet Software Consortium.";
#endif

#include "dhcpd.h"

auth_hash_t *auth_key_hash;
HASH_FUNCTIONS (auth_key, const char *, auth_key_t, auth_hash_t)

isc_result_t auth_key_enter (auth_key_t *a)
{
	auth_key_t *tk;

	tk = (auth_key_t *)0;
	if (auth_key_hash) {
		auth_key_hash_lookup (&tk, auth_key_hash, a->name, 0);
		if (tk == a) {
			return ISC_R_SUCCESS;
		}
		if (tk) {
			auth_key_hash_delete (auth_key_hash,
						    tk->name, 0);
		}
	} else {
		if (!auth_key_new_hash (&auth_key_hash, 1))
			return ISC_R_NOMEMORY;
	}
	auth_key_hash_add (auth_key_hash, a->name, 0, a);
	return ISC_R_SUCCESS;
	
}

isc_result_t auth_key_lookup_name (auth_key_t **a, const char *name)
{
	if (!auth_key_hash)
		return ISC_R_NOTFOUND;
	if (!auth_key_hash_lookup (a, auth_key_hash, name, 0))
		return ISC_R_NOTFOUND;
	return ISC_R_SUCCESS;
}
