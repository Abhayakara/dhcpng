/* hash.h

   Definitions for hashing... */

/*
 * Copyright (c) 2002-2006 Nominum, Inc.
 *
 * Copyright (c) 1995-2001 Internet Software Consortium.
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

#ifndef HASH_H
#define HASH_H

#define DEFAULT_HASH_SIZE	9973

/* The purpose of the hashed_object_t struct is to not match anything else. */
typedef struct {
	int foo;
} hashed_object_t;

typedef void (*hash_foreach_func) (const unsigned char *,
				   unsigned, hashed_object_t *);
typedef int (*hash_reference) (hashed_object_t **, hashed_object_t *,
			       const char *, int);
typedef int (*hash_dereference) (hashed_object_t **, const char *, int);

struct hash_bucket {
	struct hash_bucket *next;
	const unsigned char *name;
	unsigned len;
	hashed_object_t *value;
};

typedef int (*hash_comparator_t)(const void *, const void *, unsigned long);

struct hash_table {
	unsigned hash_count;
	struct hash_bucket *buckets [DEFAULT_HASH_SIZE];
	hash_reference referencer;
	hash_dereference dereferencer;
	hash_comparator_t cmp;
	int (*do_hash) (const unsigned char *, unsigned, unsigned);
};

struct named_hash {
	struct named_hash *next;
	const char *name;
	struct hash_table *hash;
};

#define HASH_FUNCTIONS_DECL(name, bufarg, type, hashtype)		      \
void name##_hash_add (hashtype *, bufarg, unsigned, type *);		      \
void name##_hash_delete (hashtype *, bufarg, unsigned);			      \
int name##_hash_lookup (type **, hashtype *, bufarg, unsigned);		      \
int name##_hash_foreach (hashtype *,					      \
			 void (*) (bufarg, unsigned, type *));		      \
int name##_new_hash (hashtype **, int);					      \
void name##_free_hash_table (hashtype **);


#define HASH_FUNCTIONS(name, bufarg, type, hashtype)			      \
void name##_hash_add (hashtype *table,					      \
		      bufarg buf, unsigned len, type *ptr)		      \
{									      \
	add_hash ((struct hash_table *)table,				      \
		  (const unsigned char *)buf,				      \
		  len, (hashed_object_t *)ptr);				      \
}									      \
									      \
void name##_hash_delete (hashtype *table,				      \
			 bufarg buf, unsigned len)			      \
{									      \
	delete_hash_entry ((struct hash_table *)table,			      \
			   (const unsigned char *)buf, len);		      \
}									      \
									      \
int name##_hash_lookup (type **ptr, hashtype *table,			      \
			bufarg buf, unsigned len)			      \
{									      \
	return hash_lookup ((hashed_object_t **)ptr,			      \
			    (struct hash_table *)table,			      \
			    (const unsigned char *)buf, len);		      \
}									      \
									      \
int name##_hash_foreach (hashtype *table,				      \
			 void (*func) (bufarg, unsigned, type *))	      \
{									      \
	return hash_foreach ((struct hash_table *)table,		      \
			     (hash_foreach_func)func);			      \
}									      \
									      \
int name##_new_hash (hashtype **tp, int c)				      \
{									      \
	return new_hash ((struct hash_table **)tp, c);			      \
}

int new_hash_table (struct hash_table **, int);
void free_hash_table (struct hash_table **);
struct hash_bucket *new_hash_bucket(void);
void free_hash_bucket (struct hash_bucket *);
int new_hash (struct hash_table **, int);
void add_hash (struct hash_table *,
	       const unsigned char *, unsigned, hashed_object_t *);
void delete_hash_entry (struct hash_table *, const unsigned char *, unsigned);
int hash_lookup (hashed_object_t **, struct hash_table *,
		 const unsigned char *, unsigned);
int hash_foreach (struct hash_table *, hash_foreach_func);
int casecmp (const void *s, const void *t, unsigned long len);

#endif /* HASH_H */
