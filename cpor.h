/* 
* cpor.h
*
* Copyright (c) 2010, Zachary N J Peterson <znpeters@nps.edu>
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*     * Redistributions of source code must retain the above copyright
*       notice, this list of conditions and the following disclaimer.
*     * Redistributions in binary form must reproduce the above copyright
*       notice, this list of conditions and the following disclaimer in the
*       documentation and/or other materials provided with the distribution.
*     * Neither the name of the Naval Postgraduate School nor the
*       names of its contributors may be used to endorse or promote products
*       derived from this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY ZACHARY N J PETERSON ``AS IS'' AND ANY
* EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL ZACHARY N J PETERSON BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#ifndef __CPOR_H__
#define __CPOR_H__

#include <openssl/bn.h>

#ifndef _WIN32
#include <unistd.h>
#endif

#define DEBUG_MODE
#define THREADING

/* Modes of operation */
#define CPOR_OP_NOOP 0x00
#define CPOR_OP_TAG 0x01
#define CPOR_OP_VERIFY 0x02
#define CPOR_OP_KEYGEN 0x03

typedef struct CPOR_parameters_struct CPOR_params;

struct CPOR_parameters_struct{
	/* Parameters */
	unsigned int lambda;		/* The security parameter lambda */
	unsigned int Zp_bits;		/* The size (in bits) of the prime that creates the field Z_p */
	unsigned int prf_key_size;	/* Size (in bytes) of an HMAC-SHA1 */
	unsigned int enc_key_size;	/* Size (in bytes) of the user's AES encryption key */
	unsigned int mac_key_size;	/* Size (in bytes) of the user's MAC key */

	unsigned int block_size;	/* Message block size in bytes */
	unsigned int sector_size;	/* Message sector size in bytes */
	unsigned int num_sectors;	/* Number of sectors per block */
	unsigned int num_challenge;	/* Number of blocks to challenge */
	
	unsigned int num_threads;	/* Number of tagging threads */
};

/* Global settings */
typedef struct CPOR_global_struct CPOR_global;

struct CPOR_global_struct{
	BIGNUM *Zp;					/* The prime p that defines the field Zp */
};

/* This is the client's secret key */
typedef struct CPOR_key_struct CPOR_key;

struct CPOR_key_struct{
	unsigned char *k_enc;	/* The user's secret encryption key */
	size_t k_enc_size;		/* Encryption size in bytes */
	unsigned char *k_mac;	/* The user's secret MAC key */
	size_t k_mac_size;		/* MAC key size in bytes */
	CPOR_global *global;
};

typedef struct CPOR_tag_struct CPOR_tag;

struct CPOR_tag_struct{
	BIGNUM *sigma;			/* The resulting authenticator, sigma_i*/
	unsigned int index;		/* The index for the authenticator, i */
};

typedef struct CPOR_t_struct CPOR_t;

struct CPOR_t_struct{
	unsigned int n;			/* The number of blocks in the file */
	unsigned char *k_prf;	/* The randomly generated PRF key for this file */
	BIGNUM **alpha;
};

typedef struct CPOR_challenge_struct CPOR_challenge;

struct CPOR_challenge_struct{
	unsigned int l;			/* The number of elements to be tested */
	unsigned int *I;		/* An array of l indicies to be tested */
	BIGNUM **nu;			/* An array of l random elements */
	CPOR_global *global;
};

typedef struct CPOR_proof_struct CPOR_proof;

struct CPOR_proof_struct{
	BIGNUM *sigma;
	BIGNUM **mu;
};

/* File-level CPOR functions from cpor-file.c */
int cpor_tag_file(CPOR_params *params, char *filename, char *key_filename, char *t_filename, char *tag_filename);

CPOR_challenge *cpor_challenge(CPOR_params *params, char *key_data, char *t_data);

CPOR_tag **cpor_get_tags(CPOR_challenge *challenge, char *tag_data);

CPOR_proof *cpor_prove_file(CPOR_params *params, char *filename, CPOR_challenge *challenge, CPOR_tag **tags);

int cpor_verify_file(CPOR_params *params, char *filename, char *key_data, char *t_data, CPOR_challenge *challenge, CPOR_proof *proof);

CPOR_tag *read_cpor_tag(char *tag_data, unsigned int index);

/* Key management from cpor-keys.c */
CPOR_key *cpor_create_new_keys();

/* Core CPOR functions from cpor-core.c */
CPOR_global *cpor_create_global(unsigned int bits);

CPOR_tag *cpor_tag_block(CPOR_params *params, CPOR_global *global, unsigned char *k_prf, BIGNUM **alpha, unsigned char *block, unsigned int index);

CPOR_challenge *cpor_create_challenge(CPOR_params *params, CPOR_global *global, unsigned int n);

CPOR_proof *cpor_create_proof_update(CPOR_params *params, CPOR_challenge *challenge, CPOR_proof *proof, CPOR_tag *tag, unsigned char *block, unsigned int index, unsigned int i);

CPOR_proof *cpor_create_proof_final(CPOR_proof *proof);

int cpor_verify_proof(CPOR_params *params, CPOR_global *global, CPOR_proof *proof, CPOR_challenge *challenge, unsigned char *k_prf, BIGNUM **alpha);

/* Key functions from cpor-keys.c */
// CPOR_key *cpor_get_keys(CPOR_params *params, char *key_filename);
CPOR_key *cpor_get_keys_from_file(CPOR_params *params, char *key_filename);
CPOR_key *cpor_get_keys_from_data(CPOR_params *params, char *key_data);

void destroy_cpor_key(CPOR_params *params, CPOR_key *key);

/* Helper functions from cpor-misc.c */

void sfree(void *ptr, size_t size);

int get_rand_range(unsigned int min, unsigned int max, unsigned int *value);

size_t get_ciphertext_size(size_t plaintext_len);

size_t get_authenticator_size();

int decrypt_and_verify_secrets(CPOR_key *key, unsigned char *input, size_t input_len, unsigned char *plaintext, size_t *plaintext_len, unsigned char *authenticator, size_t authenticator_len);

int encrypt_and_authentucate_secrets(CPOR_key *key, unsigned char *input, size_t input_len, unsigned char *ciphertext, size_t *ciphertext_len, unsigned char *authenticator, size_t *authenticator_len);

CPOR_t *cpor_create_t(CPOR_params *params, CPOR_global *global, unsigned int n);

BIGNUM *generate_prf_i(CPOR_params *params, unsigned char *key, unsigned int index);

CPOR_proof *allocate_cpor_proof();
void destroy_cpor_proof(CPOR_params *params, CPOR_proof *proof);

void destroy_cpor_challenge(CPOR_challenge *challenge);
CPOR_challenge *allocate_cpor_challenge(unsigned int l);

void destroy_cpor_tag(CPOR_tag *tag);
CPOR_tag *allocate_cpor_tag();

void destroy_cpor_t(CPOR_params *params, CPOR_t *t);
CPOR_t *allocate_cpor_t(CPOR_params *params);

void destroy_cpor_global(CPOR_global *global);
CPOR_global *allocate_cpor_global();

int cpor_tag(char *filename, char *key_filename, char *t_filename, char *tag_filename);
int cpor_verify(char *filename, char *key_data, char *t_data, char *tag_data);

#endif
