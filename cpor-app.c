/* 
* cpor-app.c
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

#include "cpor.h"
#include <getopt.h>



static struct option longopts[] = {
	{"numchallenge", no_argument, NULL, 'l'},
	{"lambda", no_argument, NULL, 'y'}, 
	{"Zp", no_argument, NULL, 'z'},
	{"prf_key_size", no_argument, NULL, 'p'},
	{"enc_key_size", no_argument, NULL, 'e'},
	{"mac_key_size", no_argument, NULL, 'm'},
	{"blocksize", no_argument, NULL, 'b'},
	{"sectorsize", no_argument, NULL, 'c'},
	{"numsectors", no_argument, NULL, 'n'},
	{"numthreads", no_argument, NULL, 'h'},
	{"keygen", no_argument, NULL, 'k'}, //TODO optional argument for key location
	{"tag", no_argument, NULL, 't'},
	{"verify", no_argument, NULL, 'v'},
	{NULL, 0, NULL, 0}
};


int main(int argc, char **argv){
	
	CPOR_challenge *challenge = NULL;
	CPOR_proof *proof = NULL;
	int i = -1;
	int opt = -1;

#ifdef DEBUG_MODE
	struct timeval tv1, tv2;
	double values[26];
	
	memset(values, 0, sizeof(double) * 26);
#endif
	
	if(argc < 2) return -1;
	
	/* Set default parameters */
	params.lambda = 80;						/* The security parameter lambda */

	params.prf_key_size = 20;				/* Size (in bytes) of an HMAC-SHA1 */
	params.enc_key_size = 32;				/* Size (in bytes) of the user's AES encryption key */
	params.mac_key_size = 20;				/* Size (in bytes) of the user's MAC key */

	params.block_size = 4096;				/* Message block size in bytes */				
	params.num_threads = 4;
	params.num_challenge = params.lambda;	/* From the paper, a "conservative choice" for l is lamda, the number of bits to represent our group, Zp */

	params.filename = NULL;
	params.filename_len = 0;

	params.op = CPOR_OP_NOOP;

	


	while((opt = getopt_long(argc, argv, "b:e:h:l:m:p:kt:v:y:", longopts, NULL)) != -1){
		switch(opt){
			case 'b':
				params.block_size = atoi(optarg);
				break;
			case 'e':
				params.enc_key_size = (unsigned int)atoi(optarg);
				if(params.enc_key_size != 16 && params.enc_key_size != 24 && params.enc_key_size != 32){
					fprintf(stderr, "Invalid encryption key size.  Must be 16, 24 or 32 bytes.\n");
					return -1;
				}
				break;
			case 'h':
				params.num_threads = atoi(optarg);
				break;
			case 'k':
				params.op = CPOR_OP_KEYGEN;
				break;
			case 'l':
				params.num_challenge = atoi(optarg);
				break;
			case 'm':
				params.mac_key_size = atoi(optarg);
				break;
			case 'p':
				params.prf_key_size = atoi(optarg);
				break;
			case 't':
				if(strlen(optarg) >= MAXPATHLEN){
					fprintf(stderr, "ERROR: File name is too long.\n");
					break;
				}
				params.filename = optarg;
				params.filename_len = strlen(optarg);
				params.op = CPOR_OP_TAG;

				break;

			case 'v':
				if(strlen(optarg) >= MAXPATHLEN){
					fprintf(stderr, "ERROR: File name is too long.\n");
					break;
				}
				params.filename = optarg;
				params.filename_len = strlen(optarg);
				params.op = CPOR_OP_VERIFY;

				break;
			case 'y':
				params.lambda = atoi(optarg);
				break;				
			default:
				break;
		}
	}


    /* The size (in bits) of the prime that creates the field Z_p */
    params.Zp_bits = params.lambda;
	/* The message sector size 1 byte smaller than the size of Zp so that it 
	 * is guaranteed to be an element of the group Zp */
	params.sector_size = ((params.Zp_bits/8) - 1);
	/* Number of sectors per block */
	params.num_sectors = ( (params.block_size/params.sector_size) + ((params.block_size % params.sector_size) ? 1 : 0) );


	switch(params.op){
		case CPOR_OP_KEYGEN:
		#ifdef DEBUG_MODE
			fprintf(stdout, "Using the following settings:\n");
			fprintf(stdout, "\tLambda: %u\n", params.lambda);
			fprintf(stdout, "\tPRF Key Size: %u bytes\n", params.prf_key_size);
			fprintf(stdout, "\tENC Key Size: %u bytes\n", params.enc_key_size);
			fprintf(stdout, "\tMAC Key Size: %u bytes\n", params.mac_key_size);
		#endif
			fprintf(stdout, "Generating keys...");
			if(!cpor_create_new_keys()) printf("Couldn't create keys\n");
			else printf("Done\n");
			break;
		
		case CPOR_OP_TAG:
		#ifdef DEBUG_MODE
			fprintf(stdout, "Using the following settings:\n");
			fprintf(stdout, "\tBlock Size: %u bytes\n", params.block_size);
			fprintf(stdout, "\tNumber of Threads: %u \n", params.num_threads);
		#endif			
			fprintf(stdout, "Tagging %s...", params.filename); fflush(stdout);
		#ifdef DEBUG_MODE
			gettimeofday(&tv1, NULL);
		#endif
			if(!cpor_tag_file(params.filename, params.filename_len, NULL, 0, NULL, 0)) printf("No tag\n");
			else printf("Done\n");
		#ifdef DEBUG_MODE
			gettimeofday(&tv2, NULL);
			printf("%lf\n", (double)( (double)(double)(((double)tv2.tv_sec) + (double)((double)tv2.tv_usec/1000000)) - (double)((double)((double)tv1.tv_sec) + (double)((double)tv1.tv_usec/1000000)) ) );
		#endif
			break;
			
			
		case CPOR_OP_VERIFY:
		#ifdef DEBUG_MODE
			fprintf(stdout, "Using the following settings:\n");
			fprintf(stdout, "\tBlock Size: %u bytes\n", params.block_size);
			fprintf(stdout, "\tNumber of Threads: %u \n", params.num_threads);
			fprintf(stdout, "\tNumber of Challenge blocks: %u \n", params.num_challenge);
		#endif		
			fprintf(stdout, "Challenging file %s...\n", params.filename); fflush(stdout);				
			fprintf(stdout, "\tCreating challenge for %s...", params.filename); fflush(stdout);
			challenge = cpor_challenge_file(params.filename, params.filename_len, NULL, 0);
			if(!challenge) printf("No challenge\n");
			else printf("Done.\n");

			fprintf(stdout, "\tComputing proof...");fflush(stdout);
			proof = cpor_prove_file(params.filename, params.filename_len, NULL, 0, challenge);
			if(!proof) printf("No proof\n");
			else printf("Done.\n");

			printf("\tVerifying proof..."); fflush(stdout);		
			if((i = cpor_verify_file(params.filename, params.filename_len, NULL, 0, challenge, proof)) == 1) printf("Verified\n");
			else if(i == 0) printf("Cheating!\n");
			else printf("Error\n");

			if(challenge) destroy_cpor_challenge(challenge);
			if(proof) destroy_cpor_proof(proof);		
			break;

		case CPOR_OP_NOOP:
		default:
			break;
	}
	
	return 0;
	
}









/*
	unsigned char k_prf[CPOR_PRF_KEY_SIZE];
	unsigned char block[CPOR_BLOCK_SIZE];
	CPOR_global *global = NULL;
	CPOR_tag *tag;
	BIGNUM **alpha = NULL;

	printf("Blocksize: %d Sector size: %d Num sectors: %d\n", CPOR_BLOCK_SIZE, CPOR_SECTOR_SIZE, CPOR_NUM_SECTORS);
	
	global = cpor_create_global(CPOR_ZP_BITS);
	if(!global) printf("No global\n");
	
	RAND_bytes(k_prf, CPOR_PRF_KEY_SIZE);
	RAND_bytes(block, CPOR_BLOCK_SIZE);
	
	alpha = malloc(sizeof(BIGNUM *) * CPOR_NUM_SECTORS);
	memset(alpha, 0, sizeof(BIGNUM *) * CPOR_NUM_SECTORS);
	
	for(i = 0; i < CPOR_NUM_SECTORS; i++){
		alpha[i] = BN_new();
		BN_rand_range(alpha[i], global->Zp);
	}
	
	tag = cpor_tag_block(global, k_prf, alpha, block, CPOR_BLOCK_SIZE, 0);
	if(!tag) printf("No tag\n");
	
	
	challenge = cpor_create_challenge(global, 1);
	if(!challenge) printf("No challenge\n");
		
	proof = cpor_create_proof_update(global, challenge, proof, tag, block, CPOR_BLOCK_SIZE, 0);
	if(!proof) printf("No proof\n");
	
	if(( i = cpor_verify_proof(global, proof, challenge, k_prf, alpha)) == 1 ) printf("Verified!\n");
	else if (i == 0) printf("Cheating!\n");
	else printf("Error!\n");
	
	for(i = 0; i < CPOR_NUM_SECTORS; i++){
		if(alpha[i]) BN_clear_free(alpha[i]);
	}
	sfree(alpha, sizeof(BIGNUM *) * CPOR_NUM_SECTORS);
	
	destroy_cpor_global(global);
	destroy_cpor_tag(tag);
	destroy_cpor_challenge(challenge);
	destroy_cpor_proof(proof);
*/