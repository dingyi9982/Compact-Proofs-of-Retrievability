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
#include <curl/curl.h>


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


static inline char separator()
{
#ifdef _WIN32
    return '\\';
#else
    return '/';
#endif
}


char *create_tmp_name(char *extension)
{
	// Set tmp_path
    struct stat sb;
    char *tmp_folder = NULL;
    if (getenv("GENARO_TEMP") &&
               stat(getenv("GENARO_TEMP"), &sb) == 0 &&
               S_ISDIR(sb.st_mode)) {
        tmp_folder = getenv("GENARO_TEMP");
#ifdef _WIN32
    } else if (getenv("TEMP") &&
               stat(getenv("TEMP"), &sb) == 0 &&
               S_ISDIR(sb.st_mode)) {
        tmp_folder = getenv("TEMP");
#else
    } else if ("/tmp" && stat("/tmp", &sb) == 0 && S_ISDIR(sb.st_mode)) {
        tmp_folder = "/tmp";
#endif
    } else {
        return NULL;
    }

    int encode_len = 10;
    int file_name_len = 10;
    int extension_len = strlen(extension);
    int tmp_folder_len = strlen(tmp_folder);
    if (tmp_folder[tmp_folder_len - 1] == separator()) {
        tmp_folder[tmp_folder_len - 1] = '\0';
        tmp_folder_len -= 1;
    }

    char *path = calloc(
        tmp_folder_len + 1 + encode_len + extension_len + 1,
        sizeof(char)
    );

    char *digest_encoded = "abcdefg";

    sprintf(path,
            "%s%c%s%s",
            tmp_folder,
            separator(),
            digest_encoded,
            extension
            );

    return path;
}


static size_t read_callback(void *ptr, size_t size, size_t nmemb, void *stream)
{
    size_t retcode;
    curl_off_t nread;

    /* in real-world cases, this would probably get this data differently
       as this fread() stuff is exactly what the library already would do
       by default internally */
    retcode = fread(ptr, size, nmemb, stream);

    nread = (curl_off_t)retcode;

    fprintf(stderr, "*** We read %" CURL_FORMAT_CURL_OFF_T
    " bytes from file\n", nread);

    return retcode;
}

/*
ret: 0 - Cheating, 1 - Verified, -1 - error.
*/
int cpor_challenge(char *filename, char *key_filename, char *t_filename, char *tag_filename, 
				   unsigned int lambda, unsigned int block_size)
{
	CPOR_params *myparams = (CPOR_params *)malloc(sizeof(CPOR_params));
	CPOR_challenge *challenge = NULL;
	CPOR_proof *proof = NULL;
	int ret = 0;

	myparams->lambda = lambda;						/* The security parameter lambda */

	myparams->prf_key_size = 20;				/* Size (in bytes) of an HMAC-SHA1 */
	myparams->enc_key_size = 32;				/* Size (in bytes) of the user's AES encryption key */
	myparams->mac_key_size = 20;				/* Size (in bytes) of the user's MAC key */

	myparams->block_size = block_size;				/* Message block size in bytes */				
	myparams->num_threads = 4;
	myparams->num_challenge = myparams->lambda;

	myparams->filename = filename;
	myparams->key_filename = key_filename;
	myparams->t_filename = t_filename;
	myparams->tag_filename = tag_filename;

	/* The size (in bits) of the prime that creates the field Z_p */
    myparams->Zp_bits = myparams->lambda;
	/* The message sector size 1 byte smaller than the size of Zp so that it 
	 * is guaranteed to be an element of the group Zp */
	myparams->sector_size = ((myparams->Zp_bits / 8) - 1);
	/* Number of sectors per block */
	myparams->num_sectors = ( (myparams->block_size / myparams->sector_size) + ((myparams->block_size % myparams->sector_size) ? 1 : 0) );

	printf("Challenging file %s...\n", myparams->filename);
	printf("\tCreating challenge for %s...", myparams->filename);
	challenge = cpor_challenge_file(myparams);
	if(!challenge) printf("No challenge\n");
	else printf("Done.\n");

	printf("\tComputing proof...");
	proof = cpor_prove_file(myparams, challenge);
	if(!proof) printf("No proof\n");
	else printf("Done.\n");

    printf("\tVerifying proof...");
	ret = cpor_verify_file(myparams, challenge, proof);
    printf("Done.\n");

    if(challenge) destroy_cpor_challenge(challenge);
	if(proof) destroy_cpor_proof(myparams, proof);

	free(myparams);

	return ret;
}

void cpor_test()
{
	char *key_filename = create_tmp_name(".key");
	char *t_filename = create_tmp_name(".t");
	char *tag_filename = create_tmp_name(".tag");

	int success = cpor_challenge("/Users/dingyi/10m.data", key_filename, t_filename, tag_filename, 80, 4096);
	if(success) {
		printf("Verified\n");
	} else {
		printf("Cheating\n");
	}
}

// void main()
// {
// 	char *key_filename = create_tmp_name(".key");
// 	char *t_filename = create_tmp_name(".t");
// 	char *tag_filename = create_tmp_name(".tag");

// 	int success = cpor_challenge("/Users/dingyi/10m.data", key_filename, t_filename, tag_filename, 80, 4096);
// 	if(success) {
// 		printf("Verified\n");
// 	} else {
// 		printf("Cheating\n");
// 	}
// }

// int main(int argc, char **argv){
	
// 	CPOR_challenge *challenge = NULL;
// 	CPOR_proof *proof = NULL;
// 	int i = -1;
// 	int opt = -1;

// #ifdef DEBUG_MODE
// 	struct timeval tv1, tv2;
// 	double values[26];
	
// 	memset(values, 0, sizeof(double) * 26);
// #endif
	
// 	if(argc < 2) return -1;
	
// 	/* Set default parameters */
// 	myparams->lambda = 80;						/* The security parameter lambda */

// 	myparams->prf_key_size = 20;				/* Size (in bytes) of an HMAC-SHA1 */
// 	myparams->enc_key_size = 32;				/* Size (in bytes) of the user's AES encryption key */
// 	myparams->mac_key_size = 20;				/* Size (in bytes) of the user's MAC key */

// 	myparams->block_size = 4096;				/* Message block size in bytes */				
// 	myparams->num_threads = 4;
// 	myparams->num_challenge = myparams->lambda;	/* From the paper, a "conservative choice" for l is lamda, the number of bits to represent our group, Zp */

// 	myparams->filename = NULL;

// 	myparams->op = CPOR_OP_NOOP;

//     //myparams->server = "http://10.211.55.4:9999/challenge/tag";
// 	myparams->server = "http://192.168.50.206:9999/challenge/tag";
// 	//myparams->server = "http://localhost:9999/challenge/tag";

// 	curl_global_init(CURL_GLOBAL_ALL);

// 	while((opt = getopt_long(argc, argv, "b:e:h:l:m:p:kt:v:y:", longopts, NULL)) != -1){
// 		switch(opt){
// 			case 'b':
// 				myparams->block_size = atoi(optarg);
// 				break;
// 			case 'e':
// 				myparams->enc_key_size = (unsigned int)atoi(optarg);
// 				if(myparams->enc_key_size != 16 && myparams->enc_key_size != 24 && myparams->enc_key_size != 32){
// 					fprintf(stderr, "Invalid encryption key size.  Must be 16, 24 or 32 bytes.\n");
// 					return -1;
// 				}
// 				break;
// 			case 'h':
// 				myparams->num_threads = atoi(optarg);
// 				break;
// 			case 'k':
// 				myparams->op = CPOR_OP_KEYGEN;
// 				break;
// 			case 'l':
// 				myparams->num_challenge = atoi(optarg);
// 				break;
// 			case 'm':
// 				myparams->mac_key_size = atoi(optarg);
// 				break;
// 			case 'p':
// 				myparams->prf_key_size = atoi(optarg);
// 				break;
// 			case 't':
// 				if(strlen(optarg) >= MAXPATHLEN){
// 					fprintf(stderr, "ERROR: File name is too long.\n");
// 					break;
// 				}
// 				myparams->filename = optarg;
// 				myparams->op = CPOR_OP_TAG;

// 				break;

// 			case 'v':
// 				if(strlen(optarg) >= MAXPATHLEN){
// 					fprintf(stderr, "ERROR: File name is too long.\n");
// 					break;
// 				}
// 				myparams->filename = optarg;
// 				myparams->op = CPOR_OP_VERIFY;

// 				break;
// 			case 'y':
// 				myparams->lambda = atoi(optarg);
// 				break;				
// 			default:
// 				break;
// 		}
// 	}


//     /* The size (in bits) of the prime that creates the field Z_p */
//     myparams->Zp_bits = myparams->lambda;
// 	/* The message sector size 1 byte smaller than the size of Zp so that it 
// 	 * is guaranteed to be an element of the group Zp */
// 	myparams->sector_size = ((myparams->Zp_bits / 8) - 1);
// 	/* Number of sectors per block */
// 	myparams->num_sectors = ( (myparams->block_size / myparams->sector_size) + ((myparams->block_size % myparams->sector_size) ? 1 : 0) );


// 	switch(myparams->op){
// 		case CPOR_OP_TAG:
// 			printf("Generating keys...");
// 			myparams->key_filename = create_tmp_name(".key");
// 			if(!cpor_create_new_keys(myparams->key_filename)) printf("Couldn't create keys\n");
// 			else printf("Done\n");

// 			printf("Tagging %s...", myparams->filename);
// 		#ifdef DEBUG_MODE
// 			gettimeofday(&tv1, NULL);
// 		#endif
//             myparams->tag_filename = create_tmp_name(".tag");
//             myparams->t_filename = create_tmp_name(".t");
// 			if(!cpor_tag_file(myparams->filename, strlen(myparams->filename), myparams->key_filename, myparams->tag_filename, 
//                 strlen(myparams->tag_filename), myparams->t_filename, strlen(myparams->t_filename))) printf("No tag\n");
// 			else printf("Done\n");
// 		#ifdef DEBUG_MODE
// 			gettimeofday(&tv2, NULL);
// 			printf("%lf\n", (double)tv2.tv_sec + (double)((double)tv2.tv_usec/1000000) - (double)((double)tv1.tv_sec) + (double)((double)tv1.tv_usec/1000000));
// 		#endif
//             CURL *curl = curl_easy_init();
//             if (!curl) {
//                 return 1;
//             }

//             CURLcode res;
//             FILE *tag_file ;
//             struct stat file_info;

//             /* get the file size of the local file */
//             stat(myparams->tag_filename, &file_info);

//             /* get a FILE * of the same file, could also be made with
//             fdopen() from the previous descriptor, but hey this is just
//             an example! */
//             tag_file = fopen(myparams->tag_filename, "rb");

//             /* In windows, this will init the winsock stuff */
//             curl_global_init(CURL_GLOBAL_ALL);

//             /* get a curl handle */
//             curl = curl_easy_init();
//             if(curl) {
//                 /* we want to use our own read function */
//                 curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);

//                 /* enable uploading */
//                 curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

//                 /* HTTP PUT please */
//                 curl_easy_setopt(curl, CURLOPT_PUT, 1L);

//                 /* specify target URL, and note that this URL should include a file
//                 name, not only a directory */
//                 curl_easy_setopt(curl, CURLOPT_URL, myparams->server);

//                 /* now specify which file to upload */
//                 curl_easy_setopt(curl, CURLOPT_READDATA, tag_file);

//                 /* provide the size of the upload, we specicially typecast the value
//                 to curl_off_t since we must be sure to use the correct data size */
//                 curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE,
//                                 (curl_off_t)file_info.st_size);

//                 /* Now run off and do what you've been told! */
//                 res = curl_easy_perform(curl);
//                 /* Check for errors */
//                 if(res != CURLE_OK)
//                     fprintf(stderr, "curl_easy_perform() failed: %s\n",
//                             curl_easy_strerror(res));

//                 /* always cleanup */
//                 curl_easy_cleanup(curl);
//                 fclose(tag_file); /* close the local file */
//             }
// 			break;
			
// 		case CPOR_OP_VERIFY:
// 			myparams->key_filename = create_tmp_name(".key");
// 			myparams->tag_filename = create_tmp_name(".tag");
// 			myparams->t_filename = create_tmp_name(".t");
// 		#ifdef DEBUG_MODE
// 			printf("Using the following settings:\n");
// 			printf("\tBlock Size: %u bytes\n", myparams->block_size);
// 			printf("\tNumber of Threads: %u \n", myparams->num_threads);
// 			printf("\tNumber of Challenge blocks: %u \n", myparams->num_challenge);
// 		#endif		
// 			printf("Challenging file %s...\n", myparams->filename);				
// 			printf("\tCreating challenge for %s...", myparams->filename);
// 			challenge = cpor_challenge_file(myparams->filename, strlen(myparams->filename), myparams->key_filename, myparams->t_filename, strlen(myparams->t_filename));
// 			if(!challenge) printf("No challenge\n");
// 			else printf("Done.\n");

// 			printf("\tComputing proof...");fflush(stdout);
// 			proof = cpor_prove_file(myparams->filename, strlen(myparams->filename), myparams->tag_filename, strlen(myparams->tag_filename), challenge);
// 			if(!proof) printf("No proof\n");
// 			else printf("Done.\n");

// 			printf("\tVerifying proof...");		
// 			if((i = cpor_verify_file(myparams->filename, strlen(myparams->filename), myparams->key_filename, myparams->t_filename, strlen(myparams->t_filename), challenge, proof)) == 1) printf("Verified\n");
// 			else if(i == 0) printf("Cheating!\n");
// 			else printf("Error\n");

// 			if(challenge) destroy_cpor_challenge(challenge);
// 			if(proof) destroy_cpor_proof(proof);
// 			break;

// 		case CPOR_OP_NOOP:
// 		default:
// 			break;
// 	}

//     curl_global_cleanup();
	
// 	return 0;
	
// }
