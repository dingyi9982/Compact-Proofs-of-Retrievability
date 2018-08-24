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
    char *tmp_folder = "/tmp";
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

	params.op = CPOR_OP_NOOP;

    params.server = "http://localhost:9999/challenge/tag";

	curl_global_init(CURL_GLOBAL_ALL);

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
				params.op = CPOR_OP_TAG;

				break;

			case 'v':
				if(strlen(optarg) >= MAXPATHLEN){
					fprintf(stderr, "ERROR: File name is too long.\n");
					break;
				}
				params.filename = optarg;
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
            params.tag_filename = create_tmp_name(".tag");
            params.t_filename = create_tmp_name(".t");
			if(!cpor_tag_file(params.filename, strlen(params.filename), params.tag_filename, 
                strlen(params.tag_filename), params.t_filename, strlen(params.t_filename))) printf("No tag\n");
			else printf("Done\n");
		#ifdef DEBUG_MODE
			gettimeofday(&tv2, NULL);
			printf("%lf\n", (double)tv2.tv_sec + (double)((double)tv2.tv_usec/1000000) - (double)((double)tv1.tv_sec) + (double)((double)tv1.tv_usec/1000000));
		#endif
            CURL *curl = curl_easy_init();
            if (!curl) {
                return 1;
            }

            CURLcode res;
            FILE *tag_file ;
            struct stat file_info;

            /* get the file size of the local file */
            stat(params.tag_filename, &file_info);

            /* get a FILE * of the same file, could also be made with
            fdopen() from the previous descriptor, but hey this is just
            an example! */
            tag_file = fopen(params.tag_filename, "rb");

            /* In windows, this will init the winsock stuff */
            curl_global_init(CURL_GLOBAL_ALL);

            /* get a curl handle */
            curl = curl_easy_init();
            if(curl) {
                /* we want to use our own read function */
                curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);

                /* enable uploading */
                curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

                /* HTTP PUT please */
                curl_easy_setopt(curl, CURLOPT_PUT, 1L);

                /* specify target URL, and note that this URL should include a file
                name, not only a directory */
                curl_easy_setopt(curl, CURLOPT_URL, params.server);

                /* now specify which file to upload */
                curl_easy_setopt(curl, CURLOPT_READDATA, tag_file);

                /* provide the size of the upload, we specicially typecast the value
                to curl_off_t since we must be sure to use the correct data size */
                curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE,
                                (curl_off_t)file_info.st_size);

                /* Now run off and do what you've been told! */
                res = curl_easy_perform(curl);
                /* Check for errors */
                if(res != CURLE_OK)
                    fprintf(stderr, "curl_easy_perform() failed: %s\n",
                            curl_easy_strerror(res));

                /* always cleanup */
                curl_easy_cleanup(curl);
                fclose(tag_file); /* close the local file */
            }
			break;
			
		case CPOR_OP_VERIFY:
			params.tag_filename = create_tmp_name(".tag");
			params.t_filename = create_tmp_name(".t");
		#ifdef DEBUG_MODE
			fprintf(stdout, "Using the following settings:\n");
			fprintf(stdout, "\tBlock Size: %u bytes\n", params.block_size);
			fprintf(stdout, "\tNumber of Threads: %u \n", params.num_threads);
			fprintf(stdout, "\tNumber of Challenge blocks: %u \n", params.num_challenge);
		#endif		
			fprintf(stdout, "Challenging file %s...\n", params.filename); fflush(stdout);				
			fprintf(stdout, "\tCreating challenge for %s...", params.filename); fflush(stdout);
			challenge = cpor_challenge_file(params.filename, strlen(params.filename), params.t_filename, strlen(params.t_filename));
			if(!challenge) printf("No challenge\n");
			else printf("Done.\n");

			fprintf(stdout, "\tComputing proof...");fflush(stdout);
			proof = cpor_prove_file(params.filename, strlen(params.filename), params.tag_filename, strlen(params.tag_filename), challenge);
			if(!proof) printf("No proof\n");
			else printf("Done.\n");

			printf("\tVerifying proof..."); fflush(stdout);		
			if((i = cpor_verify_file(params.filename, strlen(params.filename), params.t_filename, strlen(params.t_filename), challenge, proof)) == 1) printf("Verified\n");
			else if(i == 0) printf("Cheating!\n");
			else printf("Error\n");

			if(challenge) destroy_cpor_challenge(challenge);
			if(proof) destroy_cpor_proof(proof);		
			break;

		case CPOR_OP_NOOP:
		default:
			break;
	}

    curl_global_cleanup();
	
	return 0;
	
}
