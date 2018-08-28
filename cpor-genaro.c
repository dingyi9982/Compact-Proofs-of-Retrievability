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
#include "headers.h"
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
int cpor_verify(char *filename, char *key_data, char *t_data, char *tag_data,
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
	myparams->key_data = key_data;
	myparams->t_data = t_data;
	myparams->tag_data = tag_data;

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
	if(!challenge) {
		printf("No challenge\n");
		return -1;
	}
	else printf("Done.\n");

	printf("\tComputing proof...");
	proof = cpor_prove_file(myparams, challenge);
	if(!proof) {
		printf("No proof\n");
		return -1;
	}
	else printf("Done.\n");

    printf("\tVerifying proof...");
	ret = cpor_verify_file(myparams, challenge, proof);
    printf("Done.\n");

    if(challenge) destroy_cpor_challenge(challenge);
	if(proof) destroy_cpor_proof(myparams, proof);

	free(myparams);

	return ret;
}
#ifdef _WIN32
char *EncodingConvert(const char* strIn, int sourceCodepage, int targetCodepage)
{
	int unicodeLen = MultiByteToWideChar(sourceCodepage, 0, strIn, -1, NULL, 0);
	wchar_t* pUnicode;
	pUnicode = (wchar_t *)malloc((unicodeLen + 1) * sizeof(wchar_t));
	memset(pUnicode, 0, (unicodeLen + 1) * sizeof(wchar_t));
	MultiByteToWideChar(sourceCodepage, 0, strIn, -1, (LPWSTR)pUnicode, unicodeLen);
	char * pTargetData = NULL;
	int targetLen = WideCharToMultiByte(targetCodepage, 0, (LPWSTR)pUnicode, -1, pTargetData, 0, NULL, NULL);
	pTargetData = (BYTE *)malloc((targetLen + 1) * sizeof(BYTE));
	memset(pTargetData, 0, targetLen + 1);
	WideCharToMultiByte(targetCodepage, 0, (LPWSTR)pUnicode, -1, pTargetData, targetLen, NULL, NULL);
	free(pUnicode);
	return pTargetData;
}
#endif

void main()
{
	char *key_filename = create_tmp_name(".key");
	char *t_filename = create_tmp_name(".t");
	char *tag_filename = create_tmp_name(".tag");

	char *key_data, *t_data, *tag_data;
	FILE *key_file = fopen(key_filename, "rb");
	FILE *t_file = fopen(t_filename, "rb");
	FILE *tag_file = fopen(tag_filename, "rb");

	struct stat key_stat, t_stat, tag_stat;
	stat(key_filename, &key_stat);
	stat(t_filename, &t_stat);
	stat(tag_filename, &tag_stat);

	key_data = (char *)malloc(key_stat.st_size);
	t_data = (char *)malloc(t_stat.st_size);
	tag_data = (char *)malloc(tag_stat.st_size);

	fread(key_data, key_stat.st_size, 1, key_file);
	fread(t_data, t_stat.st_size, 1, t_file);
	fread(tag_data, tag_stat.st_size, 1, tag_file);

	fclose(key_file);
	fclose(t_file);
	fclose(tag_file);

#if defined __APPLE__
	char *filename = "/Users/dingyi/10兆.data";
#elif defined __linux__
	char *filename = "/media/psf/Home/10兆.data";
#elif defined _WIN32
	char *filename = EncodingConvert("Y:/10兆.data", CP_UTF8, CP_ACP);
#endif 

	int success = cpor_verify(filename, key_data, t_data, tag_data, 80, 4096);
	if(success == 1) {
		printf("Verified!\n");
	} else if(success == 0) {
		printf("Cheating!\n");
	} else {
		printf("Error!\n");
	}

#if defined _WIN32
    free(filename);
#endif
	free(key_data);
	free(t_data);
	free(tag_data);
}
