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

static int params_remaining_size;
static inline char separator()
{
#ifdef _WIN32
    return '\\';
#else
    return '/';
#endif
}
char *str_concat_many(int count, ...)
{
    int length = 1;

    va_list args;
    va_start(args, count);
    for (int i = 0; i < count; i++) {
        char *item = va_arg(args, char *);
        length += strlen(item);
    }
    va_end(args);

    char *combined = calloc(length, sizeof(char));
    if (!combined) {
        return NULL;
    }

    va_start(args, count);
    for (int i = 0; i < count; i++) {
        char *item = va_arg(args, char *);
        strcat(combined, item);
    }
    va_end(args);

    return combined;
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

#ifdef _WIN32
static char *EncodingConvert(const char* strIn, int sourceCodepage, int targetCodepage)
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

static size_t read_file_callback(void *ptr, size_t size, size_t nmemb, void *stream)
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

static size_t read_params_callback(void *ptr, size_t size, size_t nmemb, void *data)
{
    size_t retcode = 0;

	CPOR_params *params = (CPOR_params *)data;

	// we have already finished off all the data
    if (params_remaining_size == 0)
        return retcode;

	// set return code as the smaller of max allowed data and remaining data
    retcode =  (size * nmemb >= params_remaining_size) ? params_remaining_size : size * nmemb;

	// adjust left amount
    params_remaining_size -= retcode;
    memcpy(ptr, data, retcode);
    params_remaining_size += retcode;

    return retcode;
}

CPOR_params *cpor_new_params()
{
	CPOR_params *myparams = (CPOR_params *)malloc(sizeof(CPOR_params));
	CPOR_challenge *challenge = NULL;
	CPOR_proof *proof = NULL;
	int ret = 0;

	myparams->lambda = 80;						/* The security parameter lambda */

	myparams->prf_key_size = 20;				/* Size (in bytes) of an HMAC-SHA1 */
	myparams->enc_key_size = 32;				/* Size (in bytes) of the user's AES encryption key */
	myparams->mac_key_size = 20;				/* Size (in bytes) of the user's MAC key */

	myparams->block_size = 4096;				/* Message block size in bytes */				
	myparams->num_threads = 4;
	myparams->num_challenge = myparams->lambda;

	/* The size (in bits) of the prime that creates the field Z_p */
    myparams->Zp_bits = myparams->lambda;
	/* The message sector size 1 byte smaller than the size of Zp so that it 
	 * is guaranteed to be an element of the group Zp */
	myparams->sector_size = ((myparams->Zp_bits / 8) - 1);
	/* Number of sectors per block */
	myparams->num_sectors = ( (myparams->block_size / myparams->sector_size) + ((myparams->block_size % myparams->sector_size) ? 1 : 0) );

	myparams->key_data = NULL;
	myparams->t_data = NULL;
	myparams->tag_data = NULL;

	return myparams;
}

int cpor_tag(char *filename, char *key_filename, char *t_filename, char *tag_filename)
{
	CPOR_params *myparams = cpor_new_params();
	myparams->filename = filename;

	#ifdef DEBUG_MODE
		fprintf(stdout, "Using the following settings:\n");
		fprintf(stdout, "\tLambda: %u\n", myparams->lambda);
		fprintf(stdout, "\tPRF Key Size: %u bytes\n", myparams->prf_key_size);
		fprintf(stdout, "\tENC Key Size: %u bytes\n", myparams->enc_key_size);
		fprintf(stdout, "\tMAC Key Size: %u bytes\n", myparams->mac_key_size);
	#endif
		fprintf(stdout, "Generating keys...");
		if(!cpor_create_new_keys(myparams, key_filename)) printf("Couldn't create keys\n");
		else printf("Done\n");

	#ifdef DEBUG_MODE
		fprintf(stdout, "Using the following settings:\n");
		fprintf(stdout, "\tBlock Size: %u bytes\n", myparams->block_size);
		fprintf(stdout, "\tNumber of Threads: %u \n", myparams->num_threads);
	#endif
		fprintf(stdout, "Tagging %s...", myparams->filename); fflush(stdout);
	#ifdef DEBUG_MODE
		struct timeval tv1, tv2;
		gettimeofday(&tv1, NULL);
	#endif
		if(!cpor_tag_file(myparams, key_filename, t_filename, tag_filename)) printf("No tag\n");
		else printf("Done\n");
	#ifdef DEBUG_MODE
		gettimeofday(&tv2, NULL);
		printf("%lf\n", (double)( (double)(double)(((double)tv2.tv_sec) + (double)((double)tv2.tv_usec/1000000)) - (double)((double)((double)tv1.tv_sec) + (double)((double)tv1.tv_usec/1000000)) ) );
	#endif

	free(myparams); myparams = NULL;
}

/*
ret: 0 - Cheating, 1 - Verified, -1 - error.
*/
int cpor_verify(char *filename, char *key_data, char *t_data, char *tag_data)
{
	CPOR_params *myparams = cpor_new_params();
	CPOR_challenge *challenge = NULL;
	CPOR_proof *proof = NULL;
	int ret = 0;

	myparams->filename = filename;
	myparams->key_data = key_data;
	myparams->t_data = t_data;
	myparams->tag_data = tag_data;

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

	free(myparams); myparams = NULL;

	return ret;
}

// typedef enum {
//     CHALLENGE_DATA_KEY = 0,
//     CHALLENGE_DATA_T = 1,
//     CHALLENGE_DATA_TAG = 2
// } challenge_data_type;

// curl_easy_setopt( curl, CURLOPT_WRITEDATA, (void *)&wr_error ); 
// curl_easy_setopt( curl, CURLOPT_WRITEFUNCTION, write_data );

void send_data(char *data, size_t len, char *url)
{
	CURL *curl;
    CURLcode res;

    /* get a curl handle */
    curl = curl_easy_init();
    if(curl) {
        /* we want to use our own read function */
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_params_callback);

        /* enable uploading */
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

        /* HTTP PUT */
        curl_easy_setopt(curl, CURLOPT_PUT, 1L);

        /* specify target URL */
        curl_easy_setopt(curl, CURLOPT_URL, url);

        curl_easy_setopt(curl, CURLOPT_READDATA, data);

		 /* and give the size of the upload (optional) */
        curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, len);

        /* Now run off and do what you've been told! */
        res = curl_easy_perform(curl);
        /* Check for errors */
        if(res != CURLE_OK)
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                    curl_easy_strerror(res));

        /* always cleanup */
        curl_easy_cleanup(curl);
    }
}

void send_file(char *filename, char *url)
{
	CURL *curl;
    CURLcode res;
    FILE *file;
    struct stat file_info;

    /* get the file size of the local file */
    stat(filename, &file_info);

    /* could also be made with fdopen() from the previous descriptor */
    file = fopen(filename, "rb");

    /* get a curl handle */
    curl = curl_easy_init();
    if(curl) {
        /* we want to use our own read function */
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_file_callback);

        /* enable uploading */
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

        /* HTTP PUT */
        curl_easy_setopt(curl, CURLOPT_PUT, 1L);

        /* specify target URL */
        curl_easy_setopt(curl, CURLOPT_URL, url);

        /* now specify which file to upload */
        curl_easy_setopt(curl, CURLOPT_READDATA, file);

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
    }
    fclose(file); /* close the local file */
}

void cpor_send(CPOR_params *params, char *key_filename, char *t_filename, char *tag_filename)
{
	// char *http_server = "http://192.168.50.206:9999";
	char *http_server = "http://localhost:9999";
	char *params_path = str_concat_many(2, http_server, "/audit/cpor_params");
	char *key_path = str_concat_many(2, http_server, "/audit/cpor_key");
	char *t_path = str_concat_many(2, http_server, "/audit/cpor_t");
	char *tag_path = str_concat_many(2, http_server, "/audit/cpor_tag");
	
	params_remaining_size = sizeof(CPOR_params);
	send_data(params, params_remaining_size, params_path);

	send_file(key_filename, key_path);
	send_file(t_filename, t_path);
	send_file(tag_filename, tag_path);
}

void tag_test()
{
	#if defined __APPLE__
		char *filename = "/Users/dingyi/Downloads/10m.data";
	#elif defined __linux__
		char *filename = "/media/psf/Home/Downloads/10m.data";
	#elif defined _WIN32
		char *filename = EncodingConvert("Y:/Downloads/10m.data", CP_UTF8, CP_ACP);
	#endif 

	char *key_filename = create_tmp_name(".key");
	char *t_filename = create_tmp_name(".t");
	char *tag_filename = create_tmp_name(".tag");

	cpor_tag(filename, key_filename, t_filename, tag_filename);

	CPOR_params *params = cpor_new_params();
	cpor_send(params, key_filename, t_filename, tag_filename);
}

void verify_test()
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

	int success = cpor_verify(filename, key_data, t_data, tag_data);
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

void main()
{
    curl_global_init(CURL_GLOBAL_ALL);

	tag_test();
	verify_test();

    curl_global_cleanup();
}
