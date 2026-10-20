#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#define CURL_STATICLIB
#include "curl/curl.h"

int _curl_easy_setopt(void* curl, int option, void* param);
int _curl_easy_getinfo_socket(void* curl, int option, uintptr_t* result);
void* _curl_share_locks_new(void);
void _curl_share_locks_free(void* locks);
int _curl_share_setopt_locks(void* share, void* locks);
void* _ws_deflater_new(int window_bits, int no_context_takeover);
int _ws_deflate(void* deflater, const unsigned char* data, size_t len,
                unsigned char** out, size_t* out_len);
void _ws_deflate_free_buffer(unsigned char* buffer);
void _ws_deflater_free(void* deflater);
