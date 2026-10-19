
#include "shim.h"
#include "chromium_zlib/zlib.h"

int _curl_easy_setopt(void* curl, int option, void* parameter) {
    // printf("****** hijack test begins: \n");
    // int val = curl_easy_setopt(instance->curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
    // printf("****** hijack test ends. opt: %d, val: %d, result is: %d\n", CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0, val);
    // CURLoption opt_value = (CURLoption) option;
    // printf("option: %d, setopt parameter: %d\n", option, *(int*)parameter);
    // for integer options, we need to convert param from pointers to integers
    if (option < CURLOPTTYPE_OBJECTPOINT) {
        return (int)curl_easy_setopt(curl, (CURLoption)option, *(long*)parameter);
    }
    if (CURLOPTTYPE_OFF_T <= option && option < CURLOPTTYPE_BLOB) {
        return (int)curl_easy_setopt(curl, (CURLoption)option, *(curl_off_t*)parameter);
    }
    return (int)curl_easy_setopt(curl, (CURLoption)option, parameter);
}

int _curl_easy_getinfo_socket(void* curl, int option, uintptr_t* result) {
    curl_socket_t socket;
    CURLcode ret = curl_easy_getinfo(curl, (CURLINFO)option, &socket);
    if (ret == CURLE_OK) {
        *result = (uintptr_t)socket;
    }
    return (int)ret;
}

// Locks for a share handle, one mutex per kind of shared data. libcurl calls
// them from whatever thread runs a transfer, so they must not need the GIL.
#ifdef _WIN32
#include <windows.h>
typedef CRITICAL_SECTION share_mutex;
#define share_mutex_init(m) InitializeCriticalSection(m)
#define share_mutex_destroy(m) DeleteCriticalSection(m)
#define share_mutex_lock(m) EnterCriticalSection(m)
#define share_mutex_unlock(m) LeaveCriticalSection(m)
#else
#include <pthread.h>
typedef pthread_mutex_t share_mutex;
#define share_mutex_init(m) pthread_mutex_init(m, NULL)
#define share_mutex_destroy(m) pthread_mutex_destroy(m)
#define share_mutex_lock(m) pthread_mutex_lock(m)
#define share_mutex_unlock(m) pthread_mutex_unlock(m)
#endif

struct share_locks {
    share_mutex mutex[CURL_LOCK_DATA_LAST];
};

static void share_lock(CURL* handle, curl_lock_data data,
                       curl_lock_access access, void* userptr) {
    struct share_locks* locks = userptr;
    (void)handle;
    (void)access;
    if ((unsigned)data < CURL_LOCK_DATA_LAST) {
        share_mutex_lock(&locks->mutex[data]);
    }
}

static void share_unlock(CURL* handle, curl_lock_data data, void* userptr) {
    struct share_locks* locks = userptr;
    (void)handle;
    if ((unsigned)data < CURL_LOCK_DATA_LAST) {
        share_mutex_unlock(&locks->mutex[data]);
    }
}

void* _curl_share_locks_new(void) {
    struct share_locks* locks = malloc(sizeof(*locks));
    int i;
    if (locks) {
        for (i = 0; i < CURL_LOCK_DATA_LAST; i++) {
            share_mutex_init(&locks->mutex[i]);
        }
    }
    return locks;
}

void _curl_share_locks_free(void* ptr) {
    struct share_locks* locks = ptr;
    int i;
    if (locks) {
        for (i = 0; i < CURL_LOCK_DATA_LAST; i++) {
            share_mutex_destroy(&locks->mutex[i]);
        }
        free(locks);
    }
}

// permessage-deflate compression of outgoing WebSocket messages, done like
// Chromium's WebSocketDeflater and with Chromium's zlib, whose deflate output
// differs from canonical zlib.
struct ws_deflater {
    z_stream strm;
    int no_context_takeover;
};

void* _ws_deflater_new(int window_bits, int no_context_takeover) {
    struct ws_deflater* d = calloc(1, sizeof(*d));
    if (!d) {
        return NULL;
    }
    // zlib cannot compress raw deflate with 8 window bits; Chromium uses 9.
    if (window_bits < 9) {
        window_bits = 9;
    }
    if (deflateInit2(&d->strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -window_bits,
                     8, Z_DEFAULT_STRATEGY) != Z_OK) {
        free(d);
        return NULL;
    }
    d->no_context_takeover = no_context_takeover;
    return d;
}

static int ws_deflate_run(z_stream* strm, int flush, unsigned char** buf,
                          size_t* cap, size_t* used) {
    int ret;
    do {
        if (*used == *cap) {
            unsigned char* bigger = realloc(*buf, *cap * 2);
            if (!bigger) {
                return -1;
            }
            *buf = bigger;
            *cap *= 2;
        }
        strm->next_out = *buf + *used;
        strm->avail_out = (uInt)(*cap - *used);
        ret = deflate(strm, flush);
        if (ret == Z_STREAM_ERROR) {
            return -1;
        }
        *used = *cap - strm->avail_out;
    } while (strm->avail_out == 0 || strm->avail_in != 0);
    return 0;
}

// Compresses one message: the data with Z_NO_FLUSH, then Z_SYNC_FLUSH, and
// the trailing 00 00 FF FF removed (RFC 7692 7.2.1). An empty message is a
// single 0x00 byte and leaves the stream alone. *out is to be released with
// _ws_deflate_free_buffer(). Returns 0, or -1 on failure.
int _ws_deflate(void* deflater, const unsigned char* data, size_t len,
                unsigned char** out, size_t* out_len) {
    struct ws_deflater* d = deflater;
    size_t cap = len + len / 8 + 64, used = 0;
    unsigned char* buf = malloc(cap);
    int ret = 0;
    if (!buf) {
        return -1;
    }
    if (len == 0) {
        buf[used++] = 0;
    } else {
        while (len && ret == 0) {
            uInt chunk = len > (1u << 30) ? (1u << 30) : (uInt)len;
            d->strm.next_in = (Bytef*)data;
            d->strm.avail_in = chunk;
            ret = ws_deflate_run(&d->strm, Z_NO_FLUSH, &buf, &cap, &used);
            data += chunk;
            len -= chunk;
        }
        if (ret == 0) {
            ret = ws_deflate_run(&d->strm, Z_SYNC_FLUSH, &buf, &cap, &used);
        }
        if (ret == 0 && used >= 4) {
            used -= 4;
        } else {
            ret = -1;
        }
    }
    if (d->no_context_takeover) {
        deflateReset(&d->strm);
    }
    if (ret != 0) {
        free(buf);
        return ret;
    }
    *out = buf;
    *out_len = used;
    return 0;
}

void _ws_deflate_free_buffer(unsigned char* buffer) {
    free(buffer);
}

void _ws_deflater_free(void* deflater) {
    struct ws_deflater* d = deflater;
    if (d) {
        deflateEnd(&d->strm);
        free(d);
    }
}

int _curl_share_setopt_locks(void* share, void* locks) {
    CURLSHcode ret = curl_share_setopt(share, CURLSHOPT_LOCKFUNC, share_lock);
    if (ret == CURLSHE_OK) {
        ret = curl_share_setopt(share, CURLSHOPT_UNLOCKFUNC, share_unlock);
    }
    if (ret == CURLSHE_OK) {
        ret = curl_share_setopt(share, CURLSHOPT_USERDATA, locks);
    }
    return (int)ret;
}
