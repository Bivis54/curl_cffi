
#include "shim.h"

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
