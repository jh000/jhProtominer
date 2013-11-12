#ifndef __WIN_H
#define __WIN_H

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <time.h>
#include <malloc.h>


typedef void *LPVOID;
typedef uint32_t *LPDWORD;

typedef int SOCKET;
typedef struct sockaddr_in SOCKADDR_IN;
typedef struct sockaddr SOCKADDR;
typedef fd_set FD_SET;

typedef void *WSADATA;
#define WSAStartup(a, b)
#define MAKEWORD(a, b) a

#define ADDR_ANY INADDR_ANY
#define SOCKET_ERROR -1

#define strcpy_s(dst, n, src) \
    strncpy((dst), (src), (n))

#define RtlZeroMemory(s, size)\
    memset((s), 0, (size))

#define RtlCopyMemory(dest, src, size)\
    memcpy((dest), (src), (size))

#define max(a, b) \
    ((a)>(b)?(a):(b))

#define min(a, b) \
    ((a)<(b)?(a):(b))

#define FIONBIO 0

void WSAIoctl(SOCKET socket, int ig1, uint32_t *ig2, size_t ig3, LPVOID ig4, int ig5, LPDWORD ig6, LPVOID ig7, LPVOID ig8){
    fcntl(socket, F_SETFL, O_NONBLOCK);
}
#define WSAGetLastError() errno
#define WSAEWOULDBLOCK EWOULDBLOCK

#define closesocket(fd) close(fd)

typedef struct {
    pthread_mutex_t mutex;
    pthread_mutexattr_t attr;
} CRITICAL_SECTION;

inline void InitializeCriticalSection(CRITICAL_SECTION *s){
    pthread_mutexattr_init(&s->attr);
    pthread_mutexattr_settype(&s->attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&s->mutex, &s->attr);
}

inline void EnterCriticalSection(CRITICAL_SECTION *s){
    pthread_mutex_lock(&s->mutex);
}

inline void LeaveCriticalSection(CRITICAL_SECTION *s){
    pthread_mutex_unlock(&s->mutex);
}

typedef void *(*LPTHREAD_START_ROUTINE)(void *);

inline void CreateThread(LPVOID ig1, size_t ig2, LPTHREAD_START_ROUTINE func, LPVOID arg, uint32_t ig3,  LPDWORD tid){
    pthread_t thread;
    pthread_create(&thread, NULL, func, arg);
}

#define __declspec(x) __##x

#define Sleep sleep

#define __debugbreak() raise(SIGTRAP)

#define GetTickCount() (uint32) time(NULL)

#define _strdup strdup

typedef struct {
    int dwNumberOfProcessors;
} SYSTEM_INFO;

#define GetSystemInfo(ps) \
    (ps)->dwNumberOfProcessors = sysconf(_SC_NPROCESSORS_ONLN)

#define GetCurrentProcess() getpid()

#define BELOW_NORMAL_PRIORITY_CLASS 15

#define SetPriorityClass(pid, priority) \
    nice(priority)


#endif
