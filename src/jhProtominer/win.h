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

#define WSAIoctl(socket, ig1, ig2, ig3, ig4, ig5, ig6, ig7, ig8) \
fcntl(socket, F_SETFL, O_NONBLOCK)

#define WSAGetLastError() errno
#define WSAEWOULDBLOCK EWOULDBLOCK

#define closesocket(fd) close(fd)

typedef struct {
    pthread_mutex_t mutex;
    pthread_mutexattr_t attr;
} CRITICAL_SECTION;

void InitializeCriticalSection(CRITICAL_SECTION *s);

void EnterCriticalSection(CRITICAL_SECTION *s);

void LeaveCriticalSection(CRITICAL_SECTION *s);

typedef void *(*LPTHREAD_START_ROUTINE)(void *);

void CreateThread(LPVOID ig1, size_t ig2, LPTHREAD_START_ROUTINE func, LPVOID arg, uint32_t ig3,  LPDWORD tid);

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
