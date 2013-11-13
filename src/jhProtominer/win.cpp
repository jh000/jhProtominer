#include "win.h"


void InitializeCriticalSection(CRITICAL_SECTION *s){
    pthread_mutexattr_init(&s->attr);
    pthread_mutexattr_settype(&s->attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&s->mutex, &s->attr);
}

void EnterCriticalSection(CRITICAL_SECTION *s){
    pthread_mutex_lock(&s->mutex);
}

void LeaveCriticalSection(CRITICAL_SECTION *s){
    pthread_mutex_unlock(&s->mutex);
}

void CreateThread(LPVOID ig1, size_t ig2, LPTHREAD_START_ROUTINE func, LPVOID arg, uint32_t ig3,  LPDWORD tid){
    pthread_t thread;
    pthread_create(&thread, NULL, func, arg);
}

