/*
 * sockblock.c — network-isolation shim for the honest "jail" sandbox backend.
 * Compiled with gcc -shared -fPIC. LD_PRELOADed into sandboxed processes so
 * every socket/connect attempt fails with ENONET. Requires no privileges,
 * works where docker/bwrap/firejail are unavailable.
 *
 * NOTE: socketpair() is deliberately NOT overridden — glibc posix_spawn()
 * uses socketpair() internally to report exec errors; blocking it makes
 * every /bin/sh spawn fail with EAGAIN. socket() is blocked, so no real
 * network socket can be created.
 *
 * Build (done automatically by sandbox_runner.py on first use):
 *   gcc -shared -fPIC -O2 -o sockblock.so sockblock.c
 */
#define _GNU_SOURCE
#include <errno.h>
#include <sys/socket.h>
#include <stdarg.h>

/* Block socket creation entirely (covers AF_INET/AF_INET6/AF_UNIX). */
int socket(int domain, int type, int protocol)
{
    (void)domain; (void)type; (void)protocol;
    errno = ENONET;
    return -1;
}

/* Belt-and-braces: also neuter connect() on any fd that slipped through. */
int connect(int fd, const struct sockaddr *addr, socklen_t len)
{
    (void)fd; (void)addr; (void)len;
    errno = ENONET;
    return -1;
}