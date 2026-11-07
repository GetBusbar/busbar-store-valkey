// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
// Native OS identity only. No database protocol, credentials, or mutation.
#define _GNU_SOURCE
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 3 || strcmp(argv[1], "--peer-pid")) return 1;
    struct sockaddr_un address = {0};
    address.sun_family = AF_UNIX;
    size_t len = strlen(argv[2]);
    if (!len || len >= sizeof(address.sun_path)) return 1;
    memcpy(address.sun_path, argv[2], len + 1);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return 1;
    if (connect(fd, (struct sockaddr *)&address, sizeof(address))) { close(fd); return 1; }
    pid_t pid = 0;
#if defined(__APPLE__)
    socklen_t size = sizeof(pid);
    if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &size) || size != sizeof(pid)) { close(fd); return 1; }
#elif defined(__linux__)
    struct ucred peer;
    socklen_t size = sizeof(peer);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &size) || size != sizeof(peer)) { close(fd); return 1; }
    pid = peer.pid;
#else
    close(fd); return 1;
#endif
    close(fd);
    if (pid <= 0) return 1;
    printf("%ld\n", (long)pid);
    return 0;
}
