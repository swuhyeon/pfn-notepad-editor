#define _CRT_SECURE_NO_WARNINGS

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#pragma comment(lib, "Ws2_32.lib")

static void trim_newline(char *s) {
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r')) {
        s[--len] = '\0';
    }
}

static int recv_timeout(SOCKET s, int timeout_ms) {
    char buf[4096];
    int saw_any = 0;

    for (;;) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(s, &rfds);

        struct timeval tv;
        tv.tv_sec  = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        int ret = select(0, &rfds, NULL, NULL, &tv);
        if (ret == SOCKET_ERROR) {
            printf("[!] select() error: %d\n", WSAGetLastError());
            return -1;
        }
        if (ret == 0) {
            break;
        }

        int n = recv(s, buf, sizeof(buf) - 1, 0);
        if (n == 0) {
            if (!saw_any)
                printf("[!] server closed the connection\n");
            else
                printf("\n[!] server closed the connection\n");
            return 1;
        }
        if (n < 0) {
            printf("[!] recv() error: %d\n", WSAGetLastError());
            return -1;
        }

        saw_any = 1;
        buf[n] = '\0';
        fputs(buf, stdout);
        fflush(stdout);
    }

    return 0;
}

int main(void) {
    char host_buf[256] = {0};
    char port_buf[32]  = {0};
    int  port = 0;

    while (host_buf[0] == '\0') {
        printf("Server IP: ");
        fflush(stdout);

        if (!fgets(host_buf, sizeof(host_buf), stdin)) {
            printf("\n[!] input error\n");
            return 1;
        }
        trim_newline(host_buf);

        char *p = host_buf;
        while (*p && isspace((unsigned char)*p)) p++;
        if (*p == '\0') {
            host_buf[0] = '\0';
            printf("[!] host is required.\n");
        }
    }

    while (port == 0) {
        printf("Port: ");
        fflush(stdout);

        if (!fgets(port_buf, sizeof(port_buf), stdin)) {
            printf("\n[!] input error\n");
            return 1;
        }
        trim_newline(port_buf);

        if (port_buf[0] == '\0') {
            printf("[!] port is required.\n");
            continue;
        }

        port = atoi(port_buf);
        if (port <= 0 || port > 65535) {
            printf("[!] invalid port: %s\n", port_buf);
            port = 0;
        }
    }

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("[!] WSAStartup failed\n");
        return 1;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        printf("[!] socket() failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((unsigned short)port);

    if (inet_pton(AF_INET, host_buf, &sa.sin_addr) <= 0) {
        printf("[!] invalid ip: %s\n", host_buf);
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    printf("[*] connecting to %s:%d ...\n", host_buf, port);

    if (connect(sock, (struct sockaddr*)&sa, sizeof(sa)) == SOCKET_ERROR) {
        printf("[!] connect() failed: %d\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    printf("[+] connected.\n");
    recv_timeout(sock, 300);

    char line[1024];

    for (;;) {
        printf("pfn> ");
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin)) {
            break;
        }

        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';

        if (len == 0) {
            continue;
        }

        if (len + 1 < sizeof(line)) {
            line[len]     = '\n';
            line[len + 1] = '\0';
            len++;
        }

        int n = send(sock, line, (int)len, 0);
        if (n == SOCKET_ERROR) {
            printf("[!] send() failed: %d\n", WSAGetLastError());
            break;
        }

        int rc = recv_timeout(sock, 5000);

        if (rc == 1) {
            break;
        } else if (rc < 0) {
            break;
        }

        if (line[0] == 'q') {
            break;
        }
    }

    closesocket(sock);
    WSACleanup();
    return 0;
}