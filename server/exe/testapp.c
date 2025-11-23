#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strsafe.h>
#include <sys/sioctl.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ctype.h>
#include <stdint.h>
#include <inttypes.h>
#include <tlhelp32.h>
#include <wchar.h>
#include <stdarg.h>

#pragma comment(lib, "Ws2_32.lib")

#define u32     uint32_t
#define BUFSIZE 65535

static char OutputBuffer[100];

BOOLEAN ManageDriver(_In_ LPCTSTR DriverName, _In_ LPCTSTR ServiceName, _In_ USHORT Function);
BOOLEAN SetupDriverName(_Inout_updates_bytes_all_(BufferLength) PCHAR DriverLocation, _In_ ULONG BufferLength);

static HANDLE           g_hDevice = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_IoctlLock;

static volatile LONG g_shutdown = 0;
static SOCKET        g_listen_sock = INVALID_SOCKET;

typedef unsigned __int64 QWORD;

typedef struct PFN_CTX {
    char* pVa;
    QWORD  notepadPfn;
    char* pHit;
    size_t hit_len_chars;
    QWORD  oldPfn;
    BOOL   exitFlag;
} PFN_CTX;

static void dump(const void* mem, size_t length)
{
    const unsigned char* data = (const unsigned char*)mem;
    size_t i, j;
    for (i = 0; i < length; i += 16) {
        printf("%016p  ", (const char*)mem + i);
        for (j = 0; j < 16; ++j) {
            if (i + j < length) printf("%02x ", data[i + j]);
            else                printf("   ");
        }
        printf(" ");
        for (j = 0; j < 16; ++j) {
            if (i + j < length) {
                unsigned char ch = data[i + j];
                printf("%c", isprint(ch) ? ch : '.');
            }
            else {
                printf(" ");
            }
        }
        printf("\n");
    }
}

static char* MemScan(char* pMem, int nMemSize, const char* pData, int nDataSize)
{
    for (int i = 0; i <= nMemSize - nDataSize; i++) {
        if (0 == memcmp(pMem + i, pData, nDataSize)) {
            printf("offset : %d, 메모리 스캔 완료\n", i);
            return (pMem + i);
        }
    }
    return NULL;
}

static int send_text(SOCKET s, const char* text)
{
    size_t len = strlen(text);
    return send(s, text, (int)len, 0);
}

static int send_printf(SOCKET s, const char* fmt, ...)
{
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0) return n;
    if (n > (int)sizeof(buf)) n = (int)sizeof(buf);
    return send(s, buf, n, 0);
}

static void send_usage(SOCKET cs)
{
    send_text(cs,
        "Available commands:\n"
        "\n"
        "  f <exe> <pattern>\n"
        "      - Search process memory for a UTF-16 string,\n"
        "        automatically find pid/va, and set notepadPfn.\n"
        "        e.g. f notepad.exe \"pattern\"\n"
        "\n"
        "  1   - Allocate a 4KB page (pVa) in the server process and zero-initialize it.\n"
        "  2   - Query oldPfn (or PA) using the current process pid and pVa.\n"
        "  3   - Apply notepadPfn >> 12 via IOCTL_SET_PFN (PFN swap).\n"
        "\n"
        "  4 <pattern>\n"
        "      - Search for a string in the pVa page (UTF-16LE) and store pHit.\n"
        "        e.g. 4 \"pattern\"\n"
        "\n"
        "  5 <new text>\n"
        "      - Overwrite the last matched location (pHit) with a new UTF-16LE string.\n"
        "        e.g. 5 \"new text\"\n"
        "\n"
        "  6   - Restore the PFN using oldPfn >> 12.\n"
        "  d   - Hexdump the 4KB page containing pVa to the server console.\n"
        "  h   - Show this help.\n"
        "  q   - Terminate the session (and shut down the server).\n"
        "\n"
    );
}

static BOOL IoctlSetPid_DangerShared(u32 pid)
{
    DWORD br = 0;
    BOOL ok = DeviceIoControl(
        g_hDevice,
        (DWORD)IOCTL_SET_PID,
        &pid,
        (DWORD)sizeof(pid),
        &OutputBuffer,
        sizeof(OutputBuffer),
        &br,
        NULL
    );
    if (!ok) printf("Error in DeviceIoControl(IOCTL_SET_PID) : %d\n", GetLastError());
    else     printf("    OutBuffer (%lu): %s\n", br, OutputBuffer);
    return ok;
}

static BOOL IoctlSetVaGetPfn_DangerShared(QWORD va, QWORD* outVal)
{
    DWORD br = 0;
    QWORD tmp = 0ULL;
    BOOL ok = DeviceIoControl(
        g_hDevice,
        (DWORD)IOCTL_SET_VA,
        &va,
        (DWORD)sizeof(va),
        &tmp,
        sizeof(tmp),
        &br,
        NULL
    );
    if (!ok) printf("Error in DeviceIoControl(IOCTL_SET_VA) : %d\n", GetLastError());
    else     printf("    OutBuffer (%lu), pfn/pa : 0x%llx\n", br, tmp);
    if (ok && outVal) *outVal = tmp;
    return ok;
}

static BOOL IoctlSetPfn_DangerShared(QWORD pfn)
{
    DWORD br = 0;
    BOOL ok = DeviceIoControl(
        g_hDevice,
        (DWORD)IOCTL_SET_PFN,
        &pfn,
        (DWORD)sizeof(pfn),
        &OutputBuffer,
        sizeof(OutputBuffer),
        &br,
        NULL
    );
    if (!ok) printf("Error in DeviceIoControl(IOCTL_SET_PFN) : %d\n", GetLastError());
    else     printf("    OutBuffer (%lu)\n", br);
    return ok;
}

static BOOL Atomic_GetPfn(u32 pid, QWORD va, QWORD* outVal)
{
    BOOL ok = FALSE;
    EnterCriticalSection(&g_IoctlLock);
    do {
        if (!IoctlSetPid_DangerShared(pid))    break;
        if (!IoctlSetVaGetPfn_DangerShared(va, outVal)) break;
        ok = TRUE;
    } while (0);
    LeaveCriticalSection(&g_IoctlLock);
    return ok;
}

static BOOL Atomic_SetPfn(QWORD pfn)
{
    BOOL ok = FALSE;
    EnterCriticalSection(&g_IoctlLock);
    ok = IoctlSetPfn_DangerShared(pfn);
    LeaveCriticalSection(&g_IoctlLock);
    return ok;
}

static DWORD FindProcessIdByName(const wchar_t* exe_name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        wprintf(L"[!] CreateToolhelp32Snapshot failed: %lu\n", GetLastError());
        return 0;
    }

    PROCESSENTRY32W pe = { 0 };
    pe.dwSize = sizeof(pe);

    if (!Process32FirstW(snap, &pe)) {
        wprintf(L"[!] Process32First failed: %lu\n", GetLastError());
        CloseHandle(snap);
        return 0;
    }

    DWORD pid = 0;
    do {
        if (_wcsicmp(pe.szExeFile, exe_name) == 0) {
            pid = pe.th32ProcessID;
            break;
        }
    } while (Process32NextW(snap, &pe));

    CloseHandle(snap);
    return pid;
}

static BYTE* FindWideStringInBuffer(
    BYTE* buf,
    SIZE_T bufBytes,
    const wchar_t* needle,
    SIZE_T nlen
)
{
    if (!buf || !needle || nlen == 0) return NULL;
    if (bufBytes < nlen * sizeof(wchar_t)) return NULL;

    const wchar_t* wbuf = (const wchar_t*)buf;
    SIZE_T maxIndex = bufBytes / sizeof(wchar_t);
    if (maxIndex < nlen) return NULL;

    SIZE_T last = maxIndex - nlen;

    for (SIZE_T i = 0; i <= last; ++i) {
        if (wbuf[i] == needle[0]) {
            if (wcsncmp(&wbuf[i], needle, nlen) == 0) {
                return (BYTE*)&wbuf[i];
            }
        }
    }
    return NULL;
}

static BOOL FindPidAndVaForPattern(
    const wchar_t* procName,
    const wchar_t* pattern,
    DWORD* outPid,
    QWORD* outVa
)
{
    if (!procName || !pattern || !outPid || !outVa) return FALSE;

    SIZE_T patLen = wcslen(pattern);
    if (patLen == 0) {
        wprintf(L"[!] empty pattern\n");
        return FALSE;
    }

    DWORD pid = FindProcessIdByName(procName);
    if (!pid) {
        wprintf(L"[!] process \"%s\" not found\n", procName);
        return FALSE;
    }

    wprintf(L"[+] PID = %u (0x%x)\n", pid, pid);

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE, pid);
    if (!hProc) {
        wprintf(L"[!] OpenProcess failed: %lu\n", GetLastError());
        return FALSE;
    }

    SYSTEM_INFO si;
    GetSystemInfo(&si);

    BYTE* addr = (BYTE*)si.lpMinimumApplicationAddress;
    BYTE* max = (BYTE*)si.lpMaximumApplicationAddress;

    wprintf(L"[+] scanning memory from %p to %p ...\n", addr, max);

    BYTE* foundRemote = NULL;

    while (addr < max) {
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T res = VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi));
        if (res == 0)
            break;

        BOOL good =
            (mbi.State == MEM_COMMIT) &&
            !(mbi.Protect & PAGE_GUARD) &&
            !(mbi.Protect & PAGE_NOACCESS) &&
            (mbi.Protect & (PAGE_READWRITE |
                PAGE_WRITECOPY |
                PAGE_EXECUTE_READWRITE |
                PAGE_EXECUTE_WRITECOPY));

        if (good) {
            SIZE_T region = mbi.RegionSize;
            BYTE* buffer = (BYTE*)malloc(region);
            if (buffer) {
                SIZE_T bytesRead = 0;
                if (ReadProcessMemory(
                    hProc,
                    mbi.BaseAddress,
                    buffer,
                    region,
                    &bytesRead
                ))
                {
                    BYTE* hit = FindWideStringInBuffer(
                        buffer,
                        bytesRead,
                        pattern,
                        patLen
                    );
                    if (hit) {
                        SIZE_T offset = (SIZE_T)(hit - buffer);
                        foundRemote = (BYTE*)mbi.BaseAddress + offset;
                        wprintf(L"[+] found at remote address = %p\n", foundRemote);
                        free(buffer);
                        break;
                    }
                }
                free(buffer);
            }
        }

        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
    }

    CloseHandle(hProc);

    if (!foundRemote) {
        wprintf(L"[!] pattern not found in process memory.\n");
        return FALSE;
    }

    *outPid = pid;
    *outVa = (QWORD)(uintptr_t)foundRemote;
    wprintf(L"[+] pid=%u va=0x%p\n", pid, foundRemote);
    return TRUE;
}

static BOOL handle_command_line(PFN_CTX* C, SOCKET cs, const char* lineRaw)
{
    char line[1024];
    strncpy(line, lineRaw, sizeof(line) - 1);
    line[sizeof(line) - 1] = 0;

    size_t L = strlen(line);
    while (L && (line[L - 1] == '\r' || line[L - 1] == '\n')) line[--L] = 0;
    if (L == 0) return TRUE;

    char* save = NULL;
    char* t = strtok_s(line, " \t", &save);
    if (!t) return TRUE;
    char cmd = t[0];

    switch (cmd) {
    case 'f': {
        char* tExe = strtok_s(NULL, " \t", &save);
        char* tRest = strtok_s(NULL, "", &save);

        if (!tExe || !tRest) {
            send_text(cs, "usage: f <exe> <pattern>\n");
            break;
        }

        const char* exeA = tExe;
        const char* patA = tRest;

        while (*patA == ' ' || *patA == '\t') patA++;
        if (*patA == '\0') {
            send_text(cs, "usage: f <exe> <pattern>\n");
            break;
        }

        char patBuf[512];
        strncpy(patBuf, patA, sizeof(patBuf) - 1);
        patBuf[sizeof(patBuf) - 1] = '\0';

        size_t plen = strlen(patBuf);
        if (plen >= 2 && patBuf[0] == '"' && patBuf[plen - 1] == '"') {
            patBuf[plen - 1] = '\0';
            memmove(patBuf, patBuf + 1, plen - 1);
        }

        wchar_t wExe[260];
        wchar_t wPat[256];

        MultiByteToWideChar(CP_ACP, 0, exeA, -1, wExe, (int)_countof(wExe));
        MultiByteToWideChar(CP_ACP, 0, patBuf, -1, wPat, (int)_countof(wPat));

        DWORD pid = 0;
        QWORD va = 0;

        if (!FindPidAndVaForPattern(wExe, wPat, &pid, &va)) {
            send_text(cs, "auto pid/va search failed\n");
            break;
        }

        QWORD val = 0ULL;
        if (!Atomic_GetPfn((u32)pid, va, &val)) {
            send_text(cs, "IOCTL (PID/VA->PFN) failed\n");
            break;
        }

        C->notepadPfn = val;
        send_printf(cs,
            "auto OK: pid=%u va=0x%llx val=0x%llx (note: PFN=val>>12 if PA)\n",
            pid, (unsigned long long)va, (unsigned long long)val);
        break;
    }

    case '1': {
        if (!C->pVa) {
            C->pVa = (char*)malloc(4096);
            if (!C->pVa) {
                send_text(cs, "malloc failed\n");
                break;
            }
            memset(C->pVa, 0, 4096);
        }
        send_printf(cs, "pVa=%p\n", C->pVa);
        break;
    }

    case '2': {
        if (!C->pVa) {
            send_text(cs, "pVa is NULL. run '1' first.\n");
            break;
        }
        u32   pid = GetCurrentProcessId();
        QWORD va = (QWORD)(uintptr_t)C->pVa;
        QWORD val = 0ULL;
        if (!Atomic_GetPfn(pid, va, &val)) {
            send_text(cs, "IOCTL failed\n");
            break;
        }
        C->oldPfn = val;
        send_printf(cs,
            "oldVal=0x%llx (note: PFN=val>>12 if PA)\n",
            val
        );
        break;
    }

    case '3': {
        if (!C->pVa) {
            send_text(cs, "pVa is NULL. run '1' first.\n");
            break;
        }
        if (C->notepadPfn == 0) {
            send_text(cs, "notepadPfn is zero. run 'f' first.\n");
            break;
        }

        u32   pid = GetCurrentProcessId();
        QWORD va = (QWORD)(uintptr_t)C->pVa;
        QWORD dummy = 0;
        if (!Atomic_GetPfn(pid, va, &dummy)) {
            send_text(cs, "IOCTL (PID/VA->PFN) failed before swap\n");
            break;
        }

        QWORD newPfn = (C->notepadPfn >> 12);
        if (!Atomic_SetPfn(newPfn)) {
            send_text(cs, "SET_PFN failed\n");
            break;
        }
        send_printf(cs, "SET_PFN ok: 0x%llx\n", newPfn);
        break;
    }

    case '4': {
        if (!C->pVa) {
            send_text(cs, "pVa is NULL. run '1' first.\n");
            break;
        }

        char* tPat = strtok_s(NULL, "", &save);
        if (!tPat) {
            send_text(cs, "usage: 4 <pattern>\n");
            break;
        }

        while (*tPat == ' ' || *tPat == '\t') tPat++;
        if (*tPat == '\0') {
            send_text(cs, "usage: 4 <pattern>\n");
            break;
        }

        size_t plen = strlen(tPat);
        if (plen >= 2 && tPat[0] == '"' && tPat[plen - 1] == '"') {
            tPat[plen - 1] = '\0';
            tPat++;
            plen -= 2;
        }
        else {
            plen = strlen(tPat);
        }
        if (plen == 0) {
            send_text(cs, "empty pattern\n");
            break;
        }
        if (plen > 256) {
            send_text(cs, "pattern too long (max 256)\n");
            break;
        }

        unsigned char wpat[512];
        for (size_t i = 0; i < plen; ++i) {
            wpat[2 * i] = (unsigned char)tPat[i];
            wpat[2 * i + 1] = 0x00;
        }
        int wlen = (int)(2 * plen);

        char* page_base = (char*)((uintptr_t)C->pVa & ~(uintptr_t)0xFFF);

        C->pHit = MemScan(page_base, 4096, (const char*)wpat, wlen);
        if (C->pHit) {
            C->hit_len_chars = plen;
            long long offset = (long long)(C->pHit - page_base);
            send_printf(cs,
                "pattern \"%s\" found at offset %lld (from page base)\n",
                tPat,
                offset
            );
        }
        else {
            C->hit_len_chars = 0;
            send_printf(cs, "pattern \"%s\" not found\n", tPat);
        }
        break;
    }

    case '5': {
        if (!C->pHit || C->hit_len_chars == 0) {
            send_text(cs, "run '4' first (no pattern hit).\n");
            break;
        }

        char* tNew = strtok_s(NULL, "", &save);
        if (!tNew) {
            send_text(cs, "usage: 5 <new_text>\n");
            break;
        }

        while (*tNew == ' ' || *tNew == '\t') tNew++;
        if (*tNew == '\0') {
            send_text(cs, "usage: 5 <new_text>\n");
            break;
        }

        size_t nlen = strlen(tNew);
        if (nlen >= 2 && tNew[0] == '"' && tNew[nlen - 1] == '"') {
            tNew[nlen - 1] = '\0';
            tNew++;
            nlen -= 2;
        }
        else {
            nlen = strlen(tNew);
        }
        if (nlen == 0) {
            send_text(cs, "empty replacement\n");
            break;
        }

        size_t max_chars = nlen;
        if (max_chars > C->hit_len_chars)
            max_chars = C->hit_len_chars;
        if (max_chars > 256)
            max_chars = 256;

        wchar_t* w = (wchar_t*)C->pHit;
        for (size_t i = 0; i < max_chars; ++i) {
            w[i] = (wchar_t)(unsigned char)tNew[i];
        }
        for (size_t i = max_chars; i < C->hit_len_chars; ++i) {
            w[i] = L' ';
        }

        send_printf(cs,
            "replaced %zu chars (of %zu) with \"%s\"\n",
            max_chars,
            C->hit_len_chars,
            tNew
        );
        break;
    }

    case '6': {
        if (!C->pVa) {
            send_text(cs, "pVa is NULL. run '1' first.\n");
            break;
        }
        if (C->oldPfn == 0) {
            send_text(cs, "oldPfn is zero. run '2' first.\n");
            break;
        }

        u32   pid = GetCurrentProcessId();
        QWORD va = (QWORD)(uintptr_t)C->pVa;
        QWORD dummy = 0;
        if (!Atomic_GetPfn(pid, va, &dummy)) {
            send_text(cs, "IOCTL (PID/VA->PFN) failed before restore\n");
            break;
        }

        QWORD newPfn = (C->oldPfn >> 12);
        if (!Atomic_SetPfn(newPfn)) {
            send_text(cs, "SET_PFN failed\n");
            break;
        }
        send_printf(cs, "restored PFN: 0x%llx\n", newPfn);
        break;
    }

    case 'd': {
        if (!C->pVa) {
            send_text(cs, "pVa is NULL. run '1' first.\n");
            break;
        }

        char* page_base = (char*)((uintptr_t)C->pVa & ~(uintptr_t)0xFFF);

        dump(page_base, 4096);
        send_text(cs, "dumped 4096 bytes from page base to server console.\n");
        send_printf(cs, "dump completed (page_base=%p)\n", page_base);
        break;
    }

    case 'h': {
        send_usage(cs);
        break;
    }

    case 'q': {
        InterlockedExchange(&g_shutdown, 1);
        send_text(cs, "bye\n");

        if (g_listen_sock != INVALID_SOCKET) {
            closesocket(g_listen_sock);
            g_listen_sock = INVALID_SOCKET;
        }

        return FALSE;
    }

    default:
        send_text(cs, "unknown cmd. type 'h' for help.\n");
        break;
    }

    return TRUE;
}

static DWORD WINAPI processClient(LPVOID arg)
{
    SOCKET client_sock = (SOCKET)arg;
    char   peer[INET_ADDRSTRLEN] = { 0 };

    struct sockaddr_in sa;
    int salen = sizeof(sa);
    if (getpeername(client_sock, (struct sockaddr*)&sa, &salen) == 0) {
        inet_ntop(AF_INET, &sa.sin_addr, peer, sizeof(peer));
    }

    PFN_CTX ctx = { 0 };
    send_printf(client_sock, "connected from %s\n", peer[0] ? peer : "unknown");

    char buf[BUFSIZE + 1];
    for (;;) {
        int ret = recv(client_sock, buf, BUFSIZE, 0);
        if (ret == SOCKET_ERROR) {
            printf("recv() error\n");
            break;
        }
        if (ret == 0) break;
        buf[ret] = '\0';

        char* p = buf;
        while (p && *p) {
            char* eol = strpbrk(p, "\r\n");
            if (eol) *eol = 0;
            if (*p) {
                printf("[client %s] cmd: %s\n", peer, p);
                if (!handle_command_line(&ctx, client_sock, p)) goto done;
            }
            if (!eol) break;
            p = eol + 1;
        }
    }

done:
    if (ctx.pVa) free(ctx.pVa);
    closesocket(client_sock);
    return 0;
}

VOID __cdecl main(_In_ ULONG argc, _In_reads_(argc) PCHAR argv[])
{
    int port = 0;
    if (argc >= 2) {
        port = atoi(argv[1]);
        if (port <= 0 || port > 65535) {
            printf("invalid port: %s\n", argv[1]);
            return;
        }
    }

    InitializeCriticalSection(&g_IoctlLock);

    TCHAR driverLocation[MAX_PATH] = { 0 };

    g_hDevice = CreateFileA(
        "\\\\.\\IoctlTest",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (g_hDevice == INVALID_HANDLE_VALUE) {

        DWORD errNum = GetLastError();

        if (errNum != ERROR_FILE_NOT_FOUND) {
            printf("CreateFile failed : %lu\n", errNum);
            goto cleanup;
        }

        if (!SetupDriverName((PCHAR)driverLocation, sizeof(driverLocation))) goto cleanup;

        if (!ManageDriver(DRIVER_NAME, driverLocation, DRIVER_FUNC_INSTALL)) {
            printf("Unable to install driver.\n");
            ManageDriver(DRIVER_NAME, driverLocation, DRIVER_FUNC_REMOVE);
            goto cleanup;
        }

        g_hDevice = CreateFileA(
            "\\\\.\\IoctlTest",
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        if (g_hDevice == INVALID_HANDLE_VALUE) {
            printf("Error: CreateFile Failed : %d\n", GetLastError());
            goto cleanup;
        }
    }

    {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            printf("WSAStartup failed\n");
            goto cleanup;
        }

        g_listen_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (g_listen_sock == INVALID_SOCKET) {
            printf("socket() failed\n");
            WSACleanup();
            goto cleanup;
        }

        struct sockaddr_in serveraddr;
        memset(&serveraddr, 0, sizeof(serveraddr));
        serveraddr.sin_family = AF_INET;
        serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
        serveraddr.sin_port = htons((u_short)port);

        int ret = bind(g_listen_sock, (struct sockaddr*)&serveraddr, sizeof(serveraddr));
        if (ret == SOCKET_ERROR) {
            printf("bind() failed\n");
            closesocket(g_listen_sock);
            g_listen_sock = INVALID_SOCKET;
            WSACleanup();
            goto cleanup;
        }

        ret = listen(g_listen_sock, SOMAXCONN);
        if (ret == SOCKET_ERROR) {
            printf("listen() failed\n");
            closesocket(g_listen_sock);
            g_listen_sock = INVALID_SOCKET;
            WSACleanup();
            goto cleanup;
        }

        printf("[*] PFN server listening on 0.0.0.0:%d\n", port);

        for (;;) {
            if (g_shutdown) break;

            struct sockaddr_in clientaddr;
            int addrlen = sizeof(clientaddr);

            SOCKET client_sock = accept(g_listen_sock,
                (struct sockaddr*)&clientaddr,
                &addrlen);

            if (client_sock == INVALID_SOCKET) {
                int err = WSAGetLastError();
                if (g_shutdown) {
                    break;
                }
                printf("accept() failed: %d\n", err);
                break;
            }

            HANDLE hThread = CreateThread(NULL, 0, processClient,
                (LPVOID)client_sock, 0, NULL);
            if (hThread == NULL) {
                closesocket(client_sock);
            }
            else {
                CloseHandle(hThread);
            }
        }

        if (g_listen_sock != INVALID_SOCKET) {
            closesocket(g_listen_sock);
            g_listen_sock = INVALID_SOCKET;
        }
        WSACleanup();
    }

cleanup:
    if (g_hDevice != INVALID_HANDLE_VALUE) CloseHandle(g_hDevice);
    DeleteCriticalSection(&g_IoctlLock);
}