// ============================================================
// Windows Process Debugging & Hardware Breakpoint Research Framework
// Purpose: Educational research on Windows Hardware Breakpoints (DR0/DR7)
//          and process memory enumeration using Indirect Syscalls.
// Disclaimer: This code is for defensive/educational research only.
// ============================================================
#include <windows.h>
#include <winternl.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlwapi.h>
#include <bcrypt.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <versionhelpers.h>
#include <string>
#include <vector>
#include <cstdio>
#include <algorithm>
#include <ctime>
#include <memory>

// NullGate Libraries (For educational Syscall demonstration)
#include "NullGate/include/nullgate/obfuscation.hpp"
#include "NullGate/include/nullgate/syscalls.hpp"

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ntdll.lib")

#ifndef STATUS_NO_MORE_ENTRIES
#define STATUS_NO_MORE_ENTRIES ((NTSTATUS)0x8000001AL)
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#ifndef DEBUG_ALL_ACCESS
#define DEBUG_ALL_ACCESS 0x1F0000
#endif

namespace ng = nullgate;
ng::syscalls g_syscalls;

// ============================================================
// GÜVENLİ SYSCALL WRAPPER (SCALL KULLANIMI - Eğitim Amaçlı)
// ============================================================
using fnNtGetContextThread = NTSTATUS(NTAPI*)(HANDLE, PCONTEXT);
using fnNtSetContextThread = NTSTATUS(NTAPI*)(HANDLE, PCONTEXT);
using fnNtSuspendThread = NTSTATUS(NTAPI*)(HANDLE, PULONG);
using fnNtResumeThread = NTSTATUS(NTAPI*)(HANDLE, PULONG);
using fnNtGetNextThread = NTSTATUS(NTAPI*)(HANDLE, HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE);

template<typename... Args>
NTSTATUS SafeSyscall(const char* name, Args&&... args) {
    return g_syscalls.Call(std::string(name), std::forward<Args>(args)...);
}

// ============================================================
// DEBUG PRIVILEGE (Eğitim Amaçlı)
// ============================================================
BOOL EnableDebugPrivilege() {
    HANDLE hToken; LUID luid; TOKEN_PRIVILEGES tp;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return FALSE;
    if (!LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid)) { CloseHandle(hToken); return FALSE; }
    tp.PrivilegeCount = 1; tp.Privileges[0].Luid = luid; tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) { CloseHandle(hToken); return FALSE; }
    CloseHandle(hToken); return TRUE;
}

// ============================================================
// HARDWARE BREAKPOINT (DR0/DR7) - Eğitim Amaçlı
// ============================================================
BOOL SetHWBreakPoint(HANDLE hThread, DWORD64 addr) {
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL; 
    if (!NT_SUCCESS(SafeSyscall("NtGetContextThread", hThread, &ctx))) return FALSE;

    ctx.Dr0 = addr;
    ctx.Dr7 &= ~(1ULL << 0); 
    ctx.Dr7 |= (1ULL << 0);  
    ctx.Dr6 = 0; 

    if (!NT_SUCCESS(SafeSyscall("NtSetContextThread", hThread, &ctx))) return FALSE;
    return TRUE;
}

BOOL SetHWBPOnAllThreads(HANDLE hProcess, uintptr_t bpAddr) {
    HANDLE hThread = nullptr;
    for (;;) {
        HANDLE hNextThread = nullptr;
        NTSTATUS st = SafeSyscall("NtGetNextThread", hProcess, hThread, (ACCESS_MASK)THREAD_ALL_ACCESS, 0, 0, &hNextThread);
        if (!NT_SUCCESS(st)) {
            if (hThread) CloseHandle(hThread);
            if (st != STATUS_NO_MORE_ENTRIES) return FALSE;
            break;
        }
        if (NT_SUCCESS(SafeSyscall("NtSuspendThread", hNextThread, nullptr))) {
            SetHWBreakPoint(hNextThread, bpAddr);
            SafeSyscall("NtResumeThread", hNextThread, nullptr);
        }
        if (hThread) CloseHandle(hThread);
        hThread = hNextThread;
    }
    return TRUE;
}

// ============================================================
// BELETEK TARAMA - Eğitim Amaçlı (VIRTUALQUERYEX)
// ============================================================
void ScanProcessMemory(HANDLE hProcess) {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    uintptr_t startAddr = (uintptr_t)sysInfo.lpMinimumApplicationAddress;
    uintptr_t endAddr = (uintptr_t)sysInfo.lpMaximumApplicationAddress;
    MEMORY_BASIC_INFORMATION mbi;

    printf("[*] Scanning process memory regions (Research only)...\n");
    while (startAddr < endAddr) {
        if (VirtualQueryEx(hProcess, (LPCVOID)startAddr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.State == MEM_COMMIT) {
                printf("[*] Found region: Base=0x%p, Size=0x%zx\n", mbi.BaseAddress, mbi.RegionSize);
            }
            startAddr += mbi.RegionSize;
        } else break;
    }
}

// ============================================================
// ANA FONKSİYON - Prosesi Başlat ve İzle (Eğitim Amaçlı)
// ============================================================
int main() {
    if (!EnableDebugPrivilege()) {
        printf("[-] SeDebugPrivilege aktif edilemedi! Yonetici olarak calistirin.\n");
        return -1;
    }
    printf("[+] SeDebugPrivilege ENABLED!\n");
    printf("[+] Hardware Breakpoint Research Framework (v1.0)\n");
    printf("[+] Target: A local test process (not stealing data!)\n\n");

    // Örnek: notepad.exe başlat ve incele
    STARTUPINFOW si = {sizeof(si)};
    si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {0};

    if (!CreateProcessW(L"C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        LogError("CreateProcess failed"); return 1;
    }
    printf("[+] Test process started (PID: %d)\n", pi.dwProcessId);

    // Process memory'si hakkında bilgi topla
    ScanProcessMemory(pi.hProcess);

    // Thread'lere örnek bir breakpoint adresi (0x0 yerine geçici bir adres) set et
    printf("[*] Setting hardware breakpoint on test process...\n");
    SetHWBPOnAllThreads(pi.hProcess, (uintptr_t)pi.hThread);

    printf("[+] Done. Research complete. Process will be terminated.\n");
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    
    return 0;
}