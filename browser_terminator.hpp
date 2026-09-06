#pragma once

#include "../core/common.hpp"
#include "../core/console.hpp"
#include "browser_discovery.hpp"
#include <vector>
#include <string>
#include <set>
#include <functional>

namespace Injector {

    struct TerminationStats {
        int processesFound = 0;
        int processesTerminated = 0;
        int processesFailed = 0;
        int childProcesses = 0;
        std::vector<DWORD> terminatedPids;
    };

    struct ProcessEntry {
        DWORD pid;
        DWORD parentPid;
        std::wstring imageName;
        std::wstring commandLine;
        bool isMainProcess;
    };

    struct TerminationOptions {
        bool terminateChildren = true;
        bool waitForExit = true;
        DWORD exitWaitTimeoutMs = 2000;
    };

    class BrowserTerminator {
    public:
        explicit BrowserTerminator(const Core::Console& console);
        ~BrowserTerminator() = default;

        BrowserTerminator(const BrowserTerminator&) = delete;
        BrowserTerminator& operator=(const BrowserTerminator&) = delete;

        TerminationStats KillByExeName(const std::wstring& exeName, const TerminationOptions& opts = {});
        bool IsBrowserRunning(const std::wstring& exeName) const;
        std::vector<ProcessEntry> GetRunningProcesses(const std::wstring& exeName) const;

    private:
        std::vector<ProcessEntry> EnumerateProcesses(const std::wstring& targetExeName) const;
        std::set<DWORD> BuildProcessTree(const std::vector<ProcessEntry>& processes, DWORD rootPid) const;
        bool TerminateProcess(DWORD pid, const TerminationOptions& opts);
        Core::UniqueHandle OpenProcessHandle(DWORD pid, ACCESS_MASK access) const;
        std::wstring GetProcessCommandLine(HANDLE hProcess) const;
        std::wstring GetProcessImageName(HANDLE hProcess) const;
        bool WaitForProcessExit(HANDLE hProcess, DWORD timeoutMs) const;
        bool SendGracefulTermination(DWORD pid, DWORD timeoutMs);

        const Core::Console& m_console;
    };

}