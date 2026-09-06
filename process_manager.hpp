

#pragma once

#include "../core/common.hpp"
#include "browser_discovery.hpp"

namespace Injector {

    class ProcessManager {
    public:
        explicit ProcessManager(const BrowserInfo& browser);
        ~ProcessManager();

        void CreateSuspended();
        void Terminate();
        HANDLE GetProcessHandle() const { return m_hProcess.get(); }
        HANDLE GetThreadHandle() const { return m_hThread.get(); }
        DWORD GetPid() const { return m_pid; }

    private:
        void CheckArchitecture();

        BrowserInfo m_browser;
        Core::UniqueHandle m_hProcess;
        Core::UniqueHandle m_hThread;
        DWORD m_pid = 0;
        USHORT m_arch = 0;
    };

}