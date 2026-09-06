
#pragma once

#include "../core/common.hpp"
#include <string>

namespace Payload {

    class PipeClient {
    public:
        explicit PipeClient(const std::wstring& pipeName);
        ~PipeClient();

        bool IsValid() const { return m_hPipe != INVALID_HANDLE_VALUE; }

        void Log(const std::string& msg);
        void LogDebug(const std::string& msg);
        void LogData(const std::string& key, const std::string& value);

        struct Config {
            bool verbose;
            bool fingerprint;
            std::string outputPath;
            std::string browserType;
        };
        Config ReadConfig();

    private:
        HANDLE m_hPipe;
    };

}