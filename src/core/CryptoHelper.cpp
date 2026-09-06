// Copyright (c) 2026 Eren Taha Akkuş
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "../../include/core/CryptoHelper.hpp"
#include "../../include/utils/Logger.hpp"
#include <stdexcept>
#include <cstring>
#include <random>
#include <chrono>

#pragma comment(lib, "bcrypt.lib")

namespace SecureKeyRetriever
{
    namespace Core
    {
        BCRYPT_ALG_HANDLE CryptoHelper::InitializeAesGcm()
        {
            BCRYPT_ALG_HANDLE hAlg = nullptr;
            NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
            if (status != 0)
            {
                Utils::Logger::Get().LogError("BCryptOpenAlgorithmProvider failed: " + std::to_string(status));
                throw std::runtime_error("Failed to open AES algorithm provider");
            }

            // Set GCM chaining mode
            status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                                       (PBYTE)BCRYPT_CHAIN_MODE_GCM,
                                       sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
            if (status != 0)
            {
                BCryptCloseAlgorithmProvider(hAlg, 0);
                throw std::runtime_error("Failed to set GCM chaining mode");
            }

            return hAlg;
        }

        BCRYPT_KEY_HANDLE CryptoHelper::CreateKeyHandle(BCRYPT_ALG_HANDLE hAlg, const std::vector<uint8_t>& key)
        {
            if (key.size() != 32)
                throw std::runtime_error("Key size must be 32 bytes for AES-256");

            BCRYPT_KEY_HANDLE hKey = nullptr;
            NTSTATUS status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
                                                         (PBYTE)key.data(), (ULONG)key.size(), 0);
            if (status != 0)
                throw std::runtime_error("Failed to generate symmetric key");

            return hKey;
        }

        bool CryptoHelper::PerformDecrypt(
            BCRYPT_KEY_HANDLE hKey,
            const uint8_t* ciphertext,
            size_t ciphertextLength,
            const uint8_t* nonce,
            size_t nonceLength,
            const uint8_t* tag,
            size_t tagLength,
            std::vector<uint8_t>& plaintext)
        {
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
            BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
            authInfo.pbNonce = (PBYTE)nonce;
            authInfo.cbNonce = (ULONG)nonceLength;
            authInfo.pbTag = (PBYTE)tag;
            authInfo.cbTag = (ULONG)tagLength;

            plaintext.resize(ciphertextLength + 32); // Extra space for safety
            DWORD outLen = 0;

            NTSTATUS status = BCryptDecrypt(hKey,
                                            (PBYTE)ciphertext, (ULONG)ciphertextLength,
                                            &authInfo,
                                            nullptr, 0,
                                            plaintext.data(), (ULONG)plaintext.size(),
                                            &outLen, 0);

            if (status != 0)
            {
                Utils::Logger::Get().LogDebug("BCryptDecrypt failed with status: " + std::to_string(status));
                return false;
            }

            plaintext.resize(outLen);
            return true;
        }

        std::vector<uint8_t> CryptoHelper::DecryptAesGcm(
            const std::vector<uint8_t>& key,
            const std::vector<uint8_t>& encryptedData,
            size_t nonceOffset,
            size_t nonceLength,
            size_t tagOffset,
            size_t tagLength)
        {
            if (key.size() != 32)
                throw std::runtime_error("Key must be 32 bytes");

            if (encryptedData.size() < nonceOffset + nonceLength + tagLength)
                throw std::runtime_error("Encrypted data too small for nonce and tag");

            // Extract nonce, tag, and ciphertext
            const uint8_t* nonce = encryptedData.data() + nonceOffset;
            const uint8_t* tag = encryptedData.data() + tagOffset;
            const uint8_t* ciphertext = encryptedData.data() + nonceOffset + nonceLength;
            size_t ciphertextLen = tagOffset - (nonceOffset + nonceLength);

            if (ciphertextLen == 0)
                throw std::runtime_error("Ciphertext length is zero");

            BCRYPT_ALG_HANDLE hAlg = InitializeAesGcm();
            BCRYPT_KEY_HANDLE hKey = CreateKeyHandle(hAlg, key);

            std::vector<uint8_t> plaintext;
            bool success = PerformDecrypt(hKey, ciphertext, ciphertextLen,
                                          nonce, nonceLength, tag, tagLength, plaintext);

            BCryptDestroyKey(hKey);
            BCryptCloseAlgorithmProvider(hAlg, 0);

            if (!success)
                throw std::runtime_error("AES-GCM decryption failed");

            return plaintext;
        }

        bool CryptoHelper::TryDecryptV20Cookie(
            const std::vector<uint8_t>& key,
            const std::vector<uint8_t>& encryptedCookie,
            std::vector<uint8_t>& outPlaintext)
        {
            // v20 format: "v20" (3 bytes) + nonce (12 bytes) + ciphertext + tag (16 bytes)
            if (encryptedCookie.size() < 3 + 12 + 16)
                return false;

            // Check header for "v20"
            if (encryptedCookie[0] != 'v' || encryptedCookie[1] != '2' || encryptedCookie[2] != '0')
                return false;

            try
            {
                outPlaintext = DecryptAesGcm(key, encryptedCookie, 3, 12, encryptedCookie.size() - 16, 16);
                return !outPlaintext.empty();
            }
            catch (const std::exception& e)
            {
                Utils::Logger::Get().LogDebug("Decryption attempt failed: " + std::string(e.what()));
                return false;
            }
        }

        bool CryptoHelper::IsLikelyKey(const uint8_t* data, size_t length)
        {
            if (length < 32)
                return false;

            // Check entropy: count unique bytes
            bool seen[256] = {false};
            int uniqueCount = 0;
            for (size_t i = 0; i < 32; i++)
            {
                if (!seen[data[i]])
                {
                    seen[data[i]] = true;
                    uniqueCount++;
                }
            }

            // A good key should have at least 20 unique bytes out of 32
            if (uniqueCount < 20)
                return false;

            // Count zeros and 0xFFs
            int zeros = 0, ffs = 0;
            for (size_t i = 0; i < 32; i++)
            {
                if (data[i] == 0x00) zeros++;
                if (data[i] == 0xFF) ffs++;
            }

            // Avoid keys that are too uniform
            return (zeros <= 4 && ffs <= 4);
        }

        std::vector<uint8_t> CryptoHelper::GenerateRandomKey()
        {
            std::vector<uint8_t> key(32);
            std::random_device rd;
            std::mt19937_64 gen(rd() + std::chrono::steady_clock::now().time_since_epoch().count());
            std::uniform_int_distribution<uint64_t> dist(0, 0xFFFFFFFFFFFFFFFF);

            for (size_t i = 0; i < 4; i++)
            {
                uint64_t val = dist(gen);
                memcpy(key.data() + i * 8, &val, 8);
            }

            return key;
        }

    } // namespace Core
} // namespace SecureKeyRetriever
