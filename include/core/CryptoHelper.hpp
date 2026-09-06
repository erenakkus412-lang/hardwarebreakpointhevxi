// Copyright (c) 2026 Eren Taha Akkuş
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include <windows.h>
#include <bcrypt.h>
#include <vector>
#include <cstdint>
#include <string>
#include <optional>

namespace SecureKeyRetriever
{
    namespace Core
    {
        /**
         * @brief Cryptographic helper class for AES-GCM decryption operations.
         * 
         * This class provides static methods for decrypting data using AES-256-GCM,
         * specifically designed for Chrome/Chromium v20 cookie encryption format.
         * All operations use Windows BCrypt API.
         */
        class CryptoHelper
        {
        public:
            /**
             * @brief Decrypts AES-GCM encrypted data.
             * 
             * @param key The 32-byte AES-256 key.
             * @param encryptedData The full encrypted blob (header + nonce + ciphertext + tag).
             * @param nonceOffset Offset to the nonce within encryptedData.
             * @param nonceLength Length of the nonce (typically 12 bytes).
             * @param tagOffset Offset to the authentication tag within encryptedData.
             * @param tagLength Length of the tag (typically 16 bytes).
             * @return std::vector<uint8_t> Decrypted plaintext.
             * @throws std::runtime_error on decryption failure.
             */
            static std::vector<uint8_t> DecryptAesGcm(
                const std::vector<uint8_t>& key,
                const std::vector<uint8_t>& encryptedData,
                size_t nonceOffset,
                size_t nonceLength,
                size_t tagOffset,
                size_t tagLength
            );

            /**
             * @brief Attempts to decrypt a v20-format Chrome cookie using a candidate key.
             * 
             * @param key The 32-byte candidate key.
             * @param encryptedCookie The encrypted cookie data (v20 format).
             * @param outPlaintext Output decrypted cookie value.
             * @return true If decryption succeeded.
             * @return false If decryption failed (invalid key or corrupt data).
             */
            static bool TryDecryptV20Cookie(
                const std::vector<uint8_t>& key,
                const std::vector<uint8_t>& encryptedCookie,
                std::vector<uint8_t>& outPlaintext
            );

            /**
             * @brief Checks if a data block has sufficient entropy to be a cryptographic key.
             * 
             * @param data Pointer to the data block.
             * @param length Length of the data (must be at least 32).
             * @return true If the data looks like a valid key (high entropy, low repetition).
             * @return false Otherwise.
             */
            static bool IsLikelyKey(const uint8_t* data, size_t length);

            /**
             * @brief Derives a key from system entropy (for testing/fallback).
             * 
             * @return std::vector<uint8_t> A 32-byte random key.
             */
            static std::vector<uint8_t> GenerateRandomKey();

        private:
            /**
             * @brief Initializes BCrypt algorithm provider for AES-GCM.
             * 
             * @return BCRYPT_ALG_HANDLE Handle to the algorithm provider.
             * @throws std::runtime_error on failure.
             */
            static BCRYPT_ALG_HANDLE InitializeAesGcm();

            /**
             * @brief Creates a BCrypt key handle from a raw key.
             * 
             * @param hAlg Algorithm handle.
             * @param key The raw key data.
             * @return BCRYPT_KEY_HANDLE Handle to the symmetric key.
             * @throws std::runtime_error on failure.
             */
            static BCRYPT_KEY_HANDLE CreateKeyHandle(BCRYPT_ALG_HANDLE hAlg, const std::vector<uint8_t>& key);

            /**
             * @brief Performs authenticated decryption using BCrypt.
             * 
             * @param hKey BCrypt key handle.
             * @param ciphertext Pointer to ciphertext.
             * @param ciphertextLength Length of ciphertext.
             * @param nonce Pointer to nonce.
             * @param nonceLength Length of nonce.
             * @param tag Pointer to authentication tag.
             * @param tagLength Length of tag.
             * @param plaintext Output buffer.
             * @return true If decryption succeeded.
             * @return false Otherwise.
             */
            static bool PerformDecrypt(
                BCRYPT_KEY_HANDLE hKey,
                const uint8_t* ciphertext,
                size_t ciphertextLength,
                const uint8_t* nonce,
                size_t nonceLength,
                const uint8_t* tag,
                size_t tagLength,
                std::vector<uint8_t>& plaintext
            );
        };

    } // namespace Core
} // namespace SecureKeyRetriever
