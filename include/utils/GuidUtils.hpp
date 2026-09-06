// Copyright (c) 2026 Eren Taha Akkuş
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include <windows.h>
#include <objbase.h>
#include <string>
#include <vector>
#include <cstdint>
#include <optional>

namespace SecureKeyRetriever
{
    namespace Utils
    {
        /**
         * @brief Utility class for GUID manipulation and conversion.
         * 
         * Provides static methods for converting GUIDs to/from strings,
         * generating random GUIDs, comparing GUIDs, and checking for empty GUIDs.
         * All methods are thread-safe and use standard Windows API.
         */
        class GuidUtils
        {
        public:
            /**
             * @brief Converts a GUID to a string in the standard format.
             * 
             * Format: "{12345678-1234-1234-1234-123456789ABC}"
             * 
             * @param guid The GUID to convert.
             * @return std::string The GUID as a string.
             */
            static std::string GuidToString(const GUID& guid);

            /**
             * @brief Converts a GUID to a wide string in the standard format.
             * 
             * @param guid The GUID to convert.
             * @return std::wstring The GUID as a wide string.
             */
            static std::wstring GuidToWString(const GUID& guid);

            /**
             * @brief Parses a string representation of a GUID.
             * 
             * Supports both "{...}" and "..." formats (with or without braces).
             * 
             * @param str The string to parse.
             * @param guid Output GUID.
             * @return true If parsing succeeded.
             * @return false Otherwise.
             */
            static bool StringToGuid(const std::string& str, GUID& guid);

            /**
             * @brief Parses a wide string representation of a GUID.
             * 
             * Supports both L"{...}" and L"..." formats (with or without braces).
             * 
             * @param str The wide string to parse.
             * @param guid Output GUID.
             * @return true If parsing succeeded.
             * @return false Otherwise.
             */
            static bool WStringToGuid(const std::wstring& str, GUID& guid);

            /**
             * @brief Checks if a GUID is empty (all zeros).
             * 
             * @param guid The GUID to check.
             * @return true If the GUID is all zeros.
             * @return false Otherwise.
             */
            static bool IsGuidEmpty(const GUID& guid);

            /**
             * @brief Compares two GUIDs for equality.
             * 
             * @param a First GUID.
             * @param b Second GUID.
             * @return true If they are equal.
             * @return false Otherwise.
             */
            static bool AreGuidsEqual(const GUID& a, const GUID& b);

            /**
             * @brief Generates a random GUID using CoCreateGuid.
             * 
             * @return GUID A newly generated random GUID.
             * @throws std::runtime_error if CoCreateGuid fails.
             */
            static GUID CreateRandomGuid();

            /**
             * @brief Converts a GUID to a byte array (16 bytes).
             * 
             * The byte order matches the in-memory representation.
             * 
             * @param guid The GUID to convert.
             * @return std::vector<uint8_t> The binary representation (16 bytes).
             */
            static std::vector<uint8_t> GuidToBytes(const GUID& guid);

            /**
             * @brief Reconstructs a GUID from a byte array (16 bytes).
             * 
             * The byte order must match the in-memory representation.
             * 
             * @param bytes The byte array (must be at least 16 bytes).
             * @return std::optional<GUID> The reconstructed GUID, or std::nullopt if invalid.
             */
            static std::optional<GUID> BytesToGuid(const std::vector<uint8_t>& bytes);

            /**
             * @brief Formats a GUID for logging (without braces, uppercase).
             * 
             * @param guid The GUID to format.
             * @return std::string A compact string representation.
             */
            static std::string FormatForLog(const GUID& guid);

        private:
            /**
             * @brief Helper to convert a GUID to a string with optional braces.
             * 
             * @param guid The GUID.
             * @param useBraces Whether to include braces.
             * @param uppercase Whether to use uppercase letters.
             * @return std::string The formatted string.
             */
            static std::string ToStringInternal(const GUID& guid, bool useBraces, bool uppercase);
        };

    } // namespace Utils
} // namespace SecureKeyRetriever
