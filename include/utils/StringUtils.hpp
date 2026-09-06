// Copyright (c) 2026 Eren Taha Akkuş
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <algorithm>
#include <cctype>

namespace SecureKeyRetriever
{
    namespace Utils
    {
        /**
         * @brief Utility class for string manipulation and conversion.
         * 
         * Provides static methods for common string operations:
         * - Hex conversion (to/from binary, integers)
         * - JSON escaping
         * - Case conversion
         * - String splitting/joining
         * - Wide/narrow string conversion
         */
        class StringUtils
        {
        public:
            // ---- Hex conversions ----

            /**
             * @brief Converts a 32-bit unsigned integer to a hexadecimal string.
             * 
             * @param value The value to convert.
             * @param prefix Whether to include "0x" prefix.
             * @param uppercase Whether to use uppercase letters.
             * @return std::string The hexadecimal representation.
             */
            static std::string ToHex(uint32_t value, bool prefix = true, bool uppercase = true);

            /**
             * @brief Converts a 64-bit unsigned integer to a hexadecimal string.
             * 
             * @param value The value to convert.
             * @param prefix Whether to include "0x" prefix.
             * @param uppercase Whether to use uppercase letters.
             * @return std::string The hexadecimal representation.
             */
            static std::string ToHex(uint64_t value, bool prefix = true, bool uppercase = true);

            /**
             * @brief Converts a byte array to a hexadecimal string.
             * 
             * @param data The byte array.
             * @param uppercase Whether to use uppercase letters.
             * @param separator Optional separator between bytes (e.g., ":" or "-").
             * @return std::string The hexadecimal string.
             */
            static std::string ToHex(const std::vector<uint8_t>& data, bool uppercase = true, const std::string& separator = "");

            /**
             * @brief Converts a hexadecimal string back to a byte array.
             * 
             * @param hex The hexadecimal string (may contain spaces, separators).
             * @param outData Output byte array.
             * @return true If parsing succeeded.
             * @return false Otherwise.
             */
            static bool FromHex(const std::string& hex, std::vector<uint8_t>& outData);

            // ---- JSON escaping ----

            /**
             * @brief Escapes a string for safe embedding in JSON.
             * 
             * Escapes: ", \, /, backspace, formfeed, newline, carriage return, tab.
             * Also escapes control characters (0x00-0x1F) as \uXXXX.
             * 
             * @param input The input string.
             * @return std::string The escaped JSON string.
             */
            static std::string EscapeJson(const std::string& input);

            // ---- Case conversion ----

            /**
             * @brief Converts a string to lowercase.
             * 
             * @param input The input string.
             * @return std::string The lowercase string.
             */
            static std::string ToLower(const std::string& input);

            /**
             * @brief Converts a string to uppercase.
             * 
             * @param input The input string.
             * @return std::string The uppercase string.
             */
            static std::string ToUpper(const std::string& input);

            // ---- String operations ----

            /**
             * @brief Splits a string by a delimiter.
             * 
             * @param str The input string.
             * @param delimiter The delimiter character.
             * @param trimWhitespace Whether to trim whitespace from each token.
             * @return std::vector<std::string> The list of tokens.
             */
            static std::vector<std::string> Split(const std::string& str, char delimiter, bool trimWhitespace = true);

            /**
             * @brief Joins a list of strings with a separator.
             * 
             * @param parts The list of strings.
             * @param separator The separator string.
             * @return std::string The joined string.
             */
            static std::string Join(const std::vector<std::string>& parts, const std::string& separator);

            /**
             * @brief Trims leading and trailing whitespace from a string.
             * 
             * @param str The input string.
             * @return std::string The trimmed string.
             */
            static std::string Trim(const std::string& str);

            /**
             * @brief Checks if a string starts with a given prefix.
             * 
             * @param str The input string.
             * @param prefix The prefix to check.
             * @param caseSensitive Whether to perform case-sensitive comparison.
             * @return true If the string starts with the prefix.
             * @return false Otherwise.
             */
            static bool StartsWith(const std::string& str, const std::string& prefix, bool caseSensitive = true);

            /**
             * @brief Checks if a string ends with a given suffix.
             * 
             * @param str The input string.
             * @param suffix The suffix to check.
             * @param caseSensitive Whether to perform case-sensitive comparison.
             * @return true If the string ends with the suffix.
             * @return false Otherwise.
             */
            static bool EndsWith(const std::string& str, const std::string& suffix, bool caseSensitive = true);

            // ---- Wide/narrow conversion ----

            /**
             * @brief Converts a wide string to a narrow string (UTF-8).
             * 
             * Uses Windows API (WideCharToMultiByte) with CP_UTF8.
             * 
             * @param wstr The wide string.
             * @return std::string The narrow string.
             * @throws std::runtime_error on conversion failure.
             */
            static std::string WStringToString(const std::wstring& wstr);

            /**
             * @brief Converts a narrow string (UTF-8) to a wide string.
             * 
             * Uses Windows API (MultiByteToWideChar) with CP_UTF8.
             * 
             * @param str The narrow string.
             * @return std::wstring The wide string.
             * @throws std::runtime_error on conversion failure.
             */
            static std::wstring StringToWString(const std::string& str);

            // ---- File path utilities ----

            /**
             * @brief Extracts the file name from a full path.
             * 
             * @param path The file path.
             * @return std::string The file name (including extension).
             */
            static std::string GetFileName(const std::string& path);

            /**
             * @brief Extracts the file name without extension from a full path.
             * 
             * @param path The file path.
             * @return std::string The file name without extension.
             */
            static std::string GetFileNameWithoutExtension(const std::string& path);

            /**
             * @brief Extracts the file extension from a full path.
             * 
             * @param path The file path.
             * @return std::string The file extension (including the dot).
             */
            static std::string GetFileExtension(const std::string& path);

        private:
            /**
             * @brief Helper to convert hex digit to value.
             */
            static int HexDigitToValue(char c);

            /**
             * @brief Helper to escape control characters in JSON.
             */
            static void AppendEscapedChar(std::ostringstream& oss, unsigned char c);
        };

    } // namespace Utils
} // namespace SecureKeyRetriever
