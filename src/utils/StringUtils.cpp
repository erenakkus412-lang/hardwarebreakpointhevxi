// Copyright (c) 2026 Eren Taha Akkuş
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "../../include/utils/StringUtils.hpp"
#include "../../include/utils/Logger.hpp"
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <cstring>

namespace SecureKeyRetriever
{
    namespace Utils
    {
        // ---- Hex conversions ----

        std::string StringUtils::ToHex(uint32_t value, bool prefix, bool uppercase)
        {
            std::ostringstream oss;
            if (prefix)
                oss << "0x";
            oss << std::hex << std::setfill('0') << std::setw(8)
                << (uppercase ? std::uppercase : std::nouppercase)
                << value;
            return oss.str();
        }

        std::string StringUtils::ToHex(uint64_t value, bool prefix, bool uppercase)
        {
            std::ostringstream oss;
            if (prefix)
                oss << "0x";
            oss << std::hex << std::setfill('0') << std::setw(16)
                << (uppercase ? std::uppercase : std::nouppercase)
                << value;
            return oss.str();
        }

        std::string StringUtils::ToHex(const std::vector<uint8_t>& data, bool uppercase, const std::string& separator)
        {
            if (data.empty())
                return "";

            std::ostringstream oss;
            oss << std::hex << std::setfill('0')
                << (uppercase ? std::uppercase : std::nouppercase);

            for (size_t i = 0; i < data.size(); ++i)
            {
                if (i > 0 && !separator.empty())
                    oss << separator;
                oss << std::setw(2) << static_cast<int>(data[i]);
            }
            return oss.str();
        }

        bool StringUtils::FromHex(const std::string& hex, std::vector<uint8_t>& outData)
        {
            outData.clear();

            // Remove whitespace and separators (spaces, ':', '-', etc.)
            std::string cleaned;
            for (char c : hex)
            {
                if (std::isxdigit(c))
                    cleaned.push_back(c);
                else if (c != ' ' && c != ':' && c != '-' && c != '\t' && c != '\r' && c != '\n')
                {
                    // Invalid character
                    Logger::Get().LogWarning("Invalid hex character: '" + std::string(1, c) + "'");
                    return false;
                }
            }

            if (cleaned.empty())
                return true; // empty input -> empty output

            if (cleaned.length() % 2 != 0)
            {
                Logger::Get().LogWarning("Hex string has odd length: " + std::to_string(cleaned.length()));
                return false;
            }

            outData.reserve(cleaned.length() / 2);
            for (size_t i = 0; i < cleaned.length(); i += 2)
            {
                int high = HexDigitToValue(cleaned[i]);
                int low = HexDigitToValue(cleaned[i + 1]);
                if (high < 0 || low < 0)
                    return false;
                outData.push_back(static_cast<uint8_t>((high << 4) | low));
            }

            return true;
        }

        int StringUtils::HexDigitToValue(char c)
        {
            if (c >= '0' && c <= '9')
                return c - '0';
            if (c >= 'a' && c <= 'f')
                return 10 + (c - 'a');
            if (c >= 'A' && c <= 'F')
                return 10 + (c - 'A');
            return -1;
        }

        // ---- JSON escaping ----

        std::string StringUtils::EscapeJson(const std::string& input)
        {
            std::ostringstream oss;
            for (unsigned char c : input)
            {
                switch (c)
                {
                    case '"':  oss << "\\\""; break;
                    case '\\': oss << "\\\\"; break;
                    case '/':  oss << "\\/"; break;
                    case '\b': oss << "\\b"; break;
                    case '\f': oss << "\\f"; break;
                    case '\n': oss << "\\n"; break;
                    case '\r': oss << "\\r"; break;
                    case '\t': oss << "\\t"; break;
                    default:
                        if (c < 0x20)
                        {
                            AppendEscapedChar(oss, c);
                        }
                        else
                        {
                            oss << c;
                        }
                        break;
                }
            }
            return oss.str();
        }

        void StringUtils::AppendEscapedChar(std::ostringstream& oss, unsigned char c)
        {
            oss << "\\u"
                << std::hex << std::setfill('0') << std::setw(4)
                << static_cast<int>(c);
        }

        // ---- Case conversion ----

        std::string StringUtils::ToLower(const std::string& input)
        {
            std::string result = input;
            std::transform(result.begin(), result.end(), result.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            return result;
        }

        std::string StringUtils::ToUpper(const std::string& input)
        {
            std::string result = input;
            std::transform(result.begin(), result.end(), result.begin(),
                           [](unsigned char c) { return std::toupper(c); });
            return result;
        }

        // ---- String operations ----

        std::vector<std::string> StringUtils::Split(const std::string& str, char delimiter, bool trimWhitespace)
        {
            std::vector<std::string> tokens;
            std::stringstream ss(str);
            std::string token;

            while (std::getline(ss, token, delimiter))
            {
                if (trimWhitespace)
                    token = Trim(token);
                if (!token.empty())
                    tokens.push_back(token);
            }

            return tokens;
        }

        std::string StringUtils::Join(const std::vector<std::string>& parts, const std::string& separator)
        {
            if (parts.empty())
                return "";

            std::ostringstream oss;
            for (size_t i = 0; i < parts.size(); ++i)
            {
                if (i > 0)
                    oss << separator;
                oss << parts[i];
            }
            return oss.str();
        }

        std::string StringUtils::Trim(const std::string& str)
        {
            size_t start = str.find_first_not_of(" \t\n\r\f\v");
            if (start == std::string::npos)
                return "";

            size_t end = str.find_last_not_of(" \t\n\r\f\v");
            return str.substr(start, end - start + 1);
        }

        bool StringUtils::StartsWith(const std::string& str, const std::string& prefix, bool caseSensitive)
        {
            if (prefix.length() > str.length())
                return false;

            std::string strPart = str.substr(0, prefix.length());
            if (!caseSensitive)
            {
                strPart = ToLower(strPart);
                std::string prefixLower = ToLower(prefix);
                return strPart == prefixLower;
            }
            return strPart == prefix;
        }

        bool StringUtils::EndsWith(const std::string& str, const std::string& suffix, bool caseSensitive)
        {
            if (suffix.length() > str.length())
                return false;

            std::string strPart = str.substr(str.length() - suffix.length());
            if (!caseSensitive)
            {
                strPart = ToLower(strPart);
                std::string suffixLower = ToLower(suffix);
                return strPart == suffixLower;
            }
            return strPart == suffix;
        }

        // ---- Wide/narrow conversion ----

        std::string StringUtils::WStringToString(const std::wstring& wstr)
        {
            if (wstr.empty())
                return {};

            int len = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
            if (len <= 0)
            {
                Logger::Get().LogError("WideCharToMultiByte failed to get length");
                throw std::runtime_error("Failed to convert wide string to narrow");
            }

            std::string result(len - 1, '\0');
            int written = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &result[0], len, nullptr, nullptr);
            if (written <= 0)
            {
                Logger::Get().LogError("WideCharToMultiByte failed to convert");
                throw std::runtime_error("Failed to convert wide string to narrow");
            }

            return result;
        }

        std::wstring StringUtils::StringToWString(const std::string& str)
        {
            if (str.empty())
                return {};

            int len = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
            if (len <= 0)
            {
                Logger::Get().LogError("MultiByteToWideChar failed to get length");
                throw std::runtime_error("Failed to convert narrow string to wide");
            }

            std::wstring result(len - 1, L'\0');
            int written = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &result[0], len);
            if (written <= 0)
            {
                Logger::Get().LogError("MultiByteToWideChar failed to convert");
                throw std::runtime_error("Failed to convert narrow string to wide");
            }

            return result;
        }

        // ---- File path utilities ----

        std::string StringUtils::GetFileName(const std::string& path)
        {
            size_t pos = path.find_last_of("/\\");
            if (pos == std::string::npos)
                return path;
            return path.substr(pos + 1);
        }

        std::string StringUtils::GetFileNameWithoutExtension(const std::string& path)
        {
            std::string filename = GetFileName(path);
            size_t pos = filename.find_last_of('.');
            if (pos == std::string::npos)
                return filename;
            return filename.substr(0, pos);
        }

        std::string StringUtils::GetFileExtension(const std::string& path)
        {
            std::string filename = GetFileName(path);
            size_t pos = filename.find_last_of('.');
            if (pos == std::string::npos || pos == 0)
                return "";
            return filename.substr(pos);
        }

    } // namespace Utils
} // namespace SecureKeyRetriever