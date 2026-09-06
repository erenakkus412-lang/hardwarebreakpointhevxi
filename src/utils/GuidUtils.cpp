// Copyright (c) 2026 Eren Taha Akkuş
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "../../include/utils/GuidUtils.hpp"
#include "../../include/utils/Logger.hpp"
#include <comdef.h>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

namespace SecureKeyRetriever
{
    namespace Utils
    {
        std::string GuidUtils::GuidToString(const GUID& guid)
        {
            return ToStringInternal(guid, true, true);
        }

        std::wstring GuidUtils::GuidToWString(const GUID& guid)
        {
            wchar_t buffer[40] = {0};
            if (StringFromGUID2(guid, buffer, 40) == 0)
            {
                Logger::Get().LogError("StringFromGUID2 failed");
                return L"";
            }
            return std::wstring(buffer);
        }

        bool GuidUtils::StringToGuid(const std::string& str, GUID& guid)
        {
            // Convert to wide string and use CLSIDFromString
            std::wstring wstr(str.begin(), str.end());
            return WStringToGuid(wstr, guid);
        }

        bool GuidUtils::WStringToGuid(const std::wstring& str, GUID& guid)
        {
            // CLSIDFromString accepts the string with or without braces
            HRESULT hr = CLSIDFromString(str.c_str(), &guid);
            if (FAILED(hr))
            {
                Logger::Get().LogWarning("Failed to parse GUID from string: " + std::string(str.begin(), str.end()));
                return false;
            }
            return true;
        }

        bool GuidUtils::IsGuidEmpty(const GUID& guid)
        {
            static const GUID EmptyGuid = {};
            return AreGuidsEqual(guid, EmptyGuid);
        }

        bool GuidUtils::AreGuidsEqual(const GUID& a, const GUID& b)
        {
            return memcmp(&a, &b, sizeof(GUID)) == 0;
        }

        GUID GuidUtils::CreateRandomGuid()
        {
            GUID guid = {};
            HRESULT hr = CoCreateGuid(&guid);
            if (FAILED(hr))
            {
                Logger::Get().LogError("CoCreateGuid failed: 0x" + std::to_string(hr));
                throw std::runtime_error("Failed to create random GUID");
            }
            return guid;
        }

        std::vector<uint8_t> GuidUtils::GuidToBytes(const GUID& guid)
        {
            const uint8_t* ptr = reinterpret_cast<const uint8_t*>(&guid);
            return std::vector<uint8_t>(ptr, ptr + sizeof(GUID));
        }

        std::optional<GUID> GuidUtils::BytesToGuid(const std::vector<uint8_t>& bytes)
        {
            if (bytes.size() < sizeof(GUID))
            {
                Logger::Get().LogWarning("Byte array too small for GUID: " + std::to_string(bytes.size()));
                return std::nullopt;
            }

            GUID guid;
            memcpy(&guid, bytes.data(), sizeof(GUID));
            return guid;
        }

        std::string GuidUtils::FormatForLog(const GUID& guid)
        {
            // Without braces, uppercase
            return ToStringInternal(guid, false, true);
        }

        // Internal implementation
        std::string GuidUtils::ToStringInternal(const GUID& guid, bool useBraces, bool uppercase)
        {
            // Extract fields
            uint32_t data1 = guid.Data1;
            uint16_t data2 = guid.Data2;
            uint16_t data3 = guid.Data3;
            uint8_t data4[8];
            memcpy(data4, guid.Data4, 8);

            // Build the string
            std::ostringstream oss;
            if (useBraces)
                oss << "{";

            // Set hex formatting
            if (uppercase)
                oss << std::uppercase;
            else
                oss << std::nouppercase;

            oss << std::hex << std::setfill('0')
                << std::setw(8) << data1 << "-"
                << std::setw(4) << data2 << "-"
                << std::setw(4) << data3 << "-"
                << std::setw(2) << static_cast<int>(data4[0])
                << std::setw(2) << static_cast<int>(data4[1]) << "-"
                << std::setw(2) << static_cast<int>(data4[2])
                << std::setw(2) << static_cast<int>(data4[3])
                << std::setw(2) << static_cast<int>(data4[4])
                << std::setw(2) << static_cast<int>(data4[5])
                << std::setw(2) << static_cast<int>(data4[6])
                << std::setw(2) << static_cast<int>(data4[7]);

            if (useBraces)
                oss << "}";

            return oss.str();
        }

    } // namespace Utils
} // namespace SecureKeyRetriever
