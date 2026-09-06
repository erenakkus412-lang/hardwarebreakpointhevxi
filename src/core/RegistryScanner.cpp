// Copyright (c) 2026 Eren Taha Akkuş
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "../../include/core/RegistryScanner.hpp"
#include "../../include/utils/Logger.hpp"
#include <winreg.h>
#include <comdef.h>
#include <algorithm>

namespace SecureKeyRetriever
{
    namespace Core
    {
        bool RegistryScanner::StringToGuid(const std::wstring& str, GUID& guid)
        {
            return CLSIDFromString(str.c_str(), &guid) == S_OK;
        }

        std::wstring RegistryScanner::ReadRegistryValue(HKEY hKeyRoot, const std::wstring& subKey, const std::wstring& valueName)
        {
            HKEY hKey;
            if (RegOpenKeyExW(hKeyRoot, subKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
                return L"";

            wchar_t buffer[1024] = {0};
            DWORD bufferSize = sizeof(buffer);
            DWORD type = 0;

            LONG result = RegQueryValueExW(hKey, valueName.empty() ? nullptr : valueName.c_str(),
                                           nullptr, &type, (LPBYTE)buffer, &bufferSize);
            RegCloseKey(hKey);

            if (result != ERROR_SUCCESS)
                return L"";

            // If REG_SZ or REG_EXPAND_SZ, convert to wstring
            if (type == REG_SZ || type == REG_EXPAND_SZ)
                return std::wstring(buffer);

            return L"";
        }

        std::vector<GUID> RegistryScanner::FindClsidsByName(const std::wstring& nameFilter)
        {
            std::vector<GUID> result;
            HKEY hKeyClsid;

            if (RegOpenKeyExW(HKEY_CLASSES_ROOT, L"CLSID", 0, KEY_READ, &hKeyClsid) != ERROR_SUCCESS)
            {
                Utils::Logger::Get().LogError("Failed to open HKCR\\CLSID");
                return result;
            }

            DWORD index = 0;
            wchar_t subKeyName[256];
            DWORD subKeyNameLen = 256;
            FILETIME ft;

            while (RegEnumKeyExW(hKeyClsid, index, subKeyName, &subKeyNameLen, nullptr, nullptr, nullptr, &ft) == ERROR_SUCCESS)
            {
                GUID clsid;
                if (StringToGuid(subKeyName, clsid))
                {
                    // Read the default class name
                    std::wstring className = GetClassName(clsid);

                    // Apply filter (case-insensitive)
                    if (nameFilter.empty() ||
                        std::search(className.begin(), className.end(),
                                    nameFilter.begin(), nameFilter.end(),
                                    [](wchar_t a, wchar_t b) { return towlower(a) == towlower(b); }) != className.end())
                    {
                        result.push_back(clsid);
                        Utils::Logger::Get().LogInfo("Found CLSID: " + Utils::StringUtils::WStringToString(className) +
                                                     " -> " + Utils::StringUtils::GuidToString(clsid));
                    }
                }

                subKeyNameLen = 256;
                index++;
            }

            RegCloseKey(hKeyClsid);
            return result;
        }

        std::wstring RegistryScanner::GetClassName(const GUID& clsid)
        {
            wchar_t clsidStr[40] = {0};
            StringFromGUID(clsid, clsidStr);

            std::wstring subKey = L"CLSID\\" + std::wstring(clsidStr);
            return ReadRegistryValue(HKEY_CLASSES_ROOT, subKey, L"");
        }

        bool RegistryScanner::IsClsidRegistered(const GUID& clsid)
        {
            wchar_t clsidStr[40] = {0};
            StringFromGUID(clsid, clsidStr);

            std::wstring subKey = L"CLSID\\" + std::wstring(clsidStr);
            HKEY hKey;
            LONG result = RegOpenKeyExW(HKEY_CLASSES_ROOT, subKey.c_str(), 0, KEY_READ, &hKey);
            if (result == ERROR_SUCCESS)
            {
                RegCloseKey(hKey);
                return true;
            }
            return false;
        }

        std::wstring RegistryScanner::GetServerPath(const GUID& clsid)
        {
            wchar_t clsidStr[40] = {0};
            StringFromGUID(clsid, clsidStr);

            // Try InProcServer32 first
            std::wstring subKey = L"CLSID\\" + std::wstring(clsidStr) + L"\\InProcServer32";
            std::wstring path = ReadRegistryValue(HKEY_CLASSES_ROOT, subKey, L"");

            if (path.empty())
            {
                // Try LocalServer32
                subKey = L"CLSID\\" + std::wstring(clsidStr) + L"\\LocalServer32";
                path = ReadRegistryValue(HKEY_CLASSES_ROOT, subKey, L"");
            }

            return path;
        }

    } // namespace Core
} // namespace SecureKeyRetriever
