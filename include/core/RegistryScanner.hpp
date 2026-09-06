// Copyright (c) 2026 Eren Taha Akkuş
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include <windows.h>
#include <objbase.h>
#include <vector>
#include <string>
#include <optional>
#include <memory>

namespace SecureKeyRetriever
{
    namespace Core
    {
        /**
         * @brief Windows Registry scanner for discovering COM class IDs and interface IDs.
         * 
         * This class provides functionality to scan the Windows Registry (HKCR\CLSID)
         * to find registered COM classes matching specific name patterns, and retrieve
         * their associated CLSIDs and metadata.
         */
        class RegistryScanner
        {
        public:
            /**
             * @brief Default constructor.
             */
            RegistryScanner() = default;

            /**
             * @brief Virtual destructor.
             */
            virtual ~RegistryScanner() = default;

            // Disable copy and move
            RegistryScanner(const RegistryScanner&) = delete;
            RegistryScanner& operator=(const RegistryScanner&) = delete;
            RegistryScanner(RegistryScanner&&) = delete;
            RegistryScanner& operator=(RegistryScanner&&) = delete;

            /**
             * @brief Scans the registry for CLSIDs whose class name contains the specified filter string.
             * 
             * @param nameFilter The substring to search for in class names (case-insensitive).
             *                   If empty, returns all CLSIDs (not recommended).
             * @return std::vector<GUID> List of matching CLSIDs.
             */
            std::vector<GUID> FindClsidsByName(const std::wstring& nameFilter = L"Elevator");

            /**
             * @brief Retrieves the default class name (ProgID or description) for a given CLSID.
             * 
             * @param clsid The CLSID to query.
             * @return std::wstring The class name, or empty string if not found.
             */
            std::wstring GetClassName(const GUID& clsid);

            /**
             * @brief Checks if a specific CLSID is registered in the system.
             * 
             * @param clsid The CLSID to check.
             * @return true If the CLSID exists in the registry.
             * @return false Otherwise.
             */
            bool IsClsidRegistered(const GUID& clsid);

            /**
             * @brief Retrieves the server type (InProcServer32, LocalServer32, etc.) for a CLSID.
             * 
             * @param clsid The CLSID to query.
             * @return std::wstring The server path, or empty if not found.
             */
            std::wstring GetServerPath(const GUID& clsid);

        private:
            /**
             * @brief Converts a wide-string CLSID representation to a GUID structure.
             * 
             * @param str The wide-string representation (e.g., "{12345678-...}").
             * @param guid Output GUID.
             * @return true If conversion succeeded.
             * @return false Otherwise.
             */
            bool StringToGuid(const std::wstring& str, GUID& guid);

            /**
             * @brief Reads a registry value under a given key.
             * 
             * @param hKeyRoot Root key (e.g., HKEY_CLASSES_ROOT).
             * @param subKey Subkey path.
             * @param valueName Value name (null for default).
             * @return std::wstring The value data, or empty if failed.
             */
            std::wstring ReadRegistryValue(HKEY hKeyRoot, const std::wstring& subKey, const std::wstring& valueName = L"");
        };

    } // namespace Core
} // namespace SecureKeyRetriever
