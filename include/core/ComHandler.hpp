// Copyright (c) 2026 Eren Taha Akkuş
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include <windows.h>
#include <objbase.h>
#include <comdef.h>
#include <vector>
#include <string>
#include <memory>
#include <functional>
#include <optional>

namespace SecureKeyRetriever
{
    namespace Core
    {
        /**
         * @brief High-level COM handler for interacting with Elevator COM servers.
         * 
         * This class manages COM initialization, proxy blanket settings, and
         * the low-level vtable calls to invoke DecryptData on undocumented
         * COM interfaces (IElevator, IElevator2, Edge variants, Avast variants).
         * 
         * Uses manual vtable slot addressing to support different interface
         * layouts (Chrome vs Avast vs Edge) without relying on brittle MIDL
         * generated headers.
         */
        class ComHandler
        {
        public:
            /**
             * @brief Constructs a ComHandler instance.
             * 
             * Note: Does NOT initialize COM automatically; call Initialize()
             * before any decryption operations.
             */
            ComHandler();

            /**
             * @brief Destructor. Automatically uninitializes COM if initialized.
             */
            ~ComHandler();

            // Disable copy and move (COM state is not trivially copyable)
            ComHandler(const ComHandler&) = delete;
            ComHandler& operator=(const ComHandler&) = delete;
            ComHandler(ComHandler&&) = delete;
            ComHandler& operator=(ComHandler&&) = delete;

            /**
             * @brief Initializes the COM library for the current thread.
             * 
             * @return true if COM was initialized successfully (or already initialized).
             * @return false on failure.
             */
            bool Initialize();

            /**
             * @brief Decrypts data using a specific CLSID and IID combination.
             * 
             * This is the primary method for decrypting Chrome/Brave/Vivaldi
             * encrypted data.
             * 
             * @param encryptedData The encrypted binary data (v20 format).
             * @param clsid The CLSID of the Elevator COM server.
             * @param iid The IID of the primary interface (typically IElevator).
             * @param iid_v2 Optional second IID (typically IElevator2 for Chrome 144+).
             * @param isAvast If true, uses Avast's vtable layout (slot 12 for DecryptData).
             * @param isEdge If true, uses Edge-specific interface chain.
             * @return std::vector<uint8_t> Decrypted plaintext.
             * @throws std::runtime_error on any COM or decryption failure.
             */
            std::vector<uint8_t> DecryptData(
                const std::vector<uint8_t>& encryptedData,
                const GUID& clsid,
                const GUID& iid,
                const std::optional<GUID>& iid_v2 = std::nullopt,
                bool isAvast = false,
                bool isEdge = false
            );

            /**
             * @brief Specific decryptor for Microsoft Edge variants.
             * 
             * Edge uses a different interface inheritance chain. This method
             * attempts both IEdgeElevator and IEdgeElevator2.
             * 
             * @param encryptedData The encrypted binary data.
             * @param clsid The CLSID (typically CLSID_EdgeElevator).
             * @param iid The primary IID for Edge.
             * @param iid_v2 Optional IID for Edge v2 (if applicable).
             * @return std::vector<uint8_t> Decrypted plaintext.
             */
            std::vector<uint8_t> DecryptEdgeData(
                const std::vector<uint8_t>& encryptedData,
                const GUID& clsid,
                const GUID& iid,
                const std::optional<GUID>& iid_v2 = std::nullopt
            );

            /**
             * @brief Applies standard proxy blanket settings to a COM interface pointer.
             * 
             * Required for cross-process COM calls to local servers.
             * 
             * @param pUnknown Pointer to the IUnknown interface of the COM object.
             */
            void SetProxyBlanket(IUnknown* pUnknown);

            /**
             * @brief Checks if COM is currently initialized.
             */
            bool IsInitialized() const { return m_comInitialized; }

        private:
            bool m_comInitialized;

            /**
             * @brief Converts binary data to a BSTR for COM transmission.
             * 
             * @param data The binary data.
             * @return BSTR Allocated BSTR (caller must free with SysFreeString).
             */
            BSTR CreateBstrFromData(const std::vector<uint8_t>& data);

            /**
             * @brief Extracts binary data from a BSTR after COM decryption.
             * 
             * @param bstr The BSTR containing decrypted data.
             * @return std::vector<uint8_t> The extracted data.
             */
            std::vector<uint8_t> ExtractDataFromBstr(BSTR bstr);

            /**
             * @brief Internal helper to call DecryptData via manual vtable offset.
             * 
             * This is the core engine that handles different vtable slot layouts
             * for different vendors (Chrome slot 3, Avast slot 12, etc.).
             * 
             * @param pUnknown Pointer to the object's IUnknown.
             * @param slotIndex The vtable slot index (0-based) for DecryptData.
             * @param bstrEnc Encrypted BSTR.
             * @param pbstrDec Output decrypted BSTR.
             * @param pComErr Output COM error code.
             * @return HRESULT The result of the COM call.
             */
            HRESULT InvokeDecryptVtable(
                IUnknown* pUnknown,
                int slotIndex,
                BSTR bstrEnc,
                BSTR* pbstrDec,
                DWORD* pComErr
            );
        };

    } // namespace Core
} // namespace SecureKeyRetriever
