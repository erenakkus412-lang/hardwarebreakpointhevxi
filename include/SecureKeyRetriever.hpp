// Copyright (c) 2026 Eren Taha Akkuş
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#ifndef SECURE_KEY_RETRIEVER_HPP
#define SECURE_KEY_RETRIEVER_HPP

/**
 * @file SecureKeyRetriever.hpp
 * @brief Ana başlık dosyası. Tüm modülleri tek bir noktadan sunar.
 * 
 * Bu kütüphane, Windows üzerinde App-Bound Encryption (ABE) anahtarlarını
 * COM aracılığıyla çözmek için kullanılır. Chrome, Edge, Brave, Vivaldi,
 * Opera, Arc ve diğer Chromium tabanlı tarayıcıları destekler.
 */

#include <windows.h>
#include <objbase.h>
#include <vector>
#include <optional>
#include <string>
#include <memory>

// Alt modüller
#include "core/ComHandler.hpp"
#include "core/RegistryScanner.hpp"
#include "core/MemoryScanner.hpp"
#include "core/CryptoHelper.hpp"
#include "utils/StringUtils.hpp"
#include "utils/GuidUtils.hpp"
#include "utils/Logger.hpp"

namespace SecureKeyRetriever
{

    /**
     * @brief Ana sınıf. Tüm işlevleri tek bir noktadan sunar.
     * 
     * Kullanım:
     * @code
     *   SecureKeyRetriever::SecureKeyRetriever retriever;
     *   auto result = retriever.AutoDiscover(encryptedKey, knownPairs);
     *   if (result.success) { ... }
     * @endcode
     */
    class SecureKeyRetriever
    {
    public:
        /**
         * @brief Yapıcı. COM'u başlatır ve alt modülleri oluşturur.
         * @throw std::runtime_error COM başlatılamazsa.
         */
        SecureKeyRetriever();

        /**
         * @brief Yıkıcı. COM'u temizler.
         */
        ~SecureKeyRetriever();

        // ============================================================
        // Temel Çözme İşlevleri
        // ============================================================

        /**
         * @brief Belirtilen CLSID ve IID ile şifreli veriyi çözer.
         * @param encryptedData Şifrelenmiş veri (v20 formatında cookie veya key)
         * @param clsid Çözücü COM sınıfının CLSID'si
         * @param iid Kullanılacak arayüzün IID'si (genellikle IElevator)
         * @param iid_v2 İsteğe bağlı: IElevator2 IID'si (Chrome 144+ için)
         * @param isEdgeVariant Edge tarayıcı mı?
         * @param isAvastVariant Avast tarayıcı mı?
         * @return Çözülmüş veri (düz metin)
         * @throw std::runtime_error Çözme başarısız olursa.
         */
        std::vector<uint8_t> DecryptKey(
            const std::vector<uint8_t>& encryptedData,
            const GUID& clsid,
            const GUID& iid,
            const std::optional<GUID>& iid_v2 = std::nullopt,
            bool isEdgeVariant = false,
            bool isAvastVariant = false
        );

        /**
         * @brief Edge tarayıcı için özel çözme işlevi.
         * @param encryptedData Şifrelenmiş veri
         * @param clsid Edge çözücü sınıfının CLSID'si
         * @param iid Edge arayüzünün IID'si
         * @return Çözülmüş veri
         */
        std::vector<uint8_t> DecryptKeyEdge(
            const std::vector<uint8_t>& encryptedData,
            const GUID& clsid,
            const GUID& iid
        );

        // ============================================================
        // Otomatik Keşif ve Brute-Force
        // ============================================================

        /**
         * @brief Otomatik keşif sonucu için yapı.
         */
        struct DiscoveryResult
        {
            bool success = false;               ///< Başarılı mı?
            std::vector<uint8_t> decryptedData; ///< Çözülmüş veri
            GUID usedClsid = {};                ///< Kullanılan CLSID
            GUID usedIid = {};                  ///< Kullanılan IID
            std::string method;                 ///< Keşif yöntemi ("Known pair", "Auto-discovered", "Edge", "Avast")
            std::string error;                  ///< Hata mesajı (başarısızsa)
        };

        /**
         * @brief Bilinen CLSID/IID çiftlerini dener, ardından sistemdeki tüm
         *        "Elevator" sınıflarını tarayarak brute-force yapar.
         * @param encryptedData Şifrelenmiş veri
         * @param knownPairs Bilinen CLSID/IID çiftleri listesi
         * @param tryEdge Edge variant'larını dene
         * @param tryAvast Avast variant'larını dene
         * @param timeoutMs Maksimum çalışma süresi (milisaniye)
         * @return DiscoveryResult
         */
        DiscoveryResult AutoDiscover(
            const std::vector<uint8_t>& encryptedData,
            const std::vector<std::pair<GUID, GUID>>& knownPairs,
            bool tryEdge = true,
            bool tryAvast = true,
            int timeoutMs = 30000
        );

        /**
         * @brief Başarılı bir keşif sonucunu dosyaya kaydeder (önbellek).
         * @param filename Dosya adı
         * @param result Kaydedilecek sonuç
         */
        void SaveCache(const std::string& filename, const DiscoveryResult& result);

        // ============================================================
        // Yardımcı İşlevler
        // ============================================================

        /**
         * @brief Sistemde kayıtlı tüm "Elevator" CLSID'lerini bulur.
         * @param nameFilter Sınıf adı filtresi (varsayılan: "Elevator")
         * @return GUID listesi
         */
        std::vector<GUID> FindElevatorClsids(const std::wstring& nameFilter = L"Elevator");

        /**
         * @brief Belirli bir CLSID'nin kayıtlı sınıf adını döndürür.
         * @param clsid GUID
         * @return Sınıf adı (wstring)
         */
        std::wstring GetClassName(const GUID& clsid);

    private:
        std::unique_ptr<Core::ComHandler> m_comHandler;
        std::unique_ptr<Core::RegistryScanner> m_regScanner;
        std::unique_ptr<Core::MemoryScanner> m_memScanner;
        std::unique_ptr<Core::CryptoHelper> m_cryptoHelper;
        std::unique_ptr<Utils::Logger> m_logger;
        bool m_initialized = false;
    };

} // namespace SecureKeyRetriever

#endif // SECURE_KEY_RETRIEVER_HPP
