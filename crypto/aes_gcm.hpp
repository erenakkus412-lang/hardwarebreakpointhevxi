

#pragma once

#include "../core/common.hpp"
#include <bcrypt.h>
#include <vector>
#include <optional>

namespace Crypto {

    class AesGcm {
    public:
        static std::optional<std::vector<uint8_t>> Decrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& encryptedData);
    };

}
