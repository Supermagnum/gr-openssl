// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef GNURADIO4_OPENSSL_DETAIL_KEYDERIVATION_HPP
#define GNURADIO4_OPENSSL_DETAIL_KEYDERIVATION_HPP

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace gnuradio4::openssl::detail {

[[nodiscard]] inline std::vector<std::uint8_t> deriveKeyPbkdf2NoSaltOneShot(std::string_view password, int keyLenBytes, int iterations = 20000) {
    std::vector<std::uint8_t> key(static_cast<std::size_t>(keyLenBytes), 0U);
    if (keyLenBytes <= 0) {
        throw std::runtime_error("deriveKeyPbkdf2NoSaltOneShot: invalid key length");
    }
    if (1 != PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()), nullptr, 0, iterations, EVP_sha256(), keyLenBytes, key.data())) {
        throw std::runtime_error("PKCS5_PBKDF2_HMAC failed");
    }
    return key;
}

[[nodiscard]] inline std::vector<std::uint8_t> deriveKeyPbkdf2HmacSha256(std::string_view password, std::span<const unsigned char> salt, int iterations,
    int keyLenBytes) {
    std::vector<std::uint8_t> key(static_cast<std::size_t>(keyLenBytes), 0U);
    if (keyLenBytes <= 0) {
        throw std::runtime_error("deriveKeyPbkdf2HmacSha256: invalid key length");
    }
    if (1 != PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()), salt.data(), static_cast<int>(salt.size()), iterations, EVP_sha256(),
            keyLenBytes, key.data())) {
        throw std::runtime_error("PKCS5_PBKDF2_HMAC failed");
    }
    return key;
}

[[nodiscard]] inline std::vector<std::uint8_t> randomKeyBytes(int keyLenBytes) {
    if (keyLenBytes <= 0) {
        throw std::runtime_error("randomKeyBytes: invalid key length");
    }
    std::vector<std::uint8_t> key(static_cast<std::size_t>(keyLenBytes), 0U);
    if (1 != RAND_bytes(key.data(), keyLenBytes)) {
        throw std::runtime_error("RAND_bytes failed");
    }
    return key;
}

} // namespace gnuradio4::openssl::detail

#endif
