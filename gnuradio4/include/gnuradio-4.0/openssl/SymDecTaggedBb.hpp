// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef GNURADIO4_OPENSSL_SYMDECTAGGEDBB_HPP
#define GNURADIO4_OPENSSL_SYMDECTAGGEDBB_HPP

#include <gnuradio-4.0/Block.hpp>
#include <gnuradio-4.0/BlockRegistry.hpp>
#include <gnuradio-4.0/Tag.hpp>
#include <gnuradio-4.0/Tensor.hpp>
#include <gnuradio-4.0/annotated.hpp>
#include <gnuradio-4.0/meta/utils.hpp>
#include <gnuradio-4.0/openssl/detail/Helpers.hpp>
#include <gnuradio-4.0/openssl/detail/OpenSslAliases.hpp>

#include <openssl/evp.h>

#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace gnuradio4::openssl {

GR_REGISTER_BLOCK(gnuradio4::openssl::SymDecTaggedBb)

struct SymDecTaggedBb : gr::Block<SymDecTaggedBb, gr::NoTagPropagation> {
    using Description = gr::Doc<"Symmetric decryption for tagged streams (pairs with SymEncTaggedBb); consumes iv and final tags from stream.">;

    gr::PortIn<std::uint8_t>                                     in{};
    gr::PortOut<std::uint8_t>                                     out{};
    gr::Annotated<std::string, "cipher_name">                  cipher_name{};
    gr::Annotated<bool, "padding">                            padding           = true;
    gr::Annotated<gr::Tensor<std::uint8_t>, "symmetric_key"> symmetric_key;
    gr::Annotated<std::string, "length_tag_key">              length_tag_key = std::string("packet_len");

    GR_MAKE_REFLECTABLE(SymDecTaggedBb, in, out, cipher_name, padding, symmetric_key, length_tag_key);

    const EVP_CIPHER*            _cipher   = nullptr;
    detail::CipherCtxPtr        _ctx{EVP_CIPHER_CTX_new()};
    bool                        _haveIv  = false;
    std::vector<unsigned char> _secret{};
    std::vector<unsigned char> _iv{};

    [[nodiscard]] bool loadCipher() noexcept {
        if (!_ctx) [[unlikely]] {
            return false;
        }
        const EVP_CIPHER* ciph = EVP_get_cipherbyname(cipher_name.value.c_str());
        if (!ciph) [[unlikely]] {
            return false;
        }
        if (symmetric_key.value.size() != static_cast<std::size_t>(EVP_CIPHER_get_key_length(ciph))) [[unlikely]] {
            return false;
        }
        _cipher = ciph;
        _secret.assign(symmetric_key.value.begin(), symmetric_key.value.end());
        _iv.assign(static_cast<std::size_t>(EVP_CIPHER_get_iv_length(ciph)), 0U);
        const int ivLen = EVP_CIPHER_get_iv_length(ciph);
        _haveIv         = (ivLen == 0);
        if (_haveIv) {
            if (1 != EVP_DecryptInit_ex(_ctx.get(), _cipher, nullptr, _secret.data(), ivLen == 0 ? nullptr : _iv.data())) {
                return false;
            }
            return 1 == EVP_CIPHER_CTX_set_padding(_ctx.get(), padding.value ? 1 : 0);
        }
        return true;
    }

    [[nodiscard]] bool initDecrypt() noexcept {
        if (!_cipher) {
            return false;
        }
        if (1 != EVP_DecryptInit_ex(_ctx.get(), _cipher, nullptr, _secret.data(), _iv.data())) {
            return false;
        }
        return 1 == EVP_CIPHER_CTX_set_padding(_ctx.get(), padding.value ? 1 : 0);
    }

    void start() {
        if (!loadCipher()) {
            this->requestStop();
        }
    }

    void settingsChanged(const gr::property_map&, const gr::property_map& newSettings) {
        if (!newSettings.contains("cipher_name") && !newSettings.contains("padding") && !newSettings.contains("symmetric_key")) [[likely]] {
            return;
        }
        EVP_CIPHER_CTX_free(_ctx.release());
        _ctx.reset(EVP_CIPHER_CTX_new());
        _cipher  = nullptr;
        _haveIv = false;
        if (!loadCipher()) [[unlikely]] {
            this->requestStop();
        }
    }

    void stop() {
        EVP_CIPHER_CTX_free(_ctx.release());
        _secret.assign(_secret.size(), 0U);
    }

    [[nodiscard]] gr::work::Status processBulk(gr::InputSpanLike auto& inSamples, gr::OutputSpanLike auto& outSamples) {
        if (!_cipher || !_ctx) [[unlikely]] {
            return gr::work::Status::ERROR;
        }
        std::optional<gr::Size_t> pduLen;
        for (const auto& [relIndex, mapRef] : inSamples.tags()) {
            (void)relIndex;
            pduLen = detail::readPduLength(mapRef.get(), std::string_view(length_tag_key.value));
            if (pduLen) {
                break;
            }
        }
        if (!pduLen || *pduLen != inSamples.size()) [[unlikely]] {
            return gr::work::Status::ERROR;
        }
        const int ivLen = EVP_CIPHER_get_iv_length(_cipher);
        for (const auto& [relIndex, mapRef] : inSamples.tags(inSamples.size())) {
            (void)relIndex;
            const auto* ivT = detail::tensorBytesFromMap(mapRef.get(), std::string_view("iv"));
            if (ivT != nullptr && ivT->size() == static_cast<std::size_t>(ivLen)) {
                if (_haveIv && ivLen != 0) {
                    unsigned char* outPtr = reinterpret_cast<unsigned char*>(&outSamples[0]);
                    int            slack  = 0;
                    if (1 != EVP_DecryptFinal_ex(_ctx.get(), outPtr, &slack)) {
                        return gr::work::Status::ERROR;
                    }
                    if (slack != 0) {
                        throw std::runtime_error("SymDecTaggedBb: IV rollover produced bytes (missing final tag?)");
                    }
                }
                _iv.assign(ivT->begin(), ivT->end());
                _haveIv = true;
                if (!initDecrypt()) {
                    return gr::work::Status::ERROR;
                }
                break;
            }
        }
        bool haveFinal = false;
        for (const auto& [relIndex, mapRef] : inSamples.tags(inSamples.size())) {
            (void)relIndex;
            if (detail::mapHas(mapRef.get(), std::string_view("final"))) {
                haveFinal = true;
                break;
            }
        }
        if (!_haveIv && ivLen != 0) {
            throw std::runtime_error("SymDecTaggedBb: decrypt without iv");
        }
        const unsigned char* inPtr = reinterpret_cast<const unsigned char*>(&inSamples[0]);
        unsigned char*       outPtr = reinterpret_cast<unsigned char*>(&outSamples[0]);
        int                  nout   = 0;
        if (1 != EVP_DecryptUpdate(_ctx.get(), outPtr, &nout, inPtr, static_cast<int>(inSamples.size()))) {
            return gr::work::Status::ERROR;
        }
        if (haveFinal) {
            int tmp = 0;
            if (1 != EVP_DecryptFinal_ex(_ctx.get(), outPtr + nout, &tmp)) {
                return gr::work::Status::ERROR;
            }
            nout += tmp;
            const int ziv = EVP_CIPHER_get_iv_length(_cipher);
            _haveIv       = (ziv == 0);
        }
        if (static_cast<std::size_t>(nout) > outSamples.size()) [[unlikely]] {
            return gr::work::Status::ERROR;
        }
        outSamples.publish(static_cast<std::size_t>(nout));
        return gr::work::Status::OK;
    }
};

} // namespace gnuradio4::openssl

#endif
