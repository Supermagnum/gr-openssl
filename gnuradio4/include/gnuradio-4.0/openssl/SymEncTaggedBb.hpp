// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef GNURADIO4_OPENSSL_SYMENCTAGGEDBB_HPP
#define GNURADIO4_OPENSSL_SYMENCTAGGEDBB_HPP

#include <gnuradio-4.0/Block.hpp>
#include <gnuradio-4.0/BlockRegistry.hpp>
#include <gnuradio-4.0/Tag.hpp>
#include <gnuradio-4.0/Tensor.hpp>
#include <gnuradio-4.0/annotated.hpp>
#include <gnuradio-4.0/meta/utils.hpp>
#include <gnuradio-4.0/openssl/detail/Helpers.hpp>
#include <gnuradio-4.0/openssl/detail/OpenSslAliases.hpp>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace gnuradio4::openssl {

GR_REGISTER_BLOCK(gnuradio4::openssl::SymEncTaggedBb)

struct SymEncTaggedBb : gr::Block<SymEncTaggedBb, gr::NoTagPropagation> {
    using Description = gr::Doc<"Symmetric encryption on tagged-byte streams: PDU length from length_tag_key; iv tag on first byte; finalized on incoming 'final' tag; matches gr-crypto sym_enc_tagged_bb.">;

    gr::PortIn<std::uint8_t>                                     in{};
    gr::PortOut<std::uint8_t>                                     out{};
    gr::Annotated<std::string, "cipher_name">                  cipher_name{};
    gr::Annotated<bool, "padding">                            padding           = true;
    gr::Annotated<gr::Tensor<std::uint8_t>, "symmetric_key"> symmetric_key;
    gr::Annotated<std::string, "length_tag_key", gr::Doc<"Tag key storing PDU byte length">> length_tag_key = std::string("packet_len");

    GR_MAKE_REFLECTABLE(SymEncTaggedBb, in, out, cipher_name, padding, symmetric_key, length_tag_key);

    const EVP_CIPHER*            _cipher   = nullptr;
    detail::CipherCtxPtr        _ctx{EVP_CIPHER_CTX_new()};
    unsigned long               _pktCtr   = 0U;
    std::vector<unsigned char> _secret{};
    std::vector<unsigned char> _iv{};

    [[nodiscard]] bool loadAndInit() noexcept {
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
        if (1 != RAND_bytes(_iv.data(), static_cast<int>(_iv.size()))) {
            return false;
        }
        if (1 != EVP_EncryptInit_ex(_ctx.get(), _cipher, nullptr, _secret.data(), _iv.data())) {
            return false;
        }
        return 1 == EVP_CIPHER_CTX_set_padding(_ctx.get(), padding.value ? 1 : 0);
    }

    void start() {
        if (!loadAndInit()) {
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
        _pktCtr = 0U;
        if (!loadAndInit()) [[unlikely]] {
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
        bool haveFinal = false;
        for (const auto& [relIndex, mapRef] : inSamples.tags(inSamples.size())) {
            (void)relIndex;
            if (detail::mapHas(mapRef.get(), std::string_view("final"))) {
                haveFinal = true;
                break;
            }
        }
        const unsigned char* inPtr = reinterpret_cast<const unsigned char*>(&inSamples[0]);
        unsigned char*       outPtr = reinterpret_cast<unsigned char*>(&outSamples[0]);
        int                  nout   = 0;
        if (1 != EVP_EncryptUpdate(_ctx.get(), outPtr, &nout, inPtr, static_cast<int>(inSamples.size()))) {
            return gr::work::Status::ERROR;
        }
        if (_pktCtr == 0U) {
            gr::property_map tm;
            std::vector<std::uint8_t> ivOut(_iv.begin(), _iv.end());
            tm.insert_or_assign(gr::convert_string_domain(std::string_view("iv")), gr::pmt::Value(gr::Tensor<std::uint8_t>(std::move(ivOut))));
            outSamples.publishTag(tm, 0UZ);
        }
        ++_pktCtr;
        if (haveFinal) {
            int tmp = 0;
            if (1 != EVP_EncryptFinal_ex(_ctx.get(), outPtr + nout, &tmp)) {
                return gr::work::Status::ERROR;
            }
            nout += tmp;
            gr::property_map fm;
            fm.insert_or_assign(gr::convert_string_domain(std::string_view("final")), gr::pmt::Value(true));
            outSamples.publishTag(fm, 0UZ);
            if (!loadAndInit()) {
                return gr::work::Status::ERROR;
            }
            _pktCtr = 0U;
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
