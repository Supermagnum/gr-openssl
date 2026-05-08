// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef GNURADIO4_OPENSSL_SYMENC_HPP
#define GNURADIO4_OPENSSL_SYMENC_HPP

#include <gnuradio-4.0/Block.hpp>
#include <gnuradio-4.0/BlockRegistry.hpp>
#include <gnuradio-4.0/Message.hpp>
#include <gnuradio-4.0/Port.hpp>
#include <gnuradio-4.0/Tensor.hpp>
#include <gnuradio-4.0/annotated.hpp>
#include <gnuradio-4.0/meta/utils.hpp>
#include <gnuradio-4.0/openssl/detail/Helpers.hpp>
#include <gnuradio-4.0/openssl/detail/OpenSslAliases.hpp>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <cstdint>
#include <algorithm>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace gnuradio4::openssl {

GR_REGISTER_BLOCK(gnuradio4::openssl::SymEnc)

struct SymEnc : gr::Block<SymEnc, gr::NoTagPropagation> {
    using Description =
        gr::Doc<"PDU symmetric encryption via OpenSSL EVP (matches gr-crypto sym_enc): random IV each session, iv in PDU metadata on first fragment, finalize on 'final'.">;

    gr::MsgPortIn               msg_pdu_in{};
    gr::MsgPortOut              msg_pdu_out{};
    gr::Annotated<std::string, "cipher_name", gr::Doc<"OpenSSL EVP cipher name e.g. aes-128-cbc">>              cipher_name{};
    gr::Annotated<bool, "padding", gr::Doc<"PKCS#7 padding (typical true for CBC)">>                             padding           = true;
    gr::Annotated<gr::Tensor<std::uint8_t>, "symmetric_key", gr::Doc<"Raw key bytes; length must match cipher">> symmetric_key;

    GR_MAKE_REFLECTABLE(SymEnc, msg_pdu_in, msg_pdu_out, cipher_name, padding, symmetric_key);

    const EVP_CIPHER*            _cipher = nullptr;
    detail::CipherCtxPtr         _ctx{EVP_CIPHER_CTX_new()};
    unsigned long               _pduCtr = 0U;
    std::vector<unsigned char> _secret{};
    std::vector<unsigned char> _iv{};
    std::vector<unsigned char> _outBuf{};

    [[nodiscard]] bool loadCipherSettings() noexcept {
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
        return true;
    }

    [[nodiscard]] bool initCipherState() noexcept {
        if (!_cipher || !_ctx) [[unlikely]] {
            return false;
        }
        if (1 != RAND_bytes(_iv.data(), static_cast<int>(_iv.size()))) [[unlikely]] {
            return false;
        }
        if (1 != EVP_EncryptInit_ex(_ctx.get(), _cipher, nullptr, _secret.data(), _iv.data())) [[unlikely]] {
            return false;
        }
        if (1 != EVP_CIPHER_CTX_set_padding(_ctx.get(), padding.value ? 1 : 0)) [[unlikely]] {
            return false;
        }
        return true;
    }

    void start() {
        if (!loadCipherSettings() || !initCipherState()) {
            this->requestStop();
        }
    }

    void settingsChanged(const gr::property_map& /* oldSettings */, const gr::property_map& newSettings) {
        if (!newSettings.contains("cipher_name") && !newSettings.contains("padding") && !newSettings.contains("symmetric_key")) [[likely]] {
            return;
        }
        EVP_CIPHER_CTX_free(_ctx.release());
        _ctx.reset(EVP_CIPHER_CTX_new());
        _pduCtr = 0;
        _cipher = nullptr;
        if (!loadCipherSettings() || !initCipherState()) [[unlikely]] {
            this->requestStop();
        }
    }

    void stop() {
        EVP_CIPHER_CTX_free(_ctx.release());
        _secret.assign(_secret.size(), 0U);
    }

    [[nodiscard]] gr::work::Status processBulk() noexcept { return gr::work::Status::OK; }

    void processMessages(gr::MsgPortIn& port, std::span<const gr::Message> messages) {
        if (std::addressof(port) != std::addressof(msg_pdu_in)) [[unlikely]] {
            return;
        }
        if (!_cipher || !_ctx) [[unlikely]] {
            return;
        }
        for (const gr::Message& msg : messages) {
            if (!msg.data.has_value()) {
                continue;
            }
            const gr::property_map& body       = msg.data.value();
            const auto*               pduBits = detail::tensorBytesFromMap(body, std::string_view("pdu_data"));
            if (pduBits == nullptr || pduBits->empty()) {
                throw std::runtime_error("SymEnc: pdu_data missing or empty");
            }
            gr::property_map outBody(body.get_allocator());
            for (const auto& [k, v] : body) {
                outBody.emplace(k, v);
            }
            const unsigned char* inPtr   = pduBits->data();
            const int            inLen  = static_cast<int>(pduBits->size());
            _outBuf.resize(static_cast<std::size_t>(inLen + 2 * EVP_CIPHER_get_block_size(_cipher)));
            int nout = 0;
            int tmp  = 0;
            if (1 != EVP_EncryptUpdate(_ctx.get(), _outBuf.data(), &tmp, inPtr, inLen)) {
                throw std::runtime_error("SymEnc: EVP_EncryptUpdate failed");
            }
            nout += tmp;
            if (_pduCtr == 0U) {
                std::vector<std::uint8_t> ivOut(_iv.begin(), _iv.end());
                outBody.insert_or_assign(gr::convert_string_domain(std::string_view("iv")), gr::pmt::Value(gr::Tensor<std::uint8_t>(ivOut)));
            }
            ++_pduCtr;
            if (detail::mapHas(body, std::string_view("final"))) {
                if (1 != EVP_EncryptFinal_ex(_ctx.get(), _outBuf.data() + nout, &tmp)) {
                    throw std::runtime_error("SymEnc: EVP_EncryptFinal_ex failed");
                }
                nout += tmp;
                if (!initCipherState()) {
                    throw std::runtime_error("SymEnc: re-init after final failed");
                }
                _pduCtr = 0U;
            }
            std::vector<std::uint8_t> outBytes(static_cast<std::size_t>(nout));
            std::copy_n(_outBuf.begin(), static_cast<std::size_t>(nout), outBytes.begin());
            outBody.insert_or_assign(gr::convert_string_domain(std::string_view("pdu_data")), gr::pmt::Value(gr::Tensor<std::uint8_t>(std::move(outBytes))));
            gr::Message outgoing;
            outgoing.cmd  = gr::message::Command::Notify;
            outgoing.data = std::move(outBody);
            auto w        = msg_pdu_out.streamWriter().template reserve<gr::SpanReleasePolicy::ProcessAll>(1UZ);
            w[0]          = std::move(outgoing);
            w.publish(1UZ);
        }
    }
};

} // namespace gnuradio4::openssl

#endif
