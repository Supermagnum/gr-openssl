// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef GNURADIO4_OPENSSL_SYMDEC_HPP
#define GNURADIO4_OPENSSL_SYMDEC_HPP

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

#include <algorithm>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace gnuradio4::openssl {

GR_REGISTER_BLOCK(gnuradio4::openssl::SymDec)

struct SymDec : gr::Block<SymDec, gr::NoTagPropagation> {
    using Description = gr::Doc<"PDU symmetric decryption (pairs with SymEnc): reads iv from metadata, handles 'final'.">;

    gr::MsgPortIn               msg_pdu_in{};
    gr::MsgPortOut              msg_pdu_out{};
    gr::Annotated<std::string, "cipher_name", gr::Doc<"OpenSSL EVP cipher name e.g. aes-128-cbc">> cipher_name{};
    gr::Annotated<bool, "padding">                                                                           padding           = true;
    gr::Annotated<gr::Tensor<std::uint8_t>, "symmetric_key", gr::Doc<"Raw key bytes">>                       symmetric_key;

    GR_MAKE_REFLECTABLE(SymDec, msg_pdu_in, msg_pdu_out, cipher_name, padding, symmetric_key);

    const EVP_CIPHER*            _cipher = nullptr;
    detail::CipherCtxPtr         _ctx{EVP_CIPHER_CTX_new()};
    bool                        _haveIv  = false;
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
        const int ivLen = EVP_CIPHER_get_iv_length(ciph);
        _haveIv         = (ivLen == 0);
        if (_haveIv) {
            if (1 != EVP_DecryptInit_ex(_ctx.get(), _cipher, nullptr, _secret.data(), ivLen == 0 ? nullptr : _iv.data())) {
                return false;
            }
            if (1 != EVP_CIPHER_CTX_set_padding(_ctx.get(), padding.value ? 1 : 0)) {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] bool decryptInitOnly() noexcept {
        if (!_cipher || !_ctx) [[unlikely]] {
            return false;
        }
        if (1 != EVP_DecryptInit_ex(_ctx.get(), _cipher, nullptr, _secret.data(), _iv.data())) [[unlikely]] {
            return false;
        }
        return 1 == EVP_CIPHER_CTX_set_padding(_ctx.get(), padding.value ? 1 : 0);
    }

    void start() {
        if (!loadCipherSettings()) {
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
        if (!loadCipherSettings()) [[unlikely]] {
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
            const gr::property_map& body   = msg.data.value();
            const auto*               ivTb = detail::tensorBytesFromMap(body, std::string_view("iv"));
            gr::property_map          work(body.get_allocator());
            for (const auto& [k, v] : body) {
                work.emplace(k, v);
            }
            const int ivLen = EVP_CIPHER_get_iv_length(_cipher);
            if (ivTb != nullptr && ivTb->size() == static_cast<std::size_t>(ivLen)) {
                if (_haveIv && ivLen != 0) {
                    _outBuf.resize(static_cast<std::size_t>(2ULL * EVP_CIPHER_get_block_size(_cipher)), 0U);
                    int slack = 0;
                    if (1 != EVP_DecryptFinal_ex(_ctx.get(), _outBuf.data(), &slack)) {
                        throw std::runtime_error("SymDec: unexpected Final before iv rollover");
                    }
                    if (slack != 0) {
                        throw std::runtime_error("SymDec: iv rollover produced trailing plaintext");
                    }
                }
                _iv.assign(ivTb->begin(), ivTb->end());
                detail::eraseKey(work, std::string_view("iv"));
                _haveIv = true;
                if (!decryptInitOnly()) {
                    throw std::runtime_error("SymDec: DecryptInit failed");
                }
            }
            const auto* pduBits = detail::tensorBytesFromMap(work, std::string_view("pdu_data"));
            if (pduBits == nullptr || pduBits->empty()) {
                throw std::runtime_error("SymDec: pdu_data missing or empty");
            }
            if (!_haveIv && ivLen != 0) {
                throw std::runtime_error("SymDec: missing iv before ciphertext");
            }
            const unsigned char* inPtr   = pduBits->data();
            const int            inLen  = static_cast<int>(pduBits->size());
            _outBuf.resize(static_cast<std::size_t>(inLen + 2ULL * static_cast<unsigned>(EVP_CIPHER_get_block_size(_cipher))));
            int nout = 0;
            int tmp  = 0;
            if (1 != EVP_DecryptUpdate(_ctx.get(), _outBuf.data(), &tmp, inPtr, inLen)) {
                throw std::runtime_error("SymDec: EVP_DecryptUpdate failed");
            }
            nout = tmp;
            if (detail::mapHas(body, std::string_view("final"))) {
                if (1 != EVP_DecryptFinal_ex(_ctx.get(), _outBuf.data() + nout, &tmp)) {
                    throw std::runtime_error("SymDec: EVP_DecryptFinal_ex failed");
                }
                nout += tmp;
                const int ziv = EVP_CIPHER_get_iv_length(_cipher);
                _haveIv       = (ziv == 0);
            }
            std::vector<std::uint8_t> outBytes(static_cast<std::size_t>(nout));
            std::copy_n(_outBuf.begin(), static_cast<std::size_t>(nout), outBytes.begin());
            work.insert_or_assign(gr::convert_string_domain(std::string_view("pdu_data")), gr::pmt::Value(gr::Tensor<std::uint8_t>(std::move(outBytes))));
            gr::Message outgoing;
            outgoing.cmd  = gr::message::Command::Notify;
            outgoing.data = std::move(work);
            auto w        = msg_pdu_out.streamWriter().template reserve<gr::SpanReleasePolicy::ProcessAll>(1UZ);
            w[0]          = std::move(outgoing);
            w.publish(1UZ);
        }
    }
};

} // namespace gnuradio4::openssl

#endif
