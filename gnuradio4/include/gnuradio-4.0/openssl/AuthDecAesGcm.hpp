// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef GNURADIO4_OPENSSL_AUTHDECAESGCM_HPP
#define GNURADIO4_OPENSSL_AUTHDECAESGCM_HPP

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
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace gnuradio4::openssl {

GR_REGISTER_BLOCK(gnuradio4::openssl::AuthDecAesGcm)

struct AuthDecAesGcm : gr::Block<AuthDecAesGcm, gr::NoTagPropagation> {
    using Description =
        gr::Doc<"AES-GCM decryption: verifies auth_tag via OpenSSL SET_TAG/Final semantics; emits auth_ok=true/false; removes iv from forwarded metadata once applied.">;

    gr::MsgPortIn               msg_pdu_in{};
    gr::MsgPortOut              msg_pdu_out{};
    gr::Annotated<gr::Tensor<std::uint8_t>, "symmetric_key"> symmetric_key;
    gr::Annotated<int, "aes_key_bytes", gr::Doc<"16, 24, or 32">>    aes_key_bytes = 32;
    gr::Annotated<int, "gcm_iv_bytes", gr::Doc<"typical 12">>       gcm_iv_bytes  = 12;

    GR_MAKE_REFLECTABLE(AuthDecAesGcm, msg_pdu_in, msg_pdu_out, symmetric_key, aes_key_bytes, gcm_iv_bytes);

    static constexpr unsigned kTagBytes = 16U;

    const EVP_CIPHER*            _cipher  = nullptr;
    detail::CipherCtxPtr       _ctx{EVP_CIPHER_CTX_new()};
    unsigned long               _pduCtr  = 0U;
    bool                        _haveIv  = false;
    std::vector<unsigned char> _secret{};
    std::vector<unsigned char> _iv{};
    std::vector<unsigned char> _work{};

    [[nodiscard]] bool pickCipherAndLoadKey() noexcept {
        switch (aes_key_bytes.value) {
        case 16:
            _cipher = EVP_aes_128_gcm();
            break;
        case 24:
            _cipher = EVP_aes_192_gcm();
            break;
        case 32:
            _cipher = EVP_aes_256_gcm();
            break;
        default:
            return false;
        }
        if (symmetric_key.value.size() != static_cast<std::size_t>(aes_key_bytes.value)) {
            return false;
        }
        if (_ctx == nullptr) {
            return false;
        }
        _secret.assign(symmetric_key.value.begin(), symmetric_key.value.end());
        _iv.assign(static_cast<std::size_t>(EVP_CIPHER_get_iv_length(_cipher)), 0U);
        return true;
    }

    [[nodiscard]] bool initDecryptState() noexcept {
        if (!_cipher) {
            return false;
        }
        if (1 != EVP_DecryptInit_ex(_ctx.get(), _cipher, nullptr, nullptr, nullptr)) {
            return false;
        }
        if (1 != EVP_CIPHER_CTX_ctrl(_ctx.get(), EVP_CTRL_GCM_SET_IVLEN, gcm_iv_bytes.value, nullptr)) {
            return false;
        }
        if (1 != EVP_DecryptInit_ex(_ctx.get(), nullptr, nullptr, _secret.data(), _iv.data())) {
            return false;
        }
        return true;
    }

    void start() {
        if (!pickCipherAndLoadKey()) {
            this->requestStop();
        }
    }

    void settingsChanged(const gr::property_map&, const gr::property_map& newSettings) {
        if (!newSettings.contains("symmetric_key") && !newSettings.contains("aes_key_bytes") && !newSettings.contains("gcm_iv_bytes")) [[likely]] {
            return;
        }
        EVP_CIPHER_CTX_free(_ctx.release());
        _ctx.reset(EVP_CIPHER_CTX_new());
        _cipher  = nullptr;
        _haveIv = false;
        _pduCtr  = 0;
        if (!pickCipherAndLoadKey()) [[unlikely]] {
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
        const int cipherIvCapacity = EVP_CIPHER_get_iv_length(_cipher);
        for (const gr::Message& msg : messages) {
            if (!msg.data.has_value()) {
                continue;
            }
            const gr::property_map& body = msg.data.value();
            gr::property_map         work(body.get_allocator());
            for (const auto& [k, v] : body) {
                work.emplace(k, v);
            }
            const auto* ivT = detail::tensorBytesFromMap(body, std::string_view("iv"));
            if (ivT != nullptr && ivT->size() == static_cast<std::size_t>(cipherIvCapacity)) {
                if (_haveIv) [[unlikely]] {
                    throw std::runtime_error("AuthDecAesGcm: overlapping session (iv before tag)");
                }
                _iv.assign(ivT->begin(), ivT->end());
                detail::eraseKey(work, std::string_view("iv"));
                _haveIv = true;
                if (!initDecryptState()) {
                    throw std::runtime_error("AuthDecAesGcm: DecryptInit failed");
                }
            }
            if (detail::tensorBytesFromMap(body, std::string_view("aad")) != nullptr && detail::mapHas(body, std::string_view("aad"))) {
                const auto* aad = detail::tensorBytesFromMap(body, std::string_view("aad"));
                if (_haveIv && aad != nullptr && !aad->empty()) {
                    int n = 0;
                    if (1 != EVP_DecryptUpdate(_ctx.get(), nullptr, &n, aad->data(), static_cast<int>(aad->size()))) {
                        throw std::runtime_error("AuthDecAesGcm: AAD decrypt update failed");
                    }
                    if (n != 0) {
                        throw std::runtime_error("AuthDecAesGcm: unexpected AAD output");
                    }
                }
            }
            const auto* pduBits = detail::tensorBytesFromMap(work, std::string_view("pdu_data"));
            if (pduBits == nullptr || pduBits->empty()) {
                throw std::runtime_error("AuthDecAesGcm: pdu_data missing or empty");
            }
            if (!_haveIv) {
                throw std::runtime_error("AuthDecAesGcm: missing iv before ciphertext");
            }
            ++_pduCtr;
            _work.resize(static_cast<std::size_t>(pduBits->size() + static_cast<std::size_t>(EVP_CIPHER_get_block_size(_cipher))));
            int nout = 0;
            if (1 != EVP_DecryptUpdate(_ctx.get(), _work.data(), &nout, pduBits->data(), static_cast<int>(pduBits->size()))) {
                throw std::runtime_error("AuthDecAesGcm: decrypt update failed");
            }
            bool authOk                                   = false;
            int  finalBytes                              = nout;
            bool hadAuthVerification                    = false;
            if (detail::mapHas(work, std::string_view("auth_tag"))) {
                const auto* tagTb = detail::tensorBytesFromMap(work, std::string_view("auth_tag"));
                if (tagTb == nullptr || tagTb->size() != kTagBytes) {
                    throw std::runtime_error("AuthDecAesGcm: invalid auth_tag size");
                }
                if (1 != EVP_CIPHER_CTX_ctrl(_ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(kTagBytes), const_cast<unsigned char*>(tagTb->data()))) {
                    throw std::runtime_error("AuthDecAesGcm: SET_TAG failed");
                }
                int slack = 0;
                const int fr = EVP_DecryptFinal_ex(_ctx.get(), _work.data() + nout, &slack);
                authOk                   = (fr == 1);
                finalBytes              = nout + slack;
                hadAuthVerification       = true;
                detail::eraseKey(work, std::string_view("auth_tag"));
                _haveIv = false;
                _pduCtr = 0U;
                work.insert_or_assign(gr::convert_string_domain(std::string_view("auth_ok")), gr::pmt::Value(authOk));
            }
            std::vector<std::uint8_t> plain;
            if (hadAuthVerification && authOk) {
                plain.assign(_work.begin(), _work.begin() + finalBytes);
            } else if (!hadAuthVerification) {
                plain.assign(_work.begin(), _work.begin() + nout);
            }
            work.insert_or_assign(gr::convert_string_domain(std::string_view("pdu_data")), gr::pmt::Value(gr::Tensor<std::uint8_t>(std::move(plain))));
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
