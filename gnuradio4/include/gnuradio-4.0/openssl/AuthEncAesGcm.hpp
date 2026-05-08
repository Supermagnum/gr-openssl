// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef GNURADIO4_OPENSSL_AUTHENCAESGCM_HPP
#define GNURADIO4_OPENSSL_AUTHENCAESGCM_HPP

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

#include <algorithm>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace gnuradio4::openssl {

GR_REGISTER_BLOCK(gnuradio4::openssl::AuthEncAesGcm)

struct AuthEncAesGcm : gr::Block<AuthEncAesGcm, gr::NoTagPropagation> {
    using Description = gr::Doc<"Authenticated encryption AES-GCM: optional AAD, iv on first pdu fragment (length gcm_iv_bytes), auth_tag (16 bytes) on 'final'.">;

    gr::MsgPortIn               msg_pdu_in{};
    gr::MsgPortOut              msg_pdu_out{};
    gr::Annotated<gr::Tensor<std::uint8_t>, "symmetric_key">                                             symmetric_key;
    gr::Annotated<int, "aes_key_bytes", gr::Doc<"16, 24, or 32">>                                     aes_key_bytes     = 32;
    gr::Annotated<int, "gcm_iv_bytes", gr::Doc<"typical 12">>                                          gcm_iv_bytes      = 12;

    GR_MAKE_REFLECTABLE(AuthEncAesGcm, msg_pdu_in, msg_pdu_out, symmetric_key, aes_key_bytes, gcm_iv_bytes);

    static constexpr unsigned kTagBytes = 16U;

    const EVP_CIPHER*            _cipher = nullptr;
    detail::CipherCtxPtr       _ctx{EVP_CIPHER_CTX_new()};
    unsigned long               _pduCtr  = 0U;
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
        if (gcm_iv_bytes.value <= 0 || _ctx == nullptr) {
            return false;
        }
        _secret.assign(symmetric_key.value.begin(), symmetric_key.value.end());
        _iv.assign(static_cast<std::size_t>(EVP_CIPHER_get_iv_length(_cipher)), 0U);
        return true;
    }

    [[nodiscard]] bool initGcmEncrypt() noexcept {
        if (!_cipher) {
            return false;
        }
        if (1 != RAND_bytes(_iv.data(), static_cast<int>(_iv.size()))) {
            return false;
        }
        if (1 != EVP_EncryptInit_ex(_ctx.get(), _cipher, nullptr, nullptr, nullptr)) {
            return false;
        }
        if (1 != EVP_CIPHER_CTX_ctrl(_ctx.get(), EVP_CTRL_GCM_SET_IVLEN, gcm_iv_bytes.value, nullptr)) {
            return false;
        }
        if (1 != EVP_EncryptInit_ex(_ctx.get(), nullptr, nullptr, _secret.data(), _iv.data())) {
            return false;
        }
        return true;
    }

    void start() {
        if (!pickCipherAndLoadKey() || !initGcmEncrypt()) {
            this->requestStop();
        }
    }

    void settingsChanged(const gr::property_map&, const gr::property_map& newSettings) {
        if (!newSettings.contains("symmetric_key") && !newSettings.contains("aes_key_bytes") && !newSettings.contains("gcm_iv_bytes")) [[likely]] {
            return;
        }
        EVP_CIPHER_CTX_free(_ctx.release());
        _ctx.reset(EVP_CIPHER_CTX_new());
        _cipher = nullptr;
        _pduCtr = 0;
        if (!pickCipherAndLoadKey() || !initGcmEncrypt()) [[unlikely]] {
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
            gr::property_map          out(body.get_allocator());
            for (const auto& [k, v] : body) {
                out.emplace(k, v);
            }
            if (detail::tensorBytesFromMap(body, std::string_view("aad")) != nullptr && detail::mapHas(body, std::string_view("aad"))) {
                const auto* aad = detail::tensorBytesFromMap(body, std::string_view("aad"));
                if (aad != nullptr && !aad->empty()) {
                    int n = 0;
                    if (1 != EVP_EncryptUpdate(_ctx.get(), nullptr, &n, aad->data(), static_cast<int>(aad->size()))) {
                        throw std::runtime_error("AuthEncAesGcm: AAD update failed");
                    }
                    if (n != 0) {
                        throw std::runtime_error("AuthEncAesGcm: unexpected AAD ciphertext");
                    }
                }
            }
            const auto* pduBits = detail::tensorBytesFromMap(body, std::string_view("pdu_data"));
            if (pduBits == nullptr || pduBits->empty()) {
                throw std::runtime_error("AuthEncAesGcm: pdu_data missing or empty");
            }
            _work.resize(static_cast<std::size_t>(pduBits->size() + static_cast<std::size_t>(EVP_CIPHER_get_block_size(_cipher))));
            int nout = 0;
            if (1 != EVP_EncryptUpdate(_ctx.get(), _work.data(), &nout, pduBits->data(), static_cast<int>(pduBits->size()))) {
                throw std::runtime_error("AuthEncAesGcm: EncryptUpdate failed");
            }
            if (_pduCtr == 0U) {
                std::vector<std::uint8_t> ivOut(_iv.begin(), _iv.begin() + static_cast<std::ptrdiff_t>(gcm_iv_bytes.value));
                out.insert_or_assign(gr::convert_string_domain(std::string_view("iv")), gr::pmt::Value(gr::Tensor<std::uint8_t>(std::move(ivOut))));
            }
            ++_pduCtr;
            std::vector<std::uint8_t> ct(static_cast<std::size_t>(nout));
            std::copy_n(_work.begin(), static_cast<std::size_t>(nout), ct.begin());
            out.insert_or_assign(gr::convert_string_domain(std::string_view("pdu_data")), gr::pmt::Value(gr::Tensor<std::uint8_t>(std::move(ct))));
            if (detail::mapHas(body, std::string_view("final"))) {
                int extra = 0;
                _work.resize(static_cast<std::size_t>(EVP_CIPHER_get_block_size(_cipher)));
                if (1 != EVP_EncryptFinal_ex(_ctx.get(), _work.data(), &extra)) {
                    throw std::runtime_error("AuthEncAesGcm: EncryptFinal failed");
                }
                if (extra != 0) {
                    throw std::runtime_error("AuthEncAesGcm: unexpected post-GCM ciphertext");
                }
                std::array<unsigned char, kTagBytes> tag{};
                if (1 != EVP_CIPHER_CTX_ctrl(_ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag.size()), tag.data())) {
                    throw std::runtime_error("AuthEncAesGcm: GET_TAG failed");
                }
                std::vector<std::uint8_t> tg(tag.begin(), tag.end());
                out.insert_or_assign(gr::convert_string_domain(std::string_view("auth_tag")), gr::pmt::Value(gr::Tensor<std::uint8_t>(std::move(tg))));
                _pduCtr = 0U;
                if (!initGcmEncrypt()) {
                    throw std::runtime_error("AuthEncAesGcm: re-init failed");
                }
            }
            gr::Message outgoing;
            outgoing.cmd  = gr::message::Command::Notify;
            outgoing.data = std::move(out);
            auto w        = msg_pdu_out.streamWriter().template reserve<gr::SpanReleasePolicy::ProcessAll>(1UZ);
            w[0]          = std::move(outgoing);
            w.publish(1UZ);
        }
    }
};

} // namespace gnuradio4::openssl

#endif
