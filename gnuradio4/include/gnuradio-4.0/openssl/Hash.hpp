// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef GNURADIO4_OPENSSL_HASH_HPP
#define GNURADIO4_OPENSSL_HASH_HPP

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

namespace gnuradio4::openssl {

GR_REGISTER_BLOCK(gnuradio4::openssl::Hash)

struct Hash : gr::Block<Hash, gr::NoTagPropagation> {
    using Description = gr::Doc<"One-shot hash digest of pdu_data PDU bytes via OpenSSL EVP_MD (re-init after each PDU). Data field is replaced by digest bytes.">;

    gr::MsgPortIn            msg_pdu_in{};
    gr::MsgPortOut           msg_pdu_out{};
    gr::Annotated<std::string, "hash_name", gr::Doc<"OpenSSL digest name e.g. sha256, sha512">> hash_name{};

    GR_MAKE_REFLECTABLE(Hash, msg_pdu_in, msg_pdu_out, hash_name);

    const EVP_MD*         _md   = nullptr;
    detail::MdCtxPtr     _ctx{EVP_MD_CTX_new()};
    std::vector<unsigned char> _outBuf{};

    [[nodiscard]] bool reloadDigest() noexcept {
        _md = EVP_get_digestbyname(hash_name.value.c_str());
        if (!_md || !_ctx) [[unlikely]] {
            return false;
        }
        if (1 != EVP_DigestInit_ex(_ctx.get(), _md, nullptr)) [[unlikely]] {
            return false;
        }
        return true;
    }

    void start() {
        if (!reloadDigest()) {
            this->requestStop();
        }
    }

    void settingsChanged(const gr::property_map&, const gr::property_map& newSettings) {
        if (!newSettings.contains("hash_name")) [[likely]] {
            return;
        }
        if (!reloadDigest()) [[unlikely]] {
            this->requestStop();
        }
    }

    [[nodiscard]] gr::work::Status processBulk() noexcept { return gr::work::Status::OK; }

    void processMessages(gr::MsgPortIn& port, std::span<const gr::Message> messages) {
        if (std::addressof(port) != std::addressof(msg_pdu_in)) [[unlikely]] {
            return;
        }
        if (!_md || !_ctx) [[unlikely]] {
            return;
        }
        for (const gr::Message& msg : messages) {
            if (!msg.data.has_value()) {
                continue;
            }
            gr::property_map          work(msg.data.value().get_allocator());
            for (const auto& [k, v] : msg.data.value()) {
                work.emplace(k, v);
            }
            const auto* pduBits = detail::tensorBytesFromMap(work, std::string_view("pdu_data"));
            if (pduBits == nullptr) {
                throw std::runtime_error("Hash: pdu_data missing");
            }
            const unsigned char* inPtr   = pduBits->data();
            const size_t         inLen  = pduBits->size();
            _outBuf.resize(static_cast<std::size_t>(EVP_MD_size(_md)));
            if (1 != EVP_DigestInit_ex(_ctx.get(), _md, nullptr)) {
                throw std::runtime_error("Hash: DigestInit failed");
            }
            if (1 != EVP_DigestUpdate(_ctx.get(), inPtr, inLen)) {
                throw std::runtime_error("Hash: DigestUpdate failed");
            }
            unsigned int digLen = 0U;
            if (1 != EVP_DigestFinal_ex(_ctx.get(), _outBuf.data(), &digLen)) {
                throw std::runtime_error("Hash: DigestFinal failed");
            }
            if (1 != EVP_DigestInit_ex(_ctx.get(), _md, nullptr)) {
                throw std::runtime_error("Hash: DigestInit (reset) failed");
            }
            std::vector<std::uint8_t> digest(static_cast<std::size_t>(digLen));
            std::copy_n(_outBuf.begin(), static_cast<std::size_t>(digLen), digest.begin());
            work.insert_or_assign(gr::convert_string_domain(std::string_view("pdu_data")), gr::pmt::Value(gr::Tensor<std::uint8_t>(std::move(digest))));
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
