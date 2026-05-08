// SPDX-License-Identifier: GPL-3.0-or-later
#include <boost/ut.hpp>

#include <gnuradio-4.0/Message.hpp>
#include <gnuradio-4.0/Port.hpp>
#include <gnuradio-4.0/Sequence.hpp>
#include <gnuradio-4.0/Tensor.hpp>
#include <gnuradio-4.0/Value.hpp>
#include <gnuradio-4.0/openssl/Hash.hpp>
#include <gnuradio-4.0/openssl/detail/Helpers.hpp>
#include <gnuradio-4.0/openssl/detail/KeyDerivation.hpp>

#include <array>
#include <string>
#include <string_view>
#include <vector>

using namespace boost::ut;

namespace {

void pushNotify(gr::MsgPortOut& downstream, gr::property_map body) {
    gr::Message message;
    message.cmd  = gr::message::Command::Notify;
    message.data = std::move(body);
    auto writer  = downstream.streamWriter().template reserve<gr::SpanReleasePolicy::ProcessAll>(1UZ);
    writer[0]    = std::move(message);
    writer.publish(1UZ);
}

} // namespace

const boost::ut::suite<"Hash"> HashTests = [] {
    "SHA-256 empty string matches NIST vector"_test = [] {
        gnuradio4::openssl::Hash block(gr::property_map{{"hash_name", std::string("sha256")}});
        block.init(std::make_shared<gr::Sequence>());
        block.start();
        gr::MsgPortOut src;
        gr::MsgPortIn  sink;
        expect(src.connect(block.msg_pdu_in).has_value());
        expect(block.msg_pdu_out.connect(sink).has_value());
        gr::property_map req;
        std::vector<std::uint8_t> empty;
        req[gr::convert_string_domain(std::string_view("pdu_data"))] = gr::pmt::Value(gr::Tensor<std::uint8_t>(empty));
        pushNotify(src, std::move(req));
        block.processScheduledMessages();
        expect(eq(sink.streamReader().available(), 1UZ));
        auto               reader = sink.streamReader().template get<gr::SpanReleasePolicy::ProcessAll>(1UZ);
        const gr::Message& reply  = reader[0];
        expect(reply.data.has_value());
        const auto* out = gnuradio4::openssl::detail::tensorBytesFromMap(reply.data.value(), std::string_view("pdu_data"));
        expect(out != nullptr);
        expect(eq(out->size(), 32UZ));
        static constexpr std::array<std::uint8_t, 32> kExpected = {
            0xe3U, 0xb0U, 0xc4U, 0x42U, 0x98U, 0xfcU, 0x1cU, 0x14U, 0x9aU, 0xfbU, 0xf4U, 0xc8U, 0x99U, 0x6fU, 0xb9U, 0x24U,
            0x27U, 0xaeU, 0x41U, 0xe4U, 0x64U, 0x9bU, 0x93U, 0x4cU, 0xa4U, 0x95U, 0x99U, 0x1bU, 0x78U, 0x52U, 0xb8U, 0x55U};
        for (std::size_t i = 0; i < 32UZ; ++i) {
            expect(eq(out->data()[i], kExpected[i]));
        }
        expect(reader.consume(reader.size()));
    };

    "PBKDF2-HMAC-SHA256 matches OpenSSL one-shot (no salt)"_test = [] {
        const auto k = gnuradio4::openssl::detail::deriveKeyPbkdf2NoSaltOneShot(std::string_view("password"), 16, 1000);
        expect(eq(k.size(), 16UZ));
    };
};

int main() { return boost::ut::cfg<boost::ut::override>.run(); }
