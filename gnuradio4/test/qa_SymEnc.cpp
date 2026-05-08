// SPDX-License-Identifier: GPL-3.0-or-later
#include <boost/ut.hpp>

#include <gnuradio-4.0/Message.hpp>
#include <gnuradio-4.0/Port.hpp>
#include <gnuradio-4.0/Sequence.hpp>
#include <gnuradio-4.0/Tensor.hpp>
#include <gnuradio-4.0/Value.hpp>
#include <gnuradio-4.0/openssl/SymEnc.hpp>
#include <gnuradio-4.0/openssl/detail/Helpers.hpp>

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

const boost::ut::suite<"SymEnc"> SymEncTests = [] {
    "SymEnc produces iv and ciphertext for aes-128-cbc with final"_test = [] {
        std::vector<std::uint8_t> key(16U, 0x9AU);
        std::vector<std::uint8_t> plain({'s', 'e', 'c', 'r', 'e', 't'});
        gnuradio4::openssl::SymEnc enc(
            gr::property_map{{"cipher_name", std::string("aes-128-cbc")}, {"symmetric_key", gr::Tensor<std::uint8_t>(key)}});
        enc.init(std::make_shared<gr::Sequence>());
        enc.start();
        gr::MsgPortOut toEnc;
        gr::MsgPortIn  fromEnc;
        expect(toEnc.connect(enc.msg_pdu_in).has_value());
        expect(enc.msg_pdu_out.connect(fromEnc).has_value());
        gr::property_map req;
        req[gr::convert_string_domain(std::string_view("pdu_data"))] = gr::pmt::Value(gr::Tensor<std::uint8_t>(plain));
        req[gr::convert_string_domain(std::string_view("final"))]    = gr::pmt::Value(true);
        pushNotify(toEnc, std::move(req));
        enc.processScheduledMessages();
        expect(eq(fromEnc.streamReader().available(), 1UZ));
        auto               reader = fromEnc.streamReader().template get<gr::SpanReleasePolicy::ProcessAll>(1UZ);
        const gr::Message& reply  = reader[0];
        expect(reply.data.has_value());
        const auto* iv     = gnuradio4::openssl::detail::tensorBytesFromMap(reply.data.value(), std::string_view("iv"));
        const auto* cipher = gnuradio4::openssl::detail::tensorBytesFromMap(reply.data.value(), std::string_view("pdu_data"));
        expect(iv != nullptr);
        expect(eq(iv->size(), 16UZ));
        expect(cipher != nullptr);
        expect(cipher->size() > plain.size());
        expect(reader.consume(reader.size()));
    };
};

int main() { return boost::ut::cfg<boost::ut::override>.run(); }
