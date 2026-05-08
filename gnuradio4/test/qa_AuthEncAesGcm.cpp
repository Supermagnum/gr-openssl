// SPDX-License-Identifier: GPL-3.0-or-later
#include <boost/ut.hpp>

#include <gnuradio-4.0/Message.hpp>
#include <gnuradio-4.0/Port.hpp>
#include <gnuradio-4.0/Sequence.hpp>
#include <gnuradio-4.0/Tensor.hpp>
#include <gnuradio-4.0/Value.hpp>
#include <gnuradio-4.0/openssl/AuthDecAesGcm.hpp>
#include <gnuradio-4.0/openssl/AuthEncAesGcm.hpp>
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

const boost::ut::suite<"AuthEncAesGcm"> AuthEncAesGcmTests = [] {
    "AES-256-GCM emits iv and auth_tag on final"_test = [] {
        std::vector<std::uint8_t> key(32U, 3U);
        gnuradio4::openssl::AuthEncAesGcm enc(gr::property_map{{"symmetric_key", gr::Tensor<std::uint8_t>(key)}, {"aes_key_bytes", 32}, {"gcm_iv_bytes", 12}});
        enc.init(std::make_shared<gr::Sequence>());
        enc.start();
        gr::MsgPortOut src;
        gr::MsgPortIn  sink;
        expect(src.connect(enc.msg_pdu_in).has_value());
        expect(enc.msg_pdu_out.connect(sink).has_value());
        gr::property_map req;
        req[gr::convert_string_domain(std::string_view("pdu_data"))] = gr::pmt::Value(gr::Tensor<std::uint8_t>(std::vector<std::uint8_t>{1U, 2U, 3U}));
        req[gr::convert_string_domain(std::string_view("final"))]    = gr::pmt::Value(true);
        pushNotify(src, std::move(req));
        enc.processScheduledMessages();
        expect(eq(sink.streamReader().available(), 1UZ));
        auto               reader = sink.streamReader().template get<gr::SpanReleasePolicy::ProcessAll>(1UZ);
        const gr::Message& reply  = reader[0];
        expect(reply.data.has_value());
        const auto* iv  = gnuradio4::openssl::detail::tensorBytesFromMap(reply.data.value(), std::string_view("iv"));
        const auto* tag = gnuradio4::openssl::detail::tensorBytesFromMap(reply.data.value(), std::string_view("auth_tag"));
        expect(iv != nullptr);
        expect(eq(iv->size(), 12UZ));
        expect(tag != nullptr);
        expect(eq(tag->size(), 16UZ));
        expect(reader.consume(reader.size()));
    };
};

int main() { return boost::ut::cfg<boost::ut::override>.run(); }
