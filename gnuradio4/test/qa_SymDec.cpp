// SPDX-License-Identifier: GPL-3.0-or-later
#include <boost/ut.hpp>

#include <gnuradio-4.0/Message.hpp>
#include <gnuradio-4.0/Port.hpp>
#include <gnuradio-4.0/Sequence.hpp>
#include <gnuradio-4.0/Tensor.hpp>
#include <gnuradio-4.0/Value.hpp>
#include <gnuradio-4.0/openssl/SymDec.hpp>
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

const boost::ut::suite<"SymDec"> SymDecTests = [] {
    "SymDec restores plaintext chained after SymEnc (aes-128-cbc)"_test = [] {
        std::vector<std::uint8_t> key(16U, 0x11U);
        std::vector<std::uint8_t> plain({'d', 'a', 't', 'a'});
        gnuradio4::openssl::SymEnc enc(
            gr::property_map{{"cipher_name", std::string("aes-128-cbc")}, {"symmetric_key", gr::Tensor<std::uint8_t>(key)}});
        gnuradio4::openssl::SymDec dec(
            gr::property_map{{"cipher_name", std::string("aes-128-cbc")}, {"symmetric_key", gr::Tensor<std::uint8_t>(key)}});
        enc.init(std::make_shared<gr::Sequence>());
        dec.init(std::make_shared<gr::Sequence>());
        enc.start();
        dec.start();
        gr::MsgPortOut src;
        gr::MsgPortIn  sink;
        expect(src.connect(enc.msg_pdu_in).has_value());
        expect(enc.msg_pdu_out.connect(dec.msg_pdu_in).has_value());
        expect(dec.msg_pdu_out.connect(sink).has_value());
        gr::property_map req;
        req[gr::convert_string_domain(std::string_view("pdu_data"))] = gr::pmt::Value(gr::Tensor<std::uint8_t>(plain));
        req[gr::convert_string_domain(std::string_view("final"))]    = gr::pmt::Value(true);
        pushNotify(src, std::move(req));
        enc.processScheduledMessages();
        dec.processScheduledMessages();
        expect(eq(sink.streamReader().available(), 1UZ));
        auto reader = sink.streamReader().template get<gr::SpanReleasePolicy::ProcessAll>(1UZ);
        expect(reader[0].data.has_value());
        const auto* out = gnuradio4::openssl::detail::tensorBytesFromMap(reader[0].data.value(), std::string_view("pdu_data"));
        expect(out != nullptr);
        expect(eq(out->size(), plain.size()));
        for (std::size_t i = 0; i < plain.size(); ++i) {
            expect(eq(out->data()[i], plain[i]));
        }
        expect(reader.consume(reader.size()));
    };
};

int main() { return boost::ut::cfg<boost::ut::override>.run(); }
