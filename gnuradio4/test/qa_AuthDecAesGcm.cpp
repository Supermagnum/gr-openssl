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

const boost::ut::suite<"AuthDecAesGcm"> AuthDecAesGcmTests = [] {
    "AES-GCM round trip verifies auth_ok and plaintext"_test = [] {
        std::vector<std::uint8_t> key(32U, 5U);
        std::vector<std::uint8_t> pt{9U, 8U, 7U};
        gnuradio4::openssl::AuthEncAesGcm enc(
            gr::property_map{{"symmetric_key", gr::Tensor<std::uint8_t>(key)}, {"aes_key_bytes", 32}, {"gcm_iv_bytes", 12}});
        gnuradio4::openssl::AuthDecAesGcm dec(
            gr::property_map{{"symmetric_key", gr::Tensor<std::uint8_t>(key)}, {"aes_key_bytes", 32}, {"gcm_iv_bytes", 12}});
        enc.init(std::make_shared<gr::Sequence>());
        dec.init(std::make_shared<gr::Sequence>());
        enc.start();
        dec.start();
        gr::MsgPortOut src;
        gr::MsgPortIn  endSink;
        expect(src.connect(enc.msg_pdu_in).has_value());
        expect(enc.msg_pdu_out.connect(dec.msg_pdu_in).has_value());
        expect(dec.msg_pdu_out.connect(endSink).has_value());
        gr::property_map req;
        req[gr::convert_string_domain(std::string_view("pdu_data"))] = gr::pmt::Value(gr::Tensor<std::uint8_t>(pt));
        req[gr::convert_string_domain(std::string_view("final"))]    = gr::pmt::Value(true);
        pushNotify(src, std::move(req));
        enc.processScheduledMessages();
        dec.processScheduledMessages();
        expect(eq(endSink.streamReader().available(), 1UZ));
        auto               reader = endSink.streamReader().template get<gr::SpanReleasePolicy::ProcessAll>(1UZ);
        const gr::Message& reply  = reader[0];
        expect(reply.data.has_value());
        const auto& okEntry =
            reply.data.value().at(gr::convert_string_domain(std::string_view("auth_ok")));
        const auto* okBool = okEntry.get_if<bool>();
        expect(okBool != nullptr);
        expect(*okBool == true);
        const auto* outPt = gnuradio4::openssl::detail::tensorBytesFromMap(reply.data.value(), std::string_view("pdu_data"));
        expect(outPt != nullptr);
        expect(eq(outPt->size(), pt.size()));
        for (std::size_t i = 0; i < pt.size(); ++i) {
            expect(eq(outPt->data()[i], pt[i]));
        }
        expect(reader.consume(reader.size()));
    };

    "Corrupted authentication tag yields auth_ok false"_test = [] {
        std::vector<std::uint8_t> key(16U, 2U);
        gnuradio4::openssl::AuthEncAesGcm enc(
            gr::property_map{{"symmetric_key", gr::Tensor<std::uint8_t>(key)}, {"aes_key_bytes", 16}, {"gcm_iv_bytes", 12}});
        enc.init(std::make_shared<gr::Sequence>());
        enc.start();
        gr::MsgPortOut src;
        gr::MsgPortIn  cap;
        expect(src.connect(enc.msg_pdu_in).has_value());
        expect(enc.msg_pdu_out.connect(cap).has_value());
        gr::property_map ereq;
        ereq[gr::convert_string_domain(std::string_view("pdu_data"))] =
            gr::pmt::Value(gr::Tensor<std::uint8_t>(std::vector<std::uint8_t>{0xDU, 0xEU}));
        ereq[gr::convert_string_domain(std::string_view("final"))] = gr::pmt::Value(true);
        pushNotify(src, ereq);
        enc.processScheduledMessages();
        expect(eq(cap.streamReader().available(), 1UZ));
        auto             span = cap.streamReader().template get<gr::SpanReleasePolicy::ProcessAll>(1UZ);
        gr::property_map hacked(span[0].data.value().get_allocator());
        for (const auto& [k, v] : span[0].data.value()) {
            hacked.emplace(k, v);
        }
        expect(span.consume(span.size()));
        const auto rawTag =
            hacked.at(gr::convert_string_domain(std::string_view("auth_tag")));
        const auto* tagTensor = rawTag.get_if<gr::Tensor<std::uint8_t>>();
        expect(tagTensor != nullptr);
        std::vector<std::uint8_t> tg(tagTensor->begin(), tagTensor->end());
        tg[0] = static_cast<std::uint8_t>(tg[0] ^ 0xFEU);
        hacked.insert_or_assign(gr::convert_string_domain(std::string_view("auth_tag")), gr::pmt::Value(gr::Tensor<std::uint8_t>(tg)));

        gnuradio4::openssl::AuthDecAesGcm dec(
            gr::property_map{{"symmetric_key", gr::Tensor<std::uint8_t>(key)}, {"aes_key_bytes", 16}, {"gcm_iv_bytes", 12}});
        dec.init(std::make_shared<gr::Sequence>());
        dec.start();
        gr::MsgPortOut atk;
        gr::MsgPortIn  sink;
        expect(atk.connect(dec.msg_pdu_in).has_value());
        expect(dec.msg_pdu_out.connect(sink).has_value());
        pushNotify(atk, std::move(hacked));
        dec.processScheduledMessages();
        expect(eq(sink.streamReader().available(), 1UZ));
        auto rr = sink.streamReader().template get<gr::SpanReleasePolicy::ProcessAll>(1UZ);
        const auto okv = rr[0].data.value().at(gr::convert_string_domain(std::string_view("auth_ok")));
        const auto p   = okv.get_if<bool>();
        expect(p != nullptr);
        expect(*p == false);
        expect(rr.consume(rr.size()));
    };
};

int main() { return boost::ut::cfg<boost::ut::override>.run(); }
