// SPDX-License-Identifier: GPL-3.0-or-later
#include <boost/ut.hpp>

#include <gnuradio-4.0/Tensor.hpp>
#include <gnuradio-4.0/openssl/detail/Helpers.hpp>

#include <string_view>

using namespace boost::ut;

namespace {

[[nodiscard]] gr::property_map makePktLen(gr::Size_t n) {
    gr::property_map m;
    m.insert_or_assign(gr::convert_string_domain(std::string_view("packet_len")), gr::pmt::Value(static_cast<std::uint64_t>(n)));
    return m;
}

} // namespace

const boost::ut::suite<"SymDecTaggedBb"> SymDecTaggedBbTests = [] {
    "tag map iv/final helpers present for symmetric tagged streams"_test = [] {
        gr::property_map ivMap;
        std::vector<std::uint8_t> iv(16U, 1U);
        ivMap.insert_or_assign(gr::convert_string_domain(std::string_view("iv")), gr::pmt::Value(gr::Tensor<std::uint8_t>(iv)));
        const auto* t = gnuradio4::openssl::detail::tensorBytesFromMap(ivMap, std::string_view("iv"));
        expect(t != nullptr);
        expect(eq(t->size(), 16UZ));
        gr::property_map finalMap;
        finalMap.insert_or_assign(gr::convert_string_domain(std::string_view("final")), gr::pmt::Value(true));
        expect(gnuradio4::openssl::detail::mapHas(finalMap, std::string_view("final")));
        const auto plen = gnuradio4::openssl::detail::readPduLength(makePktLen(80UZ), std::string_view("packet_len"));
        expect(plen.has_value());
        expect(eq(plen.value(), 80UZ));
    };
};

int main() { return boost::ut::cfg<boost::ut::override>.run(); }
