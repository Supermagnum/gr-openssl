// SPDX-License-Identifier: GPL-3.0-or-later
#include <boost/ut.hpp>

#include <gnuradio-4.0/Tag.hpp>
#include <gnuradio-4.0/openssl/detail/Helpers.hpp>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <cstddef>
#include <memory>
#include <string_view>
#include <vector>

using namespace boost::ut;

namespace {

[[nodiscard]] gr::property_map makePktLen(gr::Size_t n) {
    gr::property_map m;
    m.insert_or_assign(gr::convert_string_domain(std::string_view("packet_len")), gr::pmt::Value(static_cast<std::uint64_t>(n)));
    return m;
}

struct EvpCipherCtxFree {
    void operator()(EVP_CIPHER_CTX* p) const noexcept { EVP_CIPHER_CTX_free(p); }
};

using CipherCtx = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxFree>;

} // namespace

const boost::ut::suite<"SymEncTaggedBb"> SymEncTaggedBbTests = [] {
    "readPduLength used by tagged PDU maps"_test = [] {
        const auto empty = gnuradio4::openssl::detail::readPduLength(gr::property_map{}, std::string_view("packet_len"));
        expect(!empty.has_value());
        const auto v =
            gnuradio4::openssl::detail::readPduLength(makePktLen(static_cast<gr::Size_t>(64)), std::string_view("packet_len"));
        expect(v.has_value());
        expect(eq(v.value(), 64UZ));
    };

    "aes-128-cbc tagged-stream-sized buffer round trip via EVP (reference for block)"_test = [] {
        const EVP_CIPHER*          ciph = EVP_aes_128_cbc();
        std::vector<unsigned char> key(static_cast<std::size_t>(EVP_CIPHER_get_key_length(ciph)), 0xAEU);
        std::vector<unsigned char> iv(static_cast<std::size_t>(EVP_CIPHER_get_iv_length(ciph)), 0U);
        expect(eq(RAND_bytes(iv.data(), static_cast<int>(iv.size())), 1));
        std::vector<unsigned char> plain(static_cast<std::size_t>(32U), 0x7EU);
        std::vector<unsigned char> ct(plain.size() + static_cast<std::size_t>(EVP_CIPHER_get_block_size(ciph)));
        std::vector<unsigned char> recovered(plain.size() + static_cast<std::size_t>(EVP_CIPHER_get_block_size(ciph)));

        CipherCtx enc{EVP_CIPHER_CTX_new()};
        CipherCtx dec{EVP_CIPHER_CTX_new()};
        expect(enc != nullptr && dec != nullptr);
        expect(eq(EVP_EncryptInit_ex(enc.get(), ciph, nullptr, key.data(), iv.data()), 1));
        expect(eq(EVP_CIPHER_CTX_set_padding(enc.get(), 1), 1));
        int encOut = 0;
        expect(eq(EVP_EncryptUpdate(enc.get(), ct.data(), &encOut, plain.data(), static_cast<int>(plain.size())), 1));
        int encFin = 0;
        expect(eq(EVP_EncryptFinal_ex(enc.get(), ct.data() + encOut, &encFin), 1));

        expect(eq(EVP_DecryptInit_ex(dec.get(), ciph, nullptr, key.data(), iv.data()), 1));
        expect(eq(EVP_CIPHER_CTX_set_padding(dec.get(), 1), 1));
        int decOut = 0;
        const int ctLen = encOut + encFin;
        expect(eq(EVP_DecryptUpdate(dec.get(), recovered.data(), &decOut, ct.data(), ctLen), 1));
        int decFin = 0;
        expect(eq(EVP_DecryptFinal_ex(dec.get(), recovered.data() + decOut, &decFin), 1));
        expect(eq(decOut + decFin, static_cast<int>(plain.size())));
        for (std::size_t i = 0; i < plain.size(); ++i) {
            expect(eq(recovered[static_cast<std::size_t>(i)], plain[i]));
        }
    };
};

int main() { return boost::ut::cfg<boost::ut::override>.run(); }
