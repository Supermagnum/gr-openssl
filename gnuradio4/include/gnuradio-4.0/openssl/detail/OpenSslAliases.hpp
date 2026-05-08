// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef GNURADIO4_OPENSSL_DETAIL_OPENSSLALIASES_HPP
#define GNURADIO4_OPENSSL_DETAIL_OPENSSLALIASES_HPP

#include <openssl/evp.h>

#include <memory>

namespace gnuradio4::openssl::detail {

struct EvpMdCtxFree {
    void operator()(EVP_MD_CTX* p) const noexcept {
        EVP_MD_CTX_free(p);
    }
};

struct EvpCipherCtxFree {
    void operator()(EVP_CIPHER_CTX* p) const noexcept { EVP_CIPHER_CTX_free(p); }
};

using MdCtxPtr   = std::unique_ptr<EVP_MD_CTX, EvpMdCtxFree>;
using CipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxFree>;

} // namespace gnuradio4::openssl::detail

#endif
