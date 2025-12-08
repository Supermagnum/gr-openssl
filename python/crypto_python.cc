/* -*- c++ -*- */
/*
 * Copyright 2024
 *
 * This file is part of gr-openssl.
 *
 * gr-openssl is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *
 * gr-openssl is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with gr-openssl; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <crypto/sym_enc.h>
#include <crypto/sym_dec.h>
#include <crypto/sym_enc_tagged_bb.h>
#include <crypto/sym_dec_tagged_bb.h>
#include <crypto/hash.h>
#include <crypto/auth_enc_aes_gcm.h>
#include <crypto/auth_dec_aes_gcm.h>
#include <crypto/sym_ciph_desc.h>

namespace py = pybind11;

void bind_sym_ciph_desc(py::module& m)
{
    using sym_ciph_desc = gr::crypto::sym_ciph_desc;

    py::class_<sym_ciph_desc, std::shared_ptr<sym_ciph_desc>>(
        m, "sym_ciph_desc")
        .def(py::init<const std::string&, bool, const std::vector<uint8_t>&>(),
             py::arg("ciph_name"),
             py::arg("padding"),
             py::arg("key"));
}

void bind_sym_enc(py::module& m)
{
    using sym_enc = gr::crypto::sym_enc;

    py::class_<sym_enc, gr::block, std::shared_ptr<sym_enc>>(
        m, "sym_enc")
        .def(py::init(&sym_enc::make),
             py::arg("ciph_desc"));
}

void bind_sym_dec(py::module& m)
{
    using sym_dec = gr::crypto::sym_dec;

    py::class_<sym_dec, gr::block, std::shared_ptr<sym_dec>>(
        m, "sym_dec")
        .def(py::init(&sym_dec::make),
             py::arg("ciph_desc"));
}

void bind_sym_enc_tagged_bb(py::module& m)
{
    using sym_enc_tagged_bb = gr::crypto::sym_enc_tagged_bb;

    py::class_<sym_enc_tagged_bb, gr::tagged_stream_block, std::shared_ptr<sym_enc_tagged_bb>>(
        m, "sym_enc_tagged_bb")
        .def(py::init(&sym_enc_tagged_bb::make),
             py::arg("ciph_desc"),
             py::arg("packet_len_key"));
}

void bind_sym_dec_tagged_bb(py::module& m)
{
    using sym_dec_tagged_bb = gr::crypto::sym_dec_tagged_bb;

    py::class_<sym_dec_tagged_bb, gr::tagged_stream_block, std::shared_ptr<sym_dec_tagged_bb>>(
        m, "sym_dec_tagged_bb")
        .def(py::init(&sym_dec_tagged_bb::make),
             py::arg("desc"),
             py::arg("packet_len_tag"));
}

void bind_hash(py::module& m)
{
    using hash = gr::crypto::hash;

    py::class_<hash, gr::block, std::shared_ptr<hash>>(
        m, "hash")
        .def(py::init(&hash::make),
             py::arg("hash_name"));
}

void bind_auth_enc_aes_gcm(py::module& m)
{
    using auth_enc_aes_gcm = gr::crypto::auth_enc_aes_gcm;

    py::class_<auth_enc_aes_gcm, gr::block, std::shared_ptr<auth_enc_aes_gcm>>(
        m, "auth_enc_aes_gcm")
        .def(py::init(&auth_enc_aes_gcm::make),
             py::arg("key"),
             py::arg("keylen"),
             py::arg("ivlen"));
}

void bind_auth_dec_aes_gcm(py::module& m)
{
    using auth_dec_aes_gcm = gr::crypto::auth_dec_aes_gcm;

    py::class_<auth_dec_aes_gcm, gr::block, std::shared_ptr<auth_dec_aes_gcm>>(
        m, "auth_dec_aes_gcm")
        .def(py::init(&auth_dec_aes_gcm::make),
             py::arg("key"),
             py::arg("keylen"),
             py::arg("ivlen"));
}

PYBIND11_MODULE(crypto_python, m)
{
    m.doc() = "Python bindings for gr-openssl";

    bind_sym_ciph_desc(m);
    bind_sym_enc(m);
    bind_sym_dec(m);
    bind_sym_enc_tagged_bb(m);
    bind_sym_dec_tagged_bb(m);
    bind_hash(m);
    bind_auth_enc_aes_gcm(m);
    bind_auth_dec_aes_gcm(m);
}

