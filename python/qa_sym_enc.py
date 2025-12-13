#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2016 Kristian Maier.
#
# This is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this software; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street,
# Boston, MA 02110-1301, USA.
#

from time import sleep

import crypto_swig as crypto
import numpy
import pmt
from gnuradio import blocks, gr, gr_unittest


class qa_sym_enc(gr_unittest.TestCase):
    def setUp(self):
        self.tb = gr.top_block()

    def tearDown(self):
        self.tb = None

    # test correct encryption and decryption
    def test_001_t(self):

        cipher_name = "aes-256-cbc"
        plainlen = 1600
        key = bytearray(numpy.random.randint(0, 256, 32).tolist())
        plain = bytearray(numpy.random.randint(0, 256, plainlen).tolist())

        cipher_desc = crypto.sym_ciph_desc(cipher_name, False, key)

        # Use message-based approach to avoid itemsize conversion issues
        # Create PDU message directly
        meta = pmt.make_dict()
        data_pmt = pmt.init_u8vector(len(plain), plain)
        pdu_msg = pmt.cons(meta, data_pmt)

        enc = crypto.sym_enc(cipher_desc)
        dec = crypto.sym_dec(cipher_desc)
        snk = blocks.message_debug()

        self.tb.msg_connect(enc, "pdus", dec, "pdus")
        self.tb.msg_connect(dec, "pdus", snk, "store")

        self.tb.start()

        # Send message directly to encryptor
        enc.to_basic_block()._post(pmt.intern("pdus"), pdu_msg)

        # Give it time to process
        import time

        time.sleep(0.2)

        self.tb.stop()
        self.tb.wait()

        if snk.num_messages() > 0:
            decrypted = bytearray(pmt.u8vector_elements(pmt.cdr((snk.get_message(0)))))
            # Remove any padding if present
            if len(decrypted) >= len(plain):
                decrypted_no_pad = decrypted[: len(plain)]
                self.assertEqual(plain, decrypted_no_pad)
            else:
                self.assertEqual(plain, decrypted)
        else:
            self.fail("No decrypted message received")


if __name__ == "__main__":
    gr_unittest.run(qa_sym_enc)
