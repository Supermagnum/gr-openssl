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

from gnuradio import gr, gr_unittest
from gnuradio import blocks
try:
    from gnuradio import pdu
    USE_PDU_MODULE = True
except ImportError:
    USE_PDU_MODULE = False
import crypto_swig as crypto
import pmt

class qa_hash (gr_unittest.TestCase):

    def setUp (self):
        self.tb = gr.top_block ()

    def tearDown (self):
        self.tb = None

    def test_001_t (self):
        hash_func = "md5"
        text = bytearray(b"ABCDEFGH")
        exp_result = bytearray([0x47,0x83,0xe7,0x84,0xb4,0xfa,0x2f,0xba,0x9e,0x4d,0x65,0x02,0xdb,0xc6,0x4f,0x8f])

        # Create PDU message directly to avoid itemsize conversion issues
        meta = pmt.make_dict()
        data_pmt = pmt.init_u8vector(len(text), text)
        pdu_msg = pmt.cons(meta, data_pmt)
        
        hash_block = crypto.hash(hash_func)
        snk = blocks.message_debug()

        self.tb.msg_connect(hash_block, "pdus", snk, "store")
        
        # Start flowgraph first
        self.tb.start()
        
        # Send message directly to hash block
        hash_block.to_basic_block()._post(pmt.intern("pdus"), pdu_msg)
        
        # Give it time to process
        import time
        time.sleep(0.1)
        
        self.tb.stop()
        self.tb.wait()

        if snk.num_messages() > 0:
            hash = bytearray(pmt.u8vector_elements(pmt.cdr((snk.get_message(0)))))
            self.assertEqual(exp_result, hash)
        else:
            self.fail("No hash message received")


if __name__ == '__main__':
    gr_unittest.run(qa_hash, "qa_hash.xml")
