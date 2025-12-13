# Copyright 2011 Free Software Foundation, Inc.
#
# This file is part of GNU Radio
#
# GNU Radio is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
#
# GNU Radio is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GNU Radio; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street,
# Boston, MA 02110-1301, USA.

########################################################################
# Python bindings using pybind11
########################################################################
find_package(Python3 COMPONENTS Interpreter Development)
find_package(pybind11 QUIET)

if(NOT Python3_FOUND OR NOT pybind11_FOUND)
    message(STATUS "Python3 or pybind11 not found - skipping Python bindings")
    return()
endif()

# Create Python bindings
pybind11_add_module(crypto_python
    crypto_python.cc
)

target_include_directories(crypto_python PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${GNURADIO_ALL_INCLUDE_DIRS}
)

target_link_libraries(crypto_python PRIVATE
    gnuradio-crypto
    gnuradio-runtime
    gnuradio-pmt
)

# Install Python module
install(TARGETS crypto_python
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/python3/dist-packages
)

# Install Python wrapper module to gnuradio package
install(FILES gnuradio_crypto_init.py
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/python3/dist-packages/gnuradio
    RENAME crypto.py
)

########################################################################
# Handle the unit tests
########################################################################
include(GrTest)

set(GR_TEST_TARGET_DEPS gnuradio-crypto)
set(GR_TEST_PYTHON_DIRS ${CMAKE_BINARY_DIR}/swig)
GR_ADD_TEST(qa_sym_enc_tagged_bb ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/qa_sym_enc_tagged_bb.py)
GR_ADD_TEST(qa_sym_dec_tagged_bb ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/qa_sym_dec_tagged_bb.py)
GR_ADD_TEST(qa_sym_enc ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/qa_sym_enc.py)
GR_ADD_TEST(qa_sym_dec ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/qa_sym_dec.py)
GR_ADD_TEST(qa_hash ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/qa_hash.py)
GR_ADD_TEST(qa_auth_enc_aes_gcm ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/qa_auth_enc_aes_gcm.py)
GR_ADD_TEST(qa_sym_enc_test_vectors ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/qa_sym_enc_test_vectors.py)
