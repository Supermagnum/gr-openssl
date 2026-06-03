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
include(GrPython)
# Extension module ABI must match GNU Radio's interpreter (not a random
# Python3 from PATH, e.g. Miniforge vs /usr/bin/python3).
if(PYTHON_EXECUTABLE)
    set(Python3_EXECUTABLE "${PYTHON_EXECUTABLE}" CACHE FILEPATH
        "Python for gr-openssl bindings and QA tests" FORCE)
endif()

find_package(Python3 COMPONENTS Interpreter Development REQUIRED)
find_package(pybind11 QUIET)

if(QA_PYTHON_EXECUTABLE)
    set(GR_CRYPTO_QA_PYTHON "${QA_PYTHON_EXECUTABLE}")
elseif(Python3_EXECUTABLE)
    set(GR_CRYPTO_QA_PYTHON "${Python3_EXECUTABLE}")
else()
    set(GR_CRYPTO_QA_PYTHON "${PYTHON_EXECUTABLE}")
endif()

message(STATUS "gr-openssl Python bindings: ${Python3_EXECUTABLE}")
message(STATUS "gr-openssl QA tests: ${GR_CRYPTO_QA_PYTHON}")

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

# Install Python bindings into GNU Radio's site-packages (import crypto in GRC).
install(TARGETS crypto_python
    LIBRARY DESTINATION ${GR_PYTHON_DIR}/crypto
)

install(FILES gnuradio_crypto_init.py
    DESTINATION ${GR_PYTHON_DIR}/crypto
    RENAME __init__.py
)

install(FILES gnuradio_crypto_init.py
    DESTINATION ${GR_PYTHON_DIR}/gnuradio
    RENAME crypto.py
)

########################################################################
# Handle the unit tests
########################################################################
include(GrTest)

set(GR_TEST_TARGET_DEPS gnuradio-crypto)
list(APPEND GR_TEST_LIBRARY_DIRS ${CMAKE_BINARY_DIR}/lib)
set(GR_TEST_PYTHON_DIRS
    ${CMAKE_BINARY_DIR}/python
    ${CMAKE_CURRENT_SOURCE_DIR}
)
GR_ADD_TEST(qa_sym_enc_tagged_bb ${GR_CRYPTO_QA_PYTHON} ${CMAKE_CURRENT_SOURCE_DIR}/qa_sym_enc_tagged_bb.py)
GR_ADD_TEST(qa_sym_dec_tagged_bb ${GR_CRYPTO_QA_PYTHON} ${CMAKE_CURRENT_SOURCE_DIR}/qa_sym_dec_tagged_bb.py)
GR_ADD_TEST(qa_sym_enc ${GR_CRYPTO_QA_PYTHON} ${CMAKE_CURRENT_SOURCE_DIR}/qa_sym_enc.py)
GR_ADD_TEST(qa_sym_dec ${GR_CRYPTO_QA_PYTHON} ${CMAKE_CURRENT_SOURCE_DIR}/qa_sym_dec.py)
GR_ADD_TEST(qa_hash ${GR_CRYPTO_QA_PYTHON} ${CMAKE_CURRENT_SOURCE_DIR}/qa_hash.py)
GR_ADD_TEST(qa_auth_enc_aes_gcm ${GR_CRYPTO_QA_PYTHON} ${CMAKE_CURRENT_SOURCE_DIR}/qa_auth_enc_aes_gcm.py)
GR_ADD_TEST(qa_sym_enc_test_vectors ${GR_CRYPTO_QA_PYTHON} ${CMAKE_CURRENT_SOURCE_DIR}/qa_sym_enc_test_vectors.py)
