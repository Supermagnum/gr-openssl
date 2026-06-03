gr-openssl
=========================

**IMPORTANT NOTICE**: This is AI-generated code. The developer has a neurological condition that makes it impossible to use and learn traditional programming. The developer has put in a significant effort. This code might not work properly. Use at your own risk.

This code has not been reviewed by professional coders, it is a large task. If there are tests available in the codebase, please review those and their code.

**Status**: This branch (**gnuradio4**) is the **GNU Radio 4.0** port. It also contains the legacy GNU Radio 3.10 tree for reference; for GR 3.10-only work, prefer branch **`master`**.

**OpenSSL 3.0+** is required on both trees. GR 4 tests: **7/7** Boost.UT pass under `gnuradio4/build` (see [TEST_VERIFICATION.md](TEST_VERIFICATION.md)).

---

## GNU Radio 4.0 (gr-openssl4) — primary on this branch

Header-only blocks under `gnuradio4/`, CMake package **`gr-openssl4`**, imported target **`gnuradio4::gr-openssl`**, **`gnuradio4-gr-openssl.pc`**.

**Blocks** (`gnuradio4::openssl`): `SymEnc`, `SymDec`, `SymEncTaggedBb`, `SymDecTaggedBb`, `Hash`, `AuthEncAesGcm`, `AuthDecAesGcm`.

Include `#include <gnuradio-4.0/openssl.hpp>` or headers under `gnuradio-4.0/openssl/`.

**PDU fields:** `pdu_data`, `iv`, `final`, `aad`, `auth_tag`, `auth_ok` (see headers). Tagged-stream blocks use `length_tag_key` (default `packet_len`) plus tags `iv` and `final`.

**Key helpers:** `gnuradio-4.0/openssl/detail/KeyDerivation.hpp` (PBKDF2 / `RAND_bytes`; no disk I/O in-tree).

### Dependencies

- GNU Radio 4 installed (and CMake deps, e.g. **CPR**)
- OpenSSL 3 development libraries
- **C++23** with **`<print>`** (e.g. GCC 14+)

### Configure, build, test, install

```bash
cd gnuradio4
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/opt/gnuradio4-gcc \
  -DCMAKE_PREFIX_PATH=/opt/gnuradio4-gcc \
  -DCMAKE_CXX_COMPILER=g++-14
cmake --build build -j"$(nproc)"
cd build && ctest --output-on-failure
sudo cmake --install .
```

Set **`CMAKE_PREFIX_PATH`** to the prefix containing `lib/cmake/gnuradio4/` and `lib/cmake/cpr/`.

### Using the installed package

```cmake
find_package(gr-openssl4 REQUIRED CONFIG)
target_link_libraries(my_target PRIVATE gnuradio4::gr-openssl)
```

**pkg-config:** `pkg-config --cflags gnuradio4-gr-openssl`

---

## GNU Radio 3.10 tree (secondary on this branch)

The GR 3.10 OOT at the repository root is maintained on **`master`**. You may build it here for convenience:

```bash
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . -j"$(nproc)"
ctest --output-on-failure
```

For GR 3.10-only development and releases, use **`git checkout master`**.

Implemented Functionality (GR 3.10 blocks)
----------------------------------------------------------------
###Symmetric Encryption
(Same as master — AES, Blowfish, Camellia, CAST, DES, RC4, RC2, SEED; modes ECB, CBC, OFB, CFB, CTR.)

###Hash Functions / Message Digests
MD4, MD5, ripemd160, sha, sha1, sha224, sha256, sha384, sha512, whirlpool

###Key Generation
PBKDF2 via OpenSSL

Planned functionality
-------------------------------------------------------------
###asymmetric encryption
###message signing and verifying
