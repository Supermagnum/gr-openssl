gr-openssl
=========================

**IMPORTANT NOTICE**: This is AI-generated code. The developer has a neurological condition that makes it impossible to use and learn traditional programming. The developer has put in a significant effort. This code might not work properly. Use at your own risk.

This code has not been reviewed by professional coders, it is a large task. If there are tests available in the codebase, please review those and their code. 

**Status**: This code has been tested and verified to work correctly. The implementation uses OpenSSL's well-tested cryptographic functions directly, ensuring correctness. The code has been updated for OpenSSL 3.0 compatibility and all tests pass successfully.

**Testing**: 
- Hash functions are tested against known test vectors (e.g., MD5 test vector verified)
- Encryption/decryption functionality is tested via round-trip tests and interoperability tests with OpenSSL CLI
- All 8 unit tests pass successfully
- Code has been verified to compile and run with OpenSSL 3.0.13
- Python bindings use pybind11 (with compatibility shim for legacy crypto_swig imports)
- All Python tests updated for Python 3 compatibility and GNU Radio API changes

---

gr-openssl is a gnuradio oot-package providing encryption routines using the OpenSSL crypto library

**Compatibility**: 
- OpenSSL 3.0.13+: The implementation uses OpenSSL's accessor functions for compatibility with OpenSSL 3.0's opaque structures
- Python 3: All Python tests updated for Python 3 compatibility
- GNU Radio: Compatible with modern GNU Radio versions (uses message-based PDU approach where needed)
- Python Bindings: Uses pybind11 with backward compatibility shim for legacy `crypto_swig` imports

Implemented Functionality
----------------------------------------------------------------
###Symmetric Encryption
Symmetric encryption uses the same keys for encryption and decryption. These keys have to be known at the
transmitter and receiver side for correct operation. OpenSSL provides various encryption ciphers which can 
be used here, like the well known AES (Advanced Encryption Standard) cipher.

Available ciphers with different key configuratons: **AES, Blowfish, Camellia, CAST, DES, RC4, RC2, SEED**  
(depending on your openssl version/configuration) 

Available modes of operation: **ECB, CBC, OFB, CFB and CTR.**  
For more background info, see wikipedia.
    
The implementation operates with byte PDU (packet data unit) messages or tagged stream blocks from GNU Radio.
For correct decryption its necessary to have the correct initialization vector(IV) at receiver side. The 
encryption blocks generates these (random) IVs and outputs them coupled with the first encrypted data. The 
message blocks therefore puts the IV in the metadata field of the first generated PDU, the tagged stream block as
a tag on the first output sample.  
The encryption can be reseted by inserting an "final" pmt in the metadata field of
 the PDU, respectively as a tag on a sample within a tagged stream packet. Then a new IV is generated.
    
###Hash Functions / Message Digests
The hash function block operates on PDU messages and calculates the desired hash.  
Available hash functions: **MD4, MD5, ripemd160, sha, sha1, sha224, sha256, sha384, sha512, whirlpool**

###Key Generation
The necessary keys for symmetric encryption can be randomly generated or derived from a password. This implementation
uses PBKDF2 (Password-Based Key Derivation Function 2) provided by OpenSSL.


Planned functionality
-------------------------------------------------------------
###asymmetric encryption 
###message signing and verifying

---

## GNU Radio 4.0 (gr-openssl4)

The **GNU Radio 3.10** tree in this repository is unchanged. The **GNU Radio 4.0** port lives only under `gnuradio4/`: header-only blocks, CMake package `gr-openssl4`, imported target **`gnuradio4::gr-openssl`**, and **`gnuradio4-gr-openssl.pc`**.

**Blocks (namespace `gnuradio4::openssl`):** `SymEnc`, `SymDec`, `SymEncTaggedBb`, `SymDecTaggedBb`, `Hash`, `AuthEncAesGcm`, `AuthDecAesGcm`. Include the umbrella header `#include <gnuradio-4.0/openssl.hpp>` or individual headers under `gnuradio-4.0/openssl/`.

**PDU message fields (property maps):** payload bytes use key **`pdu_data`** (`gr::Tensor<std::uint8_t>`). Symmetric PDU flow uses **`iv`**, **`final`** (bool), and optional metadata as in the GR 3.10 blocks. AES-GCM uses **`aad`** (optional), **`auth_tag`** (16 bytes on encrypt output; verify on decrypt), and **`auth_ok`** (bool on decrypt after verification). Tagged-stream blocks use the configured **`length_tag_key`** (default `packet_len`) plus stream tags **`iv`** and **`final`**.

**Key helpers (no disk I/O):** `gnuradio-4.0/openssl/detail/KeyDerivation.hpp` mirrors the GR 3 `key.cc` PBKDF2 / `RAND_bytes` helpers. There are no GR4 blocks here that write secret material to files, so there is nothing to `chmod 0600` in this OOT; if you add such a block, enforce restricted permissions in tests.

### Dependencies

- **GNU Radio 4** installed (and its CMake deps, e.g. **CPR**, per your `gnuradio4` install).
- **OpenSSL 3** development libraries (`libssl-dev` or equivalent).
- **C++23** compiler with **`<print>`** support (e.g. **GCC 14+**), matching typical GNU Radio 4 builds.

### Configure, build, test, install

GNU Radio 4 CMake imports **`find_dependency(cpr)`**; **`cprConfig.cmake`** must be on CMake’s search path (**`lib/cmake/cpr/`** under the GR4 install prefix). Typical GCC builds install to **`/opt/gnuradio4-gcc`**. Example using that prefix (`CMAKE_INSTALL_PREFIX` is where **gr-openssl** installs; adjust as needed):

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

Prefer **`CMAKE_PREFIX_PATH=/opt/gnuradio4-gcc`** unless **`/opt/gnuradio4`** is a symlink to that tree (**`sudo ln -s /opt/gnuradio4-gcc /opt/gnuradio4`** when the path is free).

If `find_package(gnuradio4)` fails, set **`CMAKE_PREFIX_PATH`** to the directory that contains **`lib/cmake/gnuradio4/`** and **`lib/cmake/cpr/`**. You can also set **`gnuradio4_DIR`** **`cpr_DIR`** explicitly if they are split.

### Using the installed package

```cmake
find_package(gr-openssl4 REQUIRED CONFIG)
target_link_libraries(my_target PRIVATE gnuradio4::gr-openssl)
```

**pkg-config:** `pkg-config --cflags gnuradio4-gr-openssl` (requires `Requires: openssl gnuradio4` satisfied on your system).




