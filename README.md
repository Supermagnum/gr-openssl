gr-openssl
=========================

**IMPORTANT NOTICE**: This is AI-generated code. The developer has a neurological condition that makes it impossible to use and learn traditional programming. The developer has put in a significant effort.

This code has not been reviewed by professional coders, it is a large task. If there are tests available in the codebase, please review those and their code. 

**Status**: This code has been tested and verified to work correctly. The implementation uses OpenSSL's well-tested cryptographic functions directly, ensuring correctness. The GNU Radio 3.10 tree requires **OpenSSL 3.0 or newer**; legacy initialization (`ERR_load_*`, `OpenSSL_add_all_*`, `OPENSSL_config`) has been removed because OpenSSL 3 auto-loads algorithms and error strings.

**Testing** (last verified **2026-06-03**):
- Hash functions are tested against known test vectors (e.g., MD5 test vector verified)
- Encryption/decryption functionality is tested via round-trip tests and interoperability tests with OpenSSL CLI
- All **8/8** CTest targets pass (`ctest --output-on-failure`, total time ~1.7 s)
- Clean Release build succeeds with **OpenSSL 3.0.13** (CMake `find_package(OpenSSL 3.0)`), linking via **`OpenSSL::Crypto`**
- Python bindings use pybind11 (with compatibility shim for legacy crypto_swig imports)
- All Python tests updated for Python 3 compatibility and GNU Radio API changes

See [TEST_VERIFICATION.md](TEST_VERIFICATION.md) for per-test descriptions and the latest run log.

Use at your own risk.

---

gr-openssl is a gnuradio oot-package providing encryption routines using the OpenSSL crypto library

**Compatibility**: 
- **OpenSSL 3.0+** (required at configure time): EVP accessor APIs for opaque structures; no OpenSSL 1.1.x support
- **CMake 3.5+**
- Python 3: All Python tests updated for Python 3 compatibility
- GNU Radio 3.10+: Compatible with modern GNU Radio versions (uses message-based PDU approach where needed)
- Python Bindings: Uses pybind11 with backward compatibility shim for legacy `crypto_swig` imports

### GNU Radio 3.10 — configure, build, test

```bash
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . -j"$(nproc)"
ctest --output-on-failure
```

Requires development packages for OpenSSL 3, Boost, GNU Radio 3.10, and CppUnit.

### GNU Radio 4.0

For **GNU Radio 4**, switch to branch **`gnuradio4`**. The port lives only under **`gnuradio4/`** (blocks in namespace **`gnuradio4::openssl`**, **`find_package(gr-openssl4)`**, target **`gnuradio4::gr-openssl`**). This **`master`** branch remains the **3.10** tree.

```bash
git fetch origin gnuradio4
git checkout gnuradio4
```

See **`README.md` on branch `gnuradio4`** (heading *GNU Radio 4.0 (gr-openssl4)*) for blocks, **`CMAKE_PREFIX_PATH`** (often **`/opt/gnuradio4-gcc`**), and **CPR** notes. GR4 tests (7 Boost.UT targets) passed on **2026-06-03** with OpenSSL 3.0.13; see [TEST_VERIFICATION.md](TEST_VERIFICATION.md).

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
###authenticated encryption
###asymmetric encryption 
###message signing and verifying






