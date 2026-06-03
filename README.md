gr-openssl
=========================

**IMPORTANT NOTICE**: This is AI-generated code. The developer has a neurological condition that makes it impossible to use and learn traditional programming. The developer has put in a significant effort. This code might not work properly. Use at your own risk.

This code has not been reviewed by professional coders, it is a large task. If there are tests available in the codebase, please review those and their code.

**Status**: This branch (**master**) is the **GNU Radio 3.10** out-of-tree module. It requires **OpenSSL 3.0 or newer**; legacy initialization (`ERR_load_*`, `OpenSSL_add_all_*`, `OPENSSL_config`) has been removed because OpenSSL 3 auto-loads algorithms and error strings.

**Testing** (last verified **2026-06-03**):
- All **8/8** CTest targets pass on this branch (`ctest --output-on-failure`)
- Build uses **OpenSSL 3.0.13**, linking **`OpenSSL::Crypto`**

See [TEST_VERIFICATION.md](TEST_VERIFICATION.md) for details.

---

gr-openssl is a gnuradio OOT package providing encryption routines using the OpenSSL crypto library.

**Compatibility**:
- **OpenSSL 3.0+** (required at configure time)
- **CMake 3.5+**
- **GNU Radio 3.10+**
- Python 3 (pybind11 bindings)

### Configure, build, test (GNU Radio 3.10)

```bash
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . -j"$(nproc)"
ctest --output-on-failure
```

Requires OpenSSL 3, Boost, GNU Radio 3.10, and CppUnit development packages.

### GNU Radio 4.0

**GNU Radio 4.x is not on this branch.** Use branch **`gnuradio4`** and build under **`gnuradio4/`** (`find_package(gr-openssl4)`, target `gnuradio4::gr-openssl`). See `README.md` on that branch.

```bash
git fetch origin gnuradio4
git checkout gnuradio4
```

Implemented Functionality
----------------------------------------------------------------
###Symmetric Encryption
Symmetric encryption uses the same keys for encryption and decryption. These keys have to be known at the
transmitter and receiver side for correct operation. OpenSSL provides various encryption ciphers which can
be used here, like the well known AES (Advanced Encryption Standard) cipher.

Available ciphers with different key configuratons: **AES, Blowfish, Camellia, CAST, DES, RC4, RC2, SEED**
(depending on your openssl version/configuration)

Available modes of operation: **ECB, CBC, OFB, CFB and CTR.**

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
