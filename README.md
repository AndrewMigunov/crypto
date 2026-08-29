# cryptomoon

`cryptomoon` is a dependency-free C99 library implementing the DES and two-key and three-key
Triple DES block primitives. It builds both static and shared `cryptomoon` libraries.

## Development environment

The repository contains an Ubuntu 24.04 development container with GCC, CMake, Ninja, GDB,
clang-format, gcov, and lcov. Open the repository as a dev container, then use only the presets
below.

```sh
cmake --preset debug
cmake --build --preset debug
ctest --preset debug
```

Replace `debug` with `release` for an optimized build. To collect coverage:

```sh
cmake --preset coverage
cmake --build --preset coverage
ctest --preset coverage
lcov --capture --directory build/coverage --output-file build/coverage/coverage-all.info
lcov --extract build/coverage/coverage-all.info '*/src/*' \
    --output-file build/coverage/coverage.info
```

All project warnings are errors. GCC is configured for strict ISO C99 without GNU language
extensions.

Unit tests use a pinned, vendored copy of the header-only Acutest framework. Configuring and
building the project never downloads test dependencies.

## API rules

- All input and output buffers are supplied by the caller; the library never allocates heap
  memory.
- DES operates on an 8-byte key and an 8-byte block.
- 2TDES accepts 16 bytes (`K1, K2`) and applies `K1, K2, K1`.
- 3TDES accepts 24 bytes (`K1, K2, K3`).
- DES parity bits are ignored during encryption and decryption; caller-owned keys are never
  modified.
- Weak, semi-weak, and potentially weak DES components are rejected. Degenerate TDES bundles are
  accepted and behave as the equivalent lower keying option.
- Input and output buffers must be distinct and must not overlap.
- Bytes are interpreted in the bit order defined by the DES specification, independently of host
  endianness.
- DES and TDES operations are one-shot calls. Key schedules remain private and are erased before
  each call returns.

The public headers are under `include/`. DES, 2TDES, and 3TDES support ECB, CBC, CFB64, OFB64,
and CTR modes, and each call processes any number of complete blocks without padding. CBC, CFB64,
OFB64, and CTR require an 8-byte initialization vector, while ECB ignores the IV and requires a
zero IV length. In CTR mode the counter block is the `nonce` (0-7 bytes) concatenated with the
initial counter value passed as the IV; only the low `8 - nonce_length` counter bytes are
incremented as a big-endian integer for each subsequent block and the carry never propagates into
the nonce. With a zero `nonce_length` the whole IV is incremented, preserving the previous
full-block behaviour. Encryption and decryption are identical because CTR is a stream mode. Input
lengths must be multiples of the 8-byte DES block size. See the unit tests for complete examples.

The generated `version.h` header exposes the CMake project version, the short Git commit hash,
and their combined `CRYPTOMOON_FULL_VERSION` value. The allocation-free `crypto_version()`
function returns `major.minor.patch`, while `crypto_full_version()` appends the Git hash.

## Command-line application

The `cryptomoon-cli` executable encrypts and decrypts DES, 2TDES, and 3TDES data through the public
library API. Keys can be supplied as hexadecimal text or raw files. Input can likewise be
hexadecimal text or a raw file:

```sh
cryptomoon-cli encrypt --algorithm des \
    --key 133457799bbcdff1 \
    --input 0123456789abcdef

cryptomoon-cli decrypt --algorithm 3tdes \
    --key-file key.bin \
    --file encrypted.bin \
    --output plaintext.bin
```

CBC mode is selected with `--mode cbc`, CFB64 with `--mode cfb64`, OFB64 with
`--mode ofb64`, and CTR with `--mode ctr`; all four require an 8-byte initialization vector:

```sh
cryptomoon-cli encrypt --algorithm des --mode cbc \
    --key 0123456789abcdef --iv 1234567890abcdef \
    --input 4e6f77206973207468652074696d6520666f7220616c6c20

cryptomoon-cli encrypt --algorithm des --mode cfb64 \
    --key 0123456789abcdef --iv 1234567890abcdef \
    --input 4e6f77206973207468652074696d6520666f7220616c6c20

cryptomoon-cli encrypt --algorithm des --mode ofb64 \
    --key 0123456789abcdef --iv 1234567890abcdef \
    --input 4e6f77206973207468652074696d6520666f7220616c6c20

cryptomoon-cli encrypt --algorithm des --mode ctr \
    --key 0123456789abcdef --iv 1234567890abcdef \
    --input 4e6f77206973207468652074696d6520666f7220616c6c20

cryptomoon-cli encrypt --algorithm des --mode ctr \
    --key 0123456789abcdef --nonce 0000 --iv fffffffffffe \
    --input 4e6f77206973207468652074696d6520666f7220616c6c20
```

The IV can be passed as 16 hexadecimal characters with `--iv` or as a raw 8-byte file with
`--iv-file`. ECB is the default mode and rejects IV options. In CTR mode only, an optional
`--nonce` (0-7 bytes, as hexadecimal text) occupies the high bytes of the counter block; when
supplied, `--iv` holds the low counter bytes and `--nonce` plus `--iv` must total 8 bytes. Passing
`--nonce` in any mode other than CTR is an error.

Without `--output`, the result is printed as lowercase hexadecimal text. With `--output`, raw
bytes are written to the selected file. File processing is streaming and does not load the whole
file into memory. Keys and inputs must have exact supported sizes, key parity bits are ignored,
and input must consist of complete 8-byte blocks because the application does not apply padding.

Run `cryptomoon-cli --help` for the complete syntax. As with the library itself, this application
is only for education and legacy interoperability; DES, TDES, and ECB are unsuitable for new
secure systems.

Run `cryptomoon-cli --version` to print the project version together with the short Git commit
hash used for the build.

## Versioning and releases

The project follows Semantic Versioning. Update the version only in the top-level `project()`
command; library artifacts, generated headers, documentation, package metadata, and tests derive
their versions from that value. Increment `MAJOR` for incompatible API or ABI changes, `MINOR` for
backward-compatible features, and `PATCH` for backward-compatible fixes.

Release tags use the annotated `vMAJOR.MINOR.PATCH` form and must point to the commit used for the
release build. The working tree must be clean before creating a release tag. The Git hash appended
by `crypto_full_version()` identifies the exact build commit but does not change package-version
compatibility.

## Installation

```sh
cmake --install build/release --prefix /desired/prefix
```

The installation provides the `cryptomoon-cli` executable, `libcryptomoon` in static and shared
forms, public headers, and CMake package targets `cryptomoon::static` and `cryptomoon::shared`. A
Release build also generates Doxygen HTML documentation in `build/release/docs/html` and installs
it under the documentation directory.

## Design sources

The implementation was written independently using the DES/TDEA specification and published
test vectors.

## License

Apache License 2.0. See `LICENSE`.

The test-only Acutest header is available under the MIT license preserved in
`tests/third_party/acutest/LICENSE.md`.
