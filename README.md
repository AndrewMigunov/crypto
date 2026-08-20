# cryptomoon

`cryptomoon` is a dependency-free C99 library implementing the DES and two-key and three-key
Triple DES block primitives. It builds both static and shared `cryptomoon` libraries.

> [!WARNING]
> DES and TDES are obsolete cryptographic algorithms. This project is intended for education
> and legacy interoperability, not for protecting new systems or data.

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
- 3TDES accepts 24 bytes (`K1, K2, K3`) with three distinct effective keys.
- DES parity bits are ignored during encryption and decryption; caller-owned keys are never
  modified.
- Weak, semi-weak, potentially weak, and degenerate keys are rejected.
- Input and output buffers must be distinct and must not overlap.
- Bytes are interpreted in the bit order defined by the DES specification, independently of host
  endianness.
- DES and TDES operations are one-shot calls. Key schedules remain private and are erased before
  each call returns.

The public headers are under `include/`. ECB is the only currently supported cipher mode, and
each call processes any number of complete blocks without padding. Input lengths must be
multiples of the 8-byte DES block size. See the unit tests for complete examples.

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

Without `--output`, the result is printed as lowercase hexadecimal text. With `--output`, raw
bytes are written to the selected file. File processing is streaming and does not load the whole
file into memory. Keys and inputs must have exact supported sizes, key parity bits are ignored,
and input must consist of complete 8-byte blocks because the application does not apply padding.

Run `cryptomoon-cli --help` for the complete syntax. As with the library itself, this application
is only for education and legacy interoperability; DES, TDES, and ECB are unsuitable for new
secure systems.

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
