# AGENTS.md

## Project scope

This repository contains the `crypto` C99 library. The first implementation stage supports:

- DES block encryption and decryption;
- two-key Triple DES (2TDES) using K1, K2, K1;
- three-key Triple DES (3TDES) using K1, K2, K3;
- single-block operations only;
- no block modes and no padding.

DES and TDES are obsolete algorithms. Treat this project as an educational and legacy
interoperability implementation, not as a suitable primitive for new security systems.

## Language and code style

- Write production code and tests in strict ISO C99.
- Do not use GNU language extensions.
- Use the Allman brace style defined by `.clang-format`.
- Every C function must contain exactly one `return` statement, including static helpers and
  test functions.
- Write code comments in English.
- All code comments must use Doxygen syntax.
- Document public functions with `@brief`, `@param`, and `@return` where applicable.
- Prefer fixed-width integer types from `<stdint.h>`.
- Avoid global mutable state.
- Keep public headers in `include/crypto/` and C implementation files in `src/`.

## Memory policy

- Do not use dynamic memory allocation.
- Calls to `malloc`, `calloc`, `realloc`, and `free` are forbidden.
- Contexts are fixed-size caller-owned structures intended for stack allocation.
- The caller supplies all input and output buffers.
- Use only bounded, fixed-size local storage inside the library.
- Explicitly erase derived key material with `crypto_des_clear()` or `crypto_tdes_clear()`.
- Sensitive-data erasure must be implemented so that the compiler cannot remove it as a dead
  store.

## Public API conventions

- Fallible public functions return the `crypto_status` enum.
- `CRYPTO_STATUS_OK` must remain zero.
- Do not return magic integer error codes.
- Append new status values to the enum; do not renumber published values.
- Key parameters use a pointer plus an explicit `size_t` length, for example:

  ```c
  crypto_status crypto_des_init(
      crypto_des_context *context,
      const uint8_t *key,
      size_t key_length);
  ```

- Validate pointers before using their corresponding lengths or contents.
- Validate exact key sizes: 8 bytes for DES, 16 bytes for 2TDES, and 24 bytes for 3TDES.
- Return `CRYPTO_STATUS_INVALID_LENGTH` for an incorrect key size.
- Block byte order follows the DES specification and must not depend on host endianness.
- In-place block operations are forbidden.
- Input and output buffers must be distinct and must not overlap.
- Do not silently modify key parity during context initialization.

## DES and TDES validation

- Require odd parity in every encoded DES key byte.
- Provide an explicit helper for callers that choose to set odd parity.
- Reject weak, semi-weak, and potentially weak DES keys.
- Weak-key detection must cover all keys that generate no more than four distinct round keys.
- Compare TDES components by their effective 56-bit values, ignoring parity bits.
- For 2TDES, require K1 and K2 to be distinct.
- For 3TDES, require K1, K2, and K3 to be pairwise distinct.
- Return `CRYPTO_STATUS_DEGENERATE_KEY` when a TDES key bundle collapses to a lower keying option.
- A failed initialization must leave the destination context cleared and invalid.
- Keep unchecked key-schedule helpers private. Do not expose an unchecked public initializer.

## Dependencies and implementation sources

- The library and its tests must not depend on third-party libraries.
- Implement DES and TDES in this repository rather than wrapping another crypto library.
- OpenSSL source may be reviewed as a design reference only.
- Do not copy OpenSSL implementation code, tables, internal APIs, or code structure.
- Verify behavior primarily with published specifications and independent known-answer vectors.

## Build system

- Use CMake with the Ninja generator and GCC toolchain.
- Keep reusable CMake modules under `cmake/modules/`.
- Keep CMake toolchain files under `cmake/toolchains/`.
- Configure, build, and test through `CMakePresets.json`.
- Supported presets are `debug`, `release`, and `coverage`.
- Build both `crypto_static` and `crypto_shared` from the same implementation sources.
- Installed library artifacts are named `libcrypto_des.a` and `libcrypto_des.so` on Linux.
- Install and export the CMake package targets `crypto::static` and `crypto::shared`.
- Apply project warning flags only to repository-owned targets, not to external consumers.
- GCC warnings are errors. Preserve the strict warning set in
  `cmake/modules/CompilerWarnings.cmake`.

## Dev-container requirement

- Perform every configure, build, test, coverage, documentation, and installation verification
  inside the Ubuntu dev-container.
- Do not treat host builds, including Windows or MinGW builds, as project validation.
- The project `Dockerfile` is the source of the development environment.
- `.devcontainer/devcontainer.json` must continue to build from that Dockerfile.
- The container must provide Ubuntu 24.04, GCC, CMake, Ninja, GDB, gcov/lcov, Doxygen, Graphviz,
  and clang-format.

Typical commands inside the container are:

```sh
cmake --preset debug
cmake --build --preset debug
ctest --preset debug

cmake --preset release
cmake --build --preset release
ctest --preset release

cmake --preset coverage
cmake --build --preset coverage
ctest --preset coverage
```

## Documentation

- Generate API documentation with Doxygen as part of the normal Release `ALL` build.
- Doxygen warnings must fail the build.
- Generate HTML documentation; LaTeX output is not required.
- Use Graphviz for supported diagrams.
- Use `README.md` as the Doxygen main page.
- Install generated HTML documentation under `share/doc/crypto/html`.

## Testing and verification

- Use the repository's dependency-free C test harness and CTest.
- Register and run tests through CMake test presets.
- Test both static and shared libraries in Debug and Release builds.
- Use the static library for coverage to avoid conflicting `.gcda` output from the shared object.
- Maintain tests for:
  - published DES, 2TDES, and 3TDES known-answer vectors;
  - encryption/decryption round trips;
  - odd-parity validation and explicit correction;
  - weak and degenerate keys;
  - null arguments and invalid lengths;
  - uninitialized and cleared contexts;
  - prohibited in-place operations;
  - every public status string;
  - installation and consumption through `find_package(crypto CONFIG)`.
- Keep line and function coverage at 100% unless a deliberate exception is documented and
  approved.
- Before completing a change, run the relevant presets inside the dev-container with `-Werror`
  enabled.

## Licensing

- Project code is licensed under Apache-2.0.
- Preserve the repository `LICENSE` file and do not add code with an incompatible license.
