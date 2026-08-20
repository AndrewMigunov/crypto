# AGENTS.md

## Project scope

This repository contains the `cryptomoon` C99 library and its `cryptomoon-cli` command-line
consumer. The first implementation stage supports:

- DES block encryption and decryption;
- two-key Triple DES (2TDES) using K1, K2, K1;
- three-key Triple DES (3TDES) using K1, K2, K3;
- ECB operations over any number of complete blocks;
- no block modes and no padding;
- CLI encryption and decryption from hexadecimal text or raw files.

DES and TDES are obsolete algorithms. Treat this project as an educational and legacy
interoperability implementation, not as a suitable primitive for new security systems.

## Language and code style

- Write production code and tests in strict ISO C99.
- Do not use GNU language extensions.
- Use the Allman brace style defined by `.clang-format`.
- Every C function must contain exactly one `return` statement, including static helpers and
  test functions.
- Return a single call expression directly instead of introducing a variable used only by that
  return statement.
- Write code comments in English.
- All code comments must use Doxygen syntax.
- Vendored third-party files under `tests/third_party/` retain their upstream formatting and are
  exempt from repository style, comment, and single-return rules.
- Document public functions with `@brief`, `@param`, and `@return` where applicable.
- Prefer fixed-width integer types from `<stdint.h>`.
- Avoid global mutable state.
- Keep public headers directly in `include/` and C implementation files in `src/`.
- Keep command-line applications under `apps/` and exercise only the public library API from
  them.

## Memory policy

- Do not use dynamic memory allocation.
- Calls to `malloc`, `calloc`, `realloc`, and `free` are forbidden.
- The caller supplies all input and output buffers.
- Use only bounded, fixed-size local storage inside the library.
- Keep key schedules private and explicitly erase all derived key material before a public
  one-shot operation returns.
- Sensitive-data erasure must be implemented so that the compiler cannot remove it as a dead
  store.

## Public API conventions

- Fallible public functions return the `crypto_status` enum.
- `CRYPTO_STATUS_OK` must remain zero.
- Do not return magic integer error codes.
- Append new status values to the enum; do not renumber published values.
- Key, IV, input, and output parameters use a pointer plus an explicit `size_t` length, for
  example:

  ```c
  crypto_status crypto_des_encrypt(
      const uint8_t *key,
      size_t key_length,
      crypto_cipher_mode mode,
      const uint8_t *iv,
      size_t iv_length,
      const uint8_t *input,
      size_t input_length,
      uint8_t *output,
      size_t output_length);
  ```

- Validate pointers before using their corresponding lengths or contents.
- Validate exact key sizes: 8 bytes for DES, 16 bytes for 2TDES, and 24 bytes for 3TDES.
- Return `CRYPTO_STATUS_INVALID_LENGTH` for an incorrect key size.
- Block byte order follows the DES specification and must not depend on host endianness.
- In-place block operations are forbidden.
- Input and output buffers must be distinct and must not overlap.
- Ignore DES parity bits during encryption and decryption without modifying caller-owned keys.
- Keep a private odd-parity normalization helper available for future key generation.

## DES and TDES validation

- Require future generated DES keys to use odd parity in every encoded key byte.
- Reject weak, semi-weak, and potentially weak DES keys.
- Weak-key detection must cover all keys that generate no more than four distinct round keys.
- Compare TDES components by their effective 56-bit values, ignoring parity bits.
- For 2TDES, require K1 and K2 to be distinct.
- For 3TDES, require K1, K2, and K3 to be pairwise distinct.
- Return `CRYPTO_STATUS_DEGENERATE_KEY` when a TDES key bundle collapses to a lower keying option.
- Keep unchecked key-schedule helpers and all derived key material private.

## Dependencies and implementation sources

- The library must not depend on third-party libraries.
- Tests use the vendored, header-only Acutest revision recorded under
  `tests/third_party/acutest/`; do not fetch dependencies during configure or build.
- Treat the Acutest include directory as a system include so project warning policy applies only
  to repository-owned test code.
- Implement DES and TDES in this repository rather than wrapping another crypto library.
- Verify behavior primarily with published specifications and independent known-answer vectors.

## Build system

- Use CMake with the Ninja generator and GCC toolchain.
- Keep reusable CMake modules under `cmake/modules/`.
- Keep CMake toolchain files under `cmake/toolchains/`.
- Configure, build, and test through `CMakePresets.json`.
- Supported presets are `debug`, `release`, and `coverage`.
- Build both `cryptomoon_static` and `cryptomoon_shared` from the same implementation sources.
- Installed library artifacts are named `libcryptomoon.a` and `libcryptomoon.so` on Linux.
- Install and export the CMake package targets `cryptomoon::static` and `cryptomoon::shared`.
- Apply project warning flags only to repository-owned targets, not to external consumers.
- GCC warnings are errors. Preserve the strict warning set in
  `cmake/modules/CompilerWarnings.cmake`.

## Git commits

- Format commit messages according to Conventional Commits 1.0.0.
- Use the form `<type>[optional scope]: <description>` for every commit subject.
- Use lowercase types such as `feat`, `fix`, `docs`, `test`, `refactor`, `build`, `ci`, `chore`,
  `perf`, `style`, and `revert`.
- Write the description in the imperative mood, keep it concise, and do not end it with a period.
- Mark breaking changes with `!` before the colon and explain them in a `BREAKING CHANGE:` footer.
- Keep each commit focused on one logical change.

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
- Install generated HTML documentation under `share/doc/cryptomoon/html`.

## Testing and verification

- Use the vendored Acutest C test harness and register its executables through CTest.
- Register and run tests through CMake test presets.
- Test both static and shared libraries in Debug and Release builds.
- Use the static library for coverage to avoid conflicting `.gcda` output from the shared object.
- Maintain tests for:
  - published DES, 2TDES, and 3TDES known-answer vectors;
  - encryption/decryption round trips;
  - parity-insensitive DES and TDES encryption and decryption;
  - weak and degenerate keys;
  - null arguments and invalid lengths;
  - one-shot key, mode, IV, input, and output validation;
  - prohibited in-place operations;
  - every public status string;
  - CLI known-answer vectors, invalid input, and raw-file round trips;
  - installation and consumption through `find_package(cryptomoon CONFIG)`.
- Keep line and function coverage at 100% unless a deliberate exception is documented and
  approved.
- Before completing a change, run the relevant presets inside the dev-container with `-Werror`
  enabled.

## Licensing

- Project code is licensed under Apache-2.0.
- Preserve the repository `LICENSE` file and do not add code with an incompatible license.
- Preserve Acutest's embedded MIT notice and its vendored `LICENSE.md` file.
