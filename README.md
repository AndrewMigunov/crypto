# cryptomoon

[English](README.md) | [Русский](README.ru.md)

`cryptomoon` is a C library for DES and two-key and three-key Triple DES encryption and decryption. It provides static and shared libraries and the `cryptomoon-cli` command-line application. The project uses **ISO C99** without GNU language extensions.

The library supports ECB, CBC, CFB64, OFB64, and CTR modes. It processes complete 8-byte blocks and does not add padding. Public headers are in [`include/`](include/).

## Build and test

Open the repository in its Ubuntu 24.04 dev container. It contains GCC, CMake, Ninja, Doxygen, and the other required build tools. Build and test with the CMake presets:

```sh
cmake --preset debug
cmake --build --preset debug
ctest --preset debug

cmake --preset release
cmake --build --preset release
ctest --preset release
```

The Release build also generates API documentation at `build/release/docs/html/index.html`.

## CLI example

Encrypt one DES block given as hexadecimal text:

```sh
cryptomoon-cli encrypt --algorithm des \
    --key 133457799bbcdff1 --input 0123456789abcdef
```

The output is `85e813540f0ab405`. Run `cryptomoon-cli --help` for modes, file input and output, and all options.

## License

Apache-2.0. See [LICENSE](LICENSE).
