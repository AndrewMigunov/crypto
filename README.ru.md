# cryptomoon

[English](README.md) | [Русский](README.ru.md)

`cryptomoon` — библиотека на языке Си для шифрования и расшифрования алгоритмами DES, двухкомпонентного и трёхкомпонентного Triple DES. Проект собирает статическую и динамическую библиотеки, а также консольное приложение `cryptomoon-cli`. Используется стандарт **ISO C99** без расширений GNU.

Библиотека поддерживает режимы ECB, CBC, CFB64, OFB64 и CTR. Она обрабатывает данные целыми блоками по 8 байт и не добавляет дополнение. Публичные заголовочные файлы находятся в [`include/`](include/).

## Сборка и тестирование

Откройте репозиторий в dev-container на базе Ubuntu 24.04. В нём установлены GCC, CMake, Ninja, Doxygen и остальные инструменты для сборки. Для сборки и запуска тестов используйте пресеты CMake:

```sh
cmake --preset debug
cmake --build --preset debug
ctest --preset debug

cmake --preset release
cmake --build --preset release
ctest --preset release
```

Сборка Release также создаёт документацию API в `build/release/docs/html/index.html`.

## Пример CLI

Пример шифрует один блок DES, заданный шестнадцатеричной строкой:

```sh
cryptomoon-cli encrypt --algorithm des \
    --key 133457799bbcdff1 --input 0123456789abcdef
```

Результат: `85e813540f0ab405`. Команда `cryptomoon-cli --help` показывает режимы, работу с файлами и все доступные параметры.

## Лицензия

Apache-2.0. См. [LICENSE](LICENSE).
