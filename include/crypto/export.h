#ifndef CRYPTO_EXPORT_H
#define CRYPTO_EXPORT_H

/**
 * @file export.h
 * @brief Cross-platform symbol visibility definitions.
 */

/** @brief Export or import a symbol from the shared crypto library. */
#if defined(_WIN32) && defined(CRYPTO_BUILD_SHARED)
#define CRYPTO_API __declspec(dllexport)
#elif defined(_WIN32) && defined(CRYPTO_USE_SHARED)
#define CRYPTO_API __declspec(dllimport)
#elif defined(__GNUC__)
#define CRYPTO_API __attribute__((visibility("default")))
#else
#define CRYPTO_API
#endif

#endif
