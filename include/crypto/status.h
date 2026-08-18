#ifndef CRYPTO_STATUS_H
#define CRYPTO_STATUS_H

/**
 * @file status.h
 * @brief Shared status codes returned by the crypto API.
 */

#include <crypto/export.h>

/** @brief Result codes returned by fallible library operations. */
typedef enum crypto_status
{
    CRYPTO_STATUS_OK = 0,              /**< The operation completed successfully. */
    CRYPTO_STATUS_NULL_ARGUMENT,       /**< A required pointer argument was NULL. */
    CRYPTO_STATUS_INVALID_KEY_PARITY,  /**< A DES key byte does not have odd parity. */
    CRYPTO_STATUS_WEAK_KEY,            /**< The key produces too few round keys. */
    CRYPTO_STATUS_DEGENERATE_KEY,      /**< TDES collapses to a lower keying option. */
    CRYPTO_STATUS_INVALID_CONTEXT,     /**< The context is not initialized. */
    CRYPTO_STATUS_OVERLAPPING_BUFFERS, /**< Input and output buffers are identical. */
    CRYPTO_STATUS_INVALID_LENGTH       /**< A buffer has an unexpected size. */
} crypto_status;

/**
 * @brief Return an allocation-free description of a status value.
 * @param status Status value to describe.
 * @return Pointer to a static string literal.
 */
CRYPTO_API const char *crypto_status_string(crypto_status status);

#endif
