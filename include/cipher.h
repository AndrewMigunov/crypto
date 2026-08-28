#ifndef CRYPTO_CIPHER_H
#define CRYPTO_CIPHER_H

/**
 * @file cipher.h
 * @brief Shared block-cipher mode definitions.
 */

/** @brief Supported block-cipher modes. */
typedef enum crypto_cipher_mode
{
    CRYPTO_CIPHER_MODE_ECB = 0, /**< Electronic Codebook mode. */
    CRYPTO_CIPHER_MODE_CBC,     /**< Cipher Block Chaining mode. */
    CRYPTO_CIPHER_MODE_CFB64,   /**< Cipher Feedback mode with full-block feedback; CFB-8 may follow. */
    CRYPTO_CIPHER_MODE_OFB64    /**< Output Feedback mode with full-block feedback. */
} crypto_cipher_mode;

#endif
