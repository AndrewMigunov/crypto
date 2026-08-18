#ifndef CRYPTO_TDES_H
#define CRYPTO_TDES_H

/**
 * @file tdes.h
 * @brief Public API for two-key and three-key Triple DES.
 */

#include <stdint.h>
#include <stddef.h>

#include <crypto/des.h>
#include <crypto/export.h>
#include <crypto/status.h>

#define CRYPTO_TDES2_KEY_SIZE 16U /**< Encoded size of K1 || K2 in bytes. */
#define CRYPTO_TDES3_KEY_SIZE 24U /**< Encoded size of K1 || K2 || K3 in bytes. */

/** @brief Caller-owned TDES key schedules. */
typedef struct crypto_tdes_context
{
    /** EDE uses K1, K2, K1 for 2TDES and K1, K2, K3 for 3TDES. */
    crypto_des_context keys[3];
    /** Internal marker used to reject uninitialized or cleared contexts. */
    uint32_t initialized;
} crypto_tdes_context;

/**
 * @brief Initialize two-key TDES from K1 || K2; K3 is derived as K1.
 * @param context Context to initialize.
 * @param key Pointer to the concatenated key bytes.
 * @param key_length Key length; must equal CRYPTO_TDES2_KEY_SIZE.
 * @return CRYPTO_STATUS_OK on success or a validation error.
 */
CRYPTO_API crypto_status crypto_tdes2_init(
    crypto_tdes_context *context,
    const uint8_t *key,
    size_t key_length);
/**
 * @brief Initialize three-key TDES from K1 || K2 || K3.
 * @param context Context to initialize.
 * @param key Pointer to the concatenated key bytes.
 * @param key_length Key length; must equal CRYPTO_TDES3_KEY_SIZE.
 * @return CRYPTO_STATUS_OK on success or a validation error.
 */
CRYPTO_API crypto_status crypto_tdes3_init(
    crypto_tdes_context *context,
    const uint8_t *key,
    size_t key_length);
/**
 * @brief Apply the TDES encrypt-decrypt-encrypt sequence to one block.
 * @param context Initialized TDES context.
 * @param input Input block. It must not overlap @p output.
 * @param output Output block.
 * @return CRYPTO_STATUS_OK on success or an argument/context error.
 */
CRYPTO_API crypto_status crypto_tdes_encrypt_block(
    const crypto_tdes_context *context,
    const uint8_t input[CRYPTO_DES_BLOCK_SIZE],
    uint8_t output[CRYPTO_DES_BLOCK_SIZE]);
/**
 * @brief Apply the inverse TDES decrypt-encrypt-decrypt sequence to one block.
 * @param context Initialized TDES context.
 * @param input Input block. It must not overlap @p output.
 * @param output Output block.
 * @return CRYPTO_STATUS_OK on success or an argument/context error.
 */
CRYPTO_API crypto_status crypto_tdes_decrypt_block(
    const crypto_tdes_context *context,
    const uint8_t input[CRYPTO_DES_BLOCK_SIZE],
    uint8_t output[CRYPTO_DES_BLOCK_SIZE]);
/**
 * @brief Erase all key schedules and invalidate a TDES context.
 * @param context Context to erase.
 * @return CRYPTO_STATUS_OK on success or CRYPTO_STATUS_NULL_ARGUMENT.
 */
CRYPTO_API crypto_status crypto_tdes_clear(crypto_tdes_context *context);

#endif
