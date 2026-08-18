#ifndef CRYPTO_DES_H
#define CRYPTO_DES_H

/**
 * @file des.h
 * @brief Public API for the DES block cipher.
 */

#include <stdint.h>
#include <stddef.h>

#include <crypto/export.h>
#include <crypto/status.h>

#define CRYPTO_DES_BLOCK_SIZE 8U   /**< DES block size in bytes. */
#define CRYPTO_DES_KEY_SIZE 8U     /**< Encoded DES key size including parity bits. */
#define CRYPTO_DES_ROUND_COUNT 16U /**< Number of DES Feistel rounds. */

/** @brief Caller-owned DES key schedule. */
typedef struct crypto_des_context
{
    /** Expanded 48-bit round keys stored in the low bits of each element. */
    uint64_t round_keys[CRYPTO_DES_ROUND_COUNT];
    /** Internal marker used to reject uninitialized or cleared contexts. */
    uint32_t initialized;
} crypto_des_context;

/**
 * @brief Validate odd parity without modifying a DES key.
 * @param key Pointer to the key bytes.
 * @param key_length Key length; must equal CRYPTO_DES_KEY_SIZE.
 * @return CRYPTO_STATUS_OK on success or a validation error.
 */
CRYPTO_API crypto_status crypto_des_key_check_parity(
    const uint8_t *key, size_t key_length);
/**
 * @brief Set the low bit of every DES key byte to obtain odd parity.
 * @param key Pointer to the mutable key bytes.
 * @param key_length Key length; must equal CRYPTO_DES_KEY_SIZE.
 * @return CRYPTO_STATUS_OK on success or an argument error.
 */
CRYPTO_API crypto_status crypto_des_key_set_odd_parity(uint8_t *key, size_t key_length);
/**
 * @brief Validate DES key length, parity, and weak-key properties.
 * @param key Pointer to the key bytes.
 * @param key_length Key length; must equal CRYPTO_DES_KEY_SIZE.
 * @return CRYPTO_STATUS_OK on success or a validation error.
 */
CRYPTO_API crypto_status crypto_des_key_validate(const uint8_t *key, size_t key_length);
/**
 * @brief Validate and expand a DES key into a caller-owned context.
 * @param context Context to initialize.
 * @param key Pointer to the key bytes.
 * @param key_length Key length; must equal CRYPTO_DES_KEY_SIZE.
 * @return CRYPTO_STATUS_OK on success or an initialization error.
 */
CRYPTO_API crypto_status crypto_des_init(
    crypto_des_context *context,
    const uint8_t *key,
    size_t key_length);
/**
 * @brief Encrypt exactly one DES block.
 * @param context Initialized DES context.
 * @param input Input block. It must not overlap @p output.
 * @param output Output block.
 * @return CRYPTO_STATUS_OK on success or an argument/context error.
 */
CRYPTO_API crypto_status crypto_des_encrypt_block(
    const crypto_des_context *context,
    const uint8_t input[CRYPTO_DES_BLOCK_SIZE],
    uint8_t output[CRYPTO_DES_BLOCK_SIZE]);
/**
 * @brief Decrypt exactly one DES block.
 * @param context Initialized DES context.
 * @param input Input block. It must not overlap @p output.
 * @param output Output block.
 * @return CRYPTO_STATUS_OK on success or an argument/context error.
 */
CRYPTO_API crypto_status crypto_des_decrypt_block(
    const crypto_des_context *context,
    const uint8_t input[CRYPTO_DES_BLOCK_SIZE],
    uint8_t output[CRYPTO_DES_BLOCK_SIZE]);
/**
 * @brief Erase derived key material and invalidate a DES context.
 * @param context Context to erase.
 * @return CRYPTO_STATUS_OK on success or CRYPTO_STATUS_NULL_ARGUMENT.
 */
CRYPTO_API crypto_status crypto_des_clear(crypto_des_context *context);

#endif
