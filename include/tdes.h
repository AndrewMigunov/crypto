#ifndef CRYPTO_TDES_H
#define CRYPTO_TDES_H

/**
 * @file tdes.h
 * @brief Public one-shot API for two-key and three-key Triple DES.
 */

#include <stddef.h>
#include <stdint.h>

#include <cipher.h>
#include <des.h>
#include <export.h>
#include <status.h>

#define CRYPTO_TDES2_KEY_SIZE 16U /**< Encoded size of K1 || K2 in bytes. */
#define CRYPTO_TDES3_KEY_SIZE 24U /**< Encoded size of K1 || K2 || K3 in bytes. */

/**
 * @brief Encrypt complete blocks with two-key or three-key Triple DES.
 * @param key Pointer to K1 || K2 or K1 || K2 || K3; parity bits are ignored.
 * @param key_length Key length; must equal CRYPTO_TDES2_KEY_SIZE or CRYPTO_TDES3_KEY_SIZE.
 * @param mode Cipher mode; CRYPTO_CIPHER_MODE_ECB or CRYPTO_CIPHER_MODE_CBC.
 * @param iv Initialization vector; required and 8 bytes long when @p mode is
 *        CRYPTO_CIPHER_MODE_CBC, ignored when @p mode is CRYPTO_CIPHER_MODE_ECB.
 * @param iv_length Initialization-vector length; must equal zero for ECB or
 *        CRYPTO_DES_BLOCK_SIZE for CBC.
 * @param input Pointer to the input blocks.
 * @param input_length Input length; must be a multiple of CRYPTO_DES_BLOCK_SIZE.
 * @param output Pointer to the output blocks; it must not overlap @p input.
 * @param output_length Output length; must equal @p input_length.
 * @return CRYPTO_STATUS_OK on success or a validation error.
 */
CRYPTO_API crypto_status crypto_tdes_encrypt(const uint8_t *key, size_t key_length,
                                             crypto_cipher_mode mode, const uint8_t *iv,
                                             size_t iv_length, const uint8_t *input,
                                             size_t input_length, uint8_t *output,
                                             size_t output_length);

/**
 * @brief Decrypt complete blocks with two-key or three-key Triple DES.
 * @param key Pointer to K1 || K2 or K1 || K2 || K3; parity bits are ignored.
 * @param key_length Key length; must equal CRYPTO_TDES2_KEY_SIZE or CRYPTO_TDES3_KEY_SIZE.
 * @param mode Cipher mode; CRYPTO_CIPHER_MODE_ECB or CRYPTO_CIPHER_MODE_CBC.
 * @param iv Initialization vector; required and 8 bytes long when @p mode is
 *        CRYPTO_CIPHER_MODE_CBC, ignored when @p mode is CRYPTO_CIPHER_MODE_ECB.
 * @param iv_length Initialization-vector length; must equal zero for ECB or
 *        CRYPTO_DES_BLOCK_SIZE for CBC.
 * @param input Pointer to the input blocks.
 * @param input_length Input length; must be a multiple of CRYPTO_DES_BLOCK_SIZE.
 * @param output Pointer to the output blocks; it must not overlap @p input.
 * @param output_length Output length; must equal @p input_length.
 * @return CRYPTO_STATUS_OK on success or a validation error.
 */
CRYPTO_API crypto_status crypto_tdes_decrypt(const uint8_t *key, size_t key_length,
                                             crypto_cipher_mode mode, const uint8_t *iv,
                                             size_t iv_length, const uint8_t *input,
                                             size_t input_length, uint8_t *output,
                                             size_t output_length);

#endif
