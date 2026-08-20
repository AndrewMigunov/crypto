#ifndef CRYPTO_DES_H
#define CRYPTO_DES_H

/**
 * @file des.h
 * @brief Public one-shot API for the DES block cipher.
 */

#include <stddef.h>
#include <stdint.h>

#include <crypto/cipher.h>
#include <crypto/export.h>
#include <crypto/status.h>

#define CRYPTO_DES_BLOCK_SIZE 8U /**< DES block size in bytes. */
#define CRYPTO_DES_KEY_SIZE 8U   /**< Encoded DES key size including parity bits. */

/**
 * @brief Encrypt complete DES blocks without retaining a public key context.
 * @param key Pointer to the encoded DES key.
 * @param key_length Key length; must equal CRYPTO_DES_KEY_SIZE.
 * @param mode Cipher mode; currently only CRYPTO_CIPHER_MODE_ECB is supported.
 * @param iv Initialization vector; ignored when @p iv_length is zero for ECB.
 * @param iv_length Initialization-vector length; must be zero for ECB.
 * @param input Pointer to the input blocks.
 * @param input_length Input length; must be a multiple of CRYPTO_DES_BLOCK_SIZE.
 * @param output Pointer to the output blocks; it must not overlap @p input.
 * @param output_length Output length; must equal @p input_length.
 * @return CRYPTO_STATUS_OK on success or a validation error.
 */
CRYPTO_API crypto_status crypto_des_encrypt(const uint8_t *key, size_t key_length,
                                            crypto_cipher_mode mode, const uint8_t *iv,
                                            size_t iv_length, const uint8_t *input,
                                            size_t input_length, uint8_t *output,
                                            size_t output_length);

/**
 * @brief Decrypt complete DES blocks without retaining a public key context.
 * @param key Pointer to the encoded DES key.
 * @param key_length Key length; must equal CRYPTO_DES_KEY_SIZE.
 * @param mode Cipher mode; currently only CRYPTO_CIPHER_MODE_ECB is supported.
 * @param iv Initialization vector; ignored when @p iv_length is zero for ECB.
 * @param iv_length Initialization-vector length; must be zero for ECB.
 * @param input Pointer to the input blocks.
 * @param input_length Input length; must be a multiple of CRYPTO_DES_BLOCK_SIZE.
 * @param output Pointer to the output blocks; it must not overlap @p input.
 * @param output_length Output length; must equal @p input_length.
 * @return CRYPTO_STATUS_OK on success or a validation error.
 */
CRYPTO_API crypto_status crypto_des_decrypt(const uint8_t *key, size_t key_length,
                                            crypto_cipher_mode mode, const uint8_t *iv,
                                            size_t iv_length, const uint8_t *input,
                                            size_t input_length, uint8_t *output,
                                            size_t output_length);

#endif
