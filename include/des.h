#ifndef CRYPTO_DES_H
#define CRYPTO_DES_H

/**
 * @file des.h
 * @brief Public one-shot API for the DES block cipher.
 */

#include <stddef.h>
#include <stdint.h>

#include <cipher.h>
#include <export.h>
#include <status.h>

#define CRYPTO_DES_BLOCK_SIZE 8U /**< DES block size in bytes. */
#define CRYPTO_DES_KEY_SIZE 8U   /**< Encoded DES key size including parity bits. */

/**
 * @brief Encrypt complete DES blocks without retaining a public key context.
 * @param key Pointer to the encoded DES key; parity bits are ignored.
 * @param key_length Key length; must equal CRYPTO_DES_KEY_SIZE.
 * @param mode Cipher mode; CRYPTO_CIPHER_MODE_ECB, CRYPTO_CIPHER_MODE_CBC, or
 *        CRYPTO_CIPHER_MODE_CFB64.
 * @param iv Initialization vector; required and 8 bytes long when @p mode is
 *        CRYPTO_CIPHER_MODE_CBC or CRYPTO_CIPHER_MODE_CFB64, ignored when @p mode is
 *        CRYPTO_CIPHER_MODE_ECB.
 * @param iv_length Initialization-vector length; must equal zero for ECB or
 *        CRYPTO_DES_BLOCK_SIZE for CBC and CFB64.
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
 * @param key Pointer to the encoded DES key; parity bits are ignored.
 * @param key_length Key length; must equal CRYPTO_DES_KEY_SIZE.
 * @param mode Cipher mode; CRYPTO_CIPHER_MODE_ECB, CRYPTO_CIPHER_MODE_CBC, or
 *        CRYPTO_CIPHER_MODE_CFB64.
 * @param iv Initialization vector; required and 8 bytes long when @p mode is
 *        CRYPTO_CIPHER_MODE_CBC or CRYPTO_CIPHER_MODE_CFB64, ignored when @p mode is
 *        CRYPTO_CIPHER_MODE_ECB.
 * @param iv_length Initialization-vector length; must equal zero for ECB or
 *        CRYPTO_DES_BLOCK_SIZE for CBC and CFB64.
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
