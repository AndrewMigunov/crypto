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
 * @param mode Cipher mode; CRYPTO_CIPHER_MODE_ECB, CRYPTO_CIPHER_MODE_CBC,
 *        CRYPTO_CIPHER_MODE_CFB64, CRYPTO_CIPHER_MODE_OFB64, or
 *        CRYPTO_CIPHER_MODE_CTR.
 * @param iv Initialization vector; in CRYPTO_CIPHER_MODE_CTR it is the initial
 *        counter value occupying the low bytes of the counter block. Required
 *        and 8 bytes long for CBC, CFB64, or OFB64, required and equal to
 *        CRYPTO_DES_BLOCK_SIZE - @p nonce_length bytes for CTR, and zero-length
 *        for ECB.
 * @param iv_length Length of @p iv in bytes; must equal zero for ECB or
 *        CRYPTO_DES_BLOCK_SIZE - @p nonce_length for CTR, otherwise
 *        CRYPTO_DES_BLOCK_SIZE for CBC, CFB64, and OFB64.
 * @param nonce CTR nonce occupying the high bytes of the counter block; it must
 *        be NULL when @p nonce_length is zero and must be NULL with a zero
 *        length for every mode except CRYPTO_CIPHER_MODE_CTR.
 * @param nonce_length Length of @p nonce in bytes; must be in the range
 *        [0, 7] for CTR and must be zero for every other mode.
 * @param input Pointer to the input blocks.
 * @param input_length Input length; must be a multiple of CRYPTO_DES_BLOCK_SIZE.
 * @param output Pointer to the output blocks; it must not overlap the input bytes
 *        written by this call.
 * @param[in,out] output_length On input the capacity of @p output in bytes; it must
 *        be at least @p input_length. On success it is updated to the number of bytes
 *        actually written, which equals @p input_length. It is left unchanged on any
 *        error return.
 * @return CRYPTO_STATUS_OK on success or a validation error.
 */
CRYPTO_API crypto_status crypto_des_encrypt(const uint8_t *key, size_t key_length,
                                            crypto_cipher_mode mode, const uint8_t *iv,
                                            size_t iv_length, const uint8_t *nonce,
                                            size_t nonce_length, const uint8_t *input,
                                            size_t input_length, uint8_t *output,
                                            size_t *output_length);

/**
 * @brief Decrypt complete DES blocks without retaining a public key context.
 * @param key Pointer to the encoded DES key; parity bits are ignored.
 * @param key_length Key length; must equal CRYPTO_DES_KEY_SIZE.
 * @param mode Cipher mode; CRYPTO_CIPHER_MODE_ECB, CRYPTO_CIPHER_MODE_CBC,
 *        CRYPTO_CIPHER_MODE_CFB64, CRYPTO_CIPHER_MODE_OFB64, or
 *        CRYPTO_CIPHER_MODE_CTR.
 * @param iv Initialization vector; in CRYPTO_CIPHER_MODE_CTR it is the initial
 *        counter value occupying the low bytes of the counter block. Required
 *        and 8 bytes long for CBC, CFB64, or OFB64, required and equal to
 *        CRYPTO_DES_BLOCK_SIZE - @p nonce_length bytes for CTR, and zero-length
 *        for ECB.
 * @param iv_length Length of @p iv in bytes; must equal zero for ECB or
 *        CRYPTO_DES_BLOCK_SIZE - @p nonce_length for CTR, otherwise
 *        CRYPTO_DES_BLOCK_SIZE for CBC, CFB64, and OFB64.
 * @param nonce CTR nonce occupying the high bytes of the counter block; it must
 *        be NULL when @p nonce_length is zero and must be NULL with a zero
 *        length for every mode except CRYPTO_CIPHER_MODE_CTR.
 * @param nonce_length Length of @p nonce in bytes; must be in the range
 *        [0, 7] for CTR and must be zero for every other mode.
 * @param input Pointer to the input blocks.
 * @param input_length Input length; must be a multiple of CRYPTO_DES_BLOCK_SIZE.
 * @param output Pointer to the output blocks; it must not overlap the input bytes
 *        written by this call.
 * @param[in,out] output_length On input the capacity of @p output in bytes; it must
 *        be at least @p input_length. On success it is updated to the number of bytes
 *        actually written, which equals @p input_length. It is left unchanged on any
 *        error return.
 * @return CRYPTO_STATUS_OK on success or a validation error.
 */
CRYPTO_API crypto_status crypto_des_decrypt(const uint8_t *key, size_t key_length,
                                            crypto_cipher_mode mode, const uint8_t *iv,
                                            size_t iv_length, const uint8_t *nonce,
                                            size_t nonce_length, const uint8_t *input,
                                            size_t input_length, uint8_t *output,
                                            size_t *output_length);

#endif
