#ifndef CRYPTO_DES_INTERNAL_H
#define CRYPTO_DES_INTERNAL_H

/**
 * @file des_internal.h
 * @brief Private DES key-schedule operations shared with Triple DES.
 */

#include <stddef.h>
#include <stdint.h>

#include <crypto/des.h>
#include <crypto/status.h>

#define CRYPTO_DES_ROUND_COUNT 16U /**< Number of DES Feistel rounds. */

/** @brief Private expanded DES key schedule. */
typedef struct crypto_des_schedule
{
    /** Expanded 48-bit round keys stored in the low bits of each element. */
    uint64_t round_keys[CRYPTO_DES_ROUND_COUNT];
} crypto_des_schedule;

/**
 * @brief Validate and expand a DES key.
 * @param schedule Schedule to initialize.
 * @param key Pointer to the encoded DES key.
 * @param key_length Encoded key length.
 * @return CRYPTO_STATUS_OK on success or a validation error.
 */
crypto_status crypto_des_schedule_init(crypto_des_schedule *schedule, const uint8_t *key,
                                       size_t key_length);

/**
 * @brief Encrypt one block with an initialized private schedule.
 * @param schedule Initialized DES schedule.
 * @param input Input block.
 * @param output Output block.
 */
void crypto_des_schedule_encrypt(const crypto_des_schedule *schedule,
                                 const uint8_t input[CRYPTO_DES_BLOCK_SIZE],
                                 uint8_t output[CRYPTO_DES_BLOCK_SIZE]);

/**
 * @brief Decrypt one block with an initialized private schedule.
 * @param schedule Initialized DES schedule.
 * @param input Input block.
 * @param output Output block.
 */
void crypto_des_schedule_decrypt(const crypto_des_schedule *schedule,
                                 const uint8_t input[CRYPTO_DES_BLOCK_SIZE],
                                 uint8_t output[CRYPTO_DES_BLOCK_SIZE]);

/**
 * @brief Securely erase a private DES schedule.
 * @param schedule Schedule to erase.
 */
void crypto_des_schedule_clear(crypto_des_schedule *schedule);

#endif
