#include <tdes.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "des_internal.h"
#include "tdes_internal.h"

/** @brief Securely erase bounded sensitive storage. */
static void crypto_tdes_secure_zero(void *memory, size_t size)
{
    volatile uint8_t *bytes = (volatile uint8_t *)memory;
    size_t index;

    for (index = 0U; index < size; ++index)
    {
        bytes[index] = UINT8_C(0);
    }
    return;
}

/** @brief Compare effective DES keys while ignoring parity bits. */
static int crypto_tdes_effective_keys_equal(const uint8_t first[CRYPTO_DES_KEY_SIZE],
                                            const uint8_t second[CRYPTO_DES_KEY_SIZE])
{
    uint8_t difference = UINT8_C(0);
    size_t index;
    int result;

    for (index = 0U; index < CRYPTO_DES_KEY_SIZE; ++index)
    {
        difference =
            (uint8_t)(difference | (uint8_t)((first[index] ^ second[index]) & UINT8_C(0xfe)));
    }
    result = (difference == UINT8_C(0)) ? 1 : 0;
    return result;
}

crypto_status crypto_tdes_key_validate_distinct(const uint8_t *key, size_t key_length)
{
    crypto_status status = CRYPTO_STATUS_OK;

    if (key == NULL)
    {
        status = CRYPTO_STATUS_NULL_ARGUMENT;
    }
    else if ((key_length != CRYPTO_TDES2_KEY_SIZE) && (key_length != CRYPTO_TDES3_KEY_SIZE))
    {
        status = CRYPTO_STATUS_INVALID_LENGTH;
    }
    else if (crypto_tdes_effective_keys_equal(key, key + CRYPTO_DES_KEY_SIZE) != 0)
    {
        status = CRYPTO_STATUS_DEGENERATE_KEY;
    }
    else if ((key_length == CRYPTO_TDES3_KEY_SIZE) &&
             ((crypto_tdes_effective_keys_equal(key, key + (2U * CRYPTO_DES_KEY_SIZE)) != 0) ||
              (crypto_tdes_effective_keys_equal(key + CRYPTO_DES_KEY_SIZE,
                                                key + (2U * CRYPTO_DES_KEY_SIZE)) != 0)))
    {
        status = CRYPTO_STATUS_DEGENERATE_KEY;
    }
    return status;
}

/** @brief Determine whether two bounded byte ranges overlap. */
static int crypto_tdes_buffers_overlap(const uint8_t *input, size_t input_length,
                                       const uint8_t *output, size_t output_length)
{
    uintptr_t input_address;
    uintptr_t output_address;
    int result;

    input_address = (uintptr_t)input;
    output_address = (uintptr_t)output;
    if (input_address <= output_address)
    {
        result = ((output_address - input_address) < input_length) ? 1 : 0;
    }
    else
    {
        result = ((input_address - output_address) < output_length) ? 1 : 0;
    }
    return result;
}

/** @brief Expand the TDES key components into private schedules. */
static crypto_status crypto_tdes_make_schedules(crypto_des_schedule schedules[3],
                                                const uint8_t *key, size_t key_length)
{
    crypto_status status = CRYPTO_STATUS_OK;
    size_t component_count;
    size_t component_index;

    component_count = (key_length == CRYPTO_TDES2_KEY_SIZE) ? 2U : 3U;
    for (component_index = 0U; component_index < component_count; ++component_index)
    {
        if (status == CRYPTO_STATUS_OK)
        {
            status = crypto_des_schedule_init(&schedules[component_index],
                                              key + (component_index * CRYPTO_DES_KEY_SIZE),
                                              CRYPTO_DES_KEY_SIZE);
        }
    }
    if ((status == CRYPTO_STATUS_OK) && (component_count == 2U))
    {
        schedules[2] = schedules[0];
    }
    return status;
}

/** @brief Apply the TDES EDE sequence in the selected direction. */
static void crypto_tdes_transform(const crypto_des_schedule schedules[3],
                                  const uint8_t input[CRYPTO_DES_BLOCK_SIZE],
                                  uint8_t output[CRYPTO_DES_BLOCK_SIZE], int decrypt)
{
    uint8_t first[CRYPTO_DES_BLOCK_SIZE];
    uint8_t second[CRYPTO_DES_BLOCK_SIZE];

    if (decrypt == 0)
    {
        crypto_des_schedule_encrypt(&schedules[0], input, first);
        crypto_des_schedule_decrypt(&schedules[1], first, second);
        crypto_des_schedule_encrypt(&schedules[2], second, output);
    }
    else
    {
        crypto_des_schedule_decrypt(&schedules[2], input, first);
        crypto_des_schedule_encrypt(&schedules[1], first, second);
        crypto_des_schedule_decrypt(&schedules[0], second, output);
    }
    crypto_tdes_secure_zero(first, sizeof(first));
    crypto_tdes_secure_zero(second, sizeof(second));
    return;
}

/** @brief XOR two complete blocks into a bounded destination. */
static void crypto_tdes_xor_blocks(uint8_t result[CRYPTO_DES_BLOCK_SIZE],
                                   const uint8_t left[CRYPTO_DES_BLOCK_SIZE],
                                   const uint8_t right[CRYPTO_DES_BLOCK_SIZE])
{
    size_t index;

    for (index = 0U; index < CRYPTO_DES_BLOCK_SIZE; ++index)
    {
        result[index] = (uint8_t)(left[index] ^ right[index]);
    }
    return;
}

/** @brief Increment the low bytes of a CTR counter block as a big-endian integer. */
static void crypto_tdes_counter_increment(uint8_t counter[CRYPTO_DES_BLOCK_SIZE],
                                          size_t counter_length)
{
    size_t index;

    /** Counter part is the low bytes of the big-endian block; carry stops at the nonce. */
    for (index = CRYPTO_DES_BLOCK_SIZE; index > (CRYPTO_DES_BLOCK_SIZE - counter_length); --index)
    {
        counter[index - 1U] = (uint8_t)(counter[index - 1U] + UINT8_C(1));
        if (counter[index - 1U] != 0U)
        {
            break;
        }
    }
    return;
}

/** @brief Validate arguments and perform a one-shot TDES operation. */
static crypto_status crypto_tdes_crypt(const uint8_t *key, size_t key_length,
                                       crypto_cipher_mode mode, const uint8_t *iv, size_t iv_length,
                                       const uint8_t *nonce, size_t nonce_length,
                                       const uint8_t *input, size_t input_length, uint8_t *output,
                                       size_t output_length, int decrypt)
{
    crypto_status status = CRYPTO_STATUS_OK;
    crypto_des_schedule schedules[3];
    uint8_t chain[CRYPTO_DES_BLOCK_SIZE];
    uint8_t scratch[CRYPTO_DES_BLOCK_SIZE];
    size_t block_offset;
    size_t nonce_index;
    size_t schedule_index;

    for (schedule_index = 0U; schedule_index < 3U; ++schedule_index)
    {
        crypto_des_schedule_clear(&schedules[schedule_index]);
    }
    crypto_tdes_secure_zero(chain, sizeof(chain));
    crypto_tdes_secure_zero(scratch, sizeof(scratch));
    if ((key == NULL) || (input == NULL) || (output == NULL))
    {
        status = CRYPTO_STATUS_NULL_ARGUMENT;
    }
    else if ((mode != CRYPTO_CIPHER_MODE_ECB) && (mode != CRYPTO_CIPHER_MODE_CBC) &&
             (mode != CRYPTO_CIPHER_MODE_CFB64) && (mode != CRYPTO_CIPHER_MODE_OFB64) &&
             (mode != CRYPTO_CIPHER_MODE_CTR))
    {
        status = CRYPTO_STATUS_INVALID_MODE;
    }
    else if ((mode != CRYPTO_CIPHER_MODE_CTR) && (nonce_length != 0U))
    {
        status = CRYPTO_STATUS_INVALID_LENGTH;
    }
    else if ((nonce_length != 0U) && (nonce == NULL))
    {
        status = CRYPTO_STATUS_NULL_ARGUMENT;
    }
    else if ((mode != CRYPTO_CIPHER_MODE_CTR) && (iv_length != 0U) &&
             (iv_length != CRYPTO_DES_BLOCK_SIZE))
    {
        status = CRYPTO_STATUS_INVALID_LENGTH;
    }
    else if ((mode == CRYPTO_CIPHER_MODE_ECB) && (iv_length != 0U))
    {
        status = CRYPTO_STATUS_INVALID_LENGTH;
    }
    else if ((mode == CRYPTO_CIPHER_MODE_CTR) &&
             ((nonce_length > CRYPTO_DES_BLOCK_SIZE) ||
              (iv_length != (CRYPTO_DES_BLOCK_SIZE - nonce_length))))
    {
        status = CRYPTO_STATUS_INVALID_LENGTH;
    }
    else if ((mode != CRYPTO_CIPHER_MODE_ECB) && (iv == NULL))
    {
        status = CRYPTO_STATUS_NULL_ARGUMENT;
    }
    else if ((mode != CRYPTO_CIPHER_MODE_ECB) && (mode != CRYPTO_CIPHER_MODE_CTR) &&
             (iv_length != CRYPTO_DES_BLOCK_SIZE))
    {
        status = CRYPTO_STATUS_INVALID_LENGTH;
    }
    else if ((key_length != CRYPTO_TDES2_KEY_SIZE) && (key_length != CRYPTO_TDES3_KEY_SIZE))
    {
        status = CRYPTO_STATUS_INVALID_LENGTH;
    }
    else if (((input_length % CRYPTO_DES_BLOCK_SIZE) != 0U) || (output_length != input_length))
    {
        status = CRYPTO_STATUS_INVALID_LENGTH;
    }
    else if (crypto_tdes_buffers_overlap(input, input_length, output, output_length) != 0)
    {
        status = CRYPTO_STATUS_OVERLAPPING_BUFFERS;
    }
    else
    {
        status = crypto_tdes_make_schedules(schedules, key, key_length);
        if (status == CRYPTO_STATUS_OK)
        {
            if (mode != CRYPTO_CIPHER_MODE_ECB)
            {
                if (mode == CRYPTO_CIPHER_MODE_CTR)
                {
                    (void)memcpy(chain + nonce_length, iv, CRYPTO_DES_BLOCK_SIZE - nonce_length);
                    for (nonce_index = 0U; nonce_index < nonce_length; ++nonce_index)
                    {
                        chain[nonce_index] = nonce[nonce_index];
                    }
                }
                else
                {
                    (void)memcpy(chain, iv, sizeof(chain));
                }
                if (mode == CRYPTO_CIPHER_MODE_CFB64)
                {
                    for (block_offset = 0U; block_offset < input_length;
                         block_offset += CRYPTO_DES_BLOCK_SIZE)
                    {
                        crypto_tdes_transform(schedules, chain, scratch, 0);
                        crypto_tdes_xor_blocks(output + block_offset, input + block_offset, scratch);
                        if (decrypt == 0)
                        {
                            (void)memcpy(chain, output + block_offset, sizeof(chain));
                        }
                        else
                        {
                            (void)memcpy(chain, input + block_offset, sizeof(chain));
                        }
                    }
                }
                else if (mode == CRYPTO_CIPHER_MODE_OFB64)
                {
                    for (block_offset = 0U; block_offset < input_length;
                         block_offset += CRYPTO_DES_BLOCK_SIZE)
                    {
                        crypto_tdes_transform(schedules, chain, scratch, 0);
                        crypto_tdes_xor_blocks(output + block_offset, input + block_offset, scratch);
                        (void)memcpy(chain, scratch, sizeof(chain));
                    }
                }
                else if (mode == CRYPTO_CIPHER_MODE_CTR)
                {
                    /** Encryption and decryption both encrypt a full-block counter. */
                    for (block_offset = 0U; block_offset < input_length;
                         block_offset += CRYPTO_DES_BLOCK_SIZE)
                    {
                        crypto_tdes_transform(schedules, chain, scratch, 0);
                        crypto_tdes_xor_blocks(output + block_offset, input + block_offset, scratch);
                        crypto_tdes_counter_increment(chain, CRYPTO_DES_BLOCK_SIZE - nonce_length);
                    }
                }
                else if (decrypt == 0)
                {
                    for (block_offset = 0U; block_offset < input_length;
                         block_offset += CRYPTO_DES_BLOCK_SIZE)
                    {
                        crypto_tdes_xor_blocks(scratch, input + block_offset, chain);
                        crypto_tdes_transform(schedules, scratch, output + block_offset, 0);
                        (void)memcpy(chain, output + block_offset, sizeof(chain));
                    }
                }
                else
                {
                    for (block_offset = 0U; block_offset < input_length;
                         block_offset += CRYPTO_DES_BLOCK_SIZE)
                    {
                        crypto_tdes_transform(schedules, input + block_offset, scratch, 1);
                        crypto_tdes_xor_blocks(output + block_offset, scratch, chain);
                        (void)memcpy(chain, input + block_offset, sizeof(chain));
                    }
                }
            }
            else
            {
                for (block_offset = 0U; block_offset < input_length;
                     block_offset += CRYPTO_DES_BLOCK_SIZE)
                {
                    crypto_tdes_transform(schedules, input + block_offset, output + block_offset,
                                          decrypt);
                }
            }
        }
    }
    (void)iv;
    (void)nonce;
    crypto_tdes_secure_zero(scratch, sizeof(scratch));
    crypto_tdes_secure_zero(chain, sizeof(chain));
    for (schedule_index = 0U; schedule_index < 3U; ++schedule_index)
    {
        crypto_des_schedule_clear(&schedules[schedule_index]);
    }
    return status;
}

crypto_status crypto_tdes_encrypt(const uint8_t *key, size_t key_length, crypto_cipher_mode mode,
                                  const uint8_t *iv, size_t iv_length, const uint8_t *nonce,
                                  size_t nonce_length, const uint8_t *input, size_t input_length,
                                  uint8_t *output, size_t output_length)
{
    return crypto_tdes_crypt(key, key_length, mode, iv, iv_length, nonce, nonce_length, input,
                             input_length, output, output_length, 0);
}

crypto_status crypto_tdes_decrypt(const uint8_t *key, size_t key_length, crypto_cipher_mode mode,
                                  const uint8_t *iv, size_t iv_length, const uint8_t *nonce,
                                  size_t nonce_length, const uint8_t *input, size_t input_length,
                                  uint8_t *output, size_t output_length)
{
    return crypto_tdes_crypt(key, key_length, mode, iv, iv_length, nonce, nonce_length, input,
                             input_length, output, output_length, 1);
}
