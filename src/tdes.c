#include <crypto/tdes.h>

#include <stddef.h>

#define CRYPTO_TDES_CONTEXT_MAGIC UINT32_C(0x54444553)

static void crypto_tdes_secure_zero(void *memory, size_t size)
{
    /** Keep context erasure observable to the compiler. */
    volatile uint8_t *bytes = (volatile uint8_t *)memory;
    size_t index;

    for (index = 0U; index < size; ++index)
    {
        bytes[index] = UINT8_C(0);
    }
}

static int crypto_tdes_effective_keys_equal(const uint8_t first[CRYPTO_DES_KEY_SIZE],
                                            const uint8_t second[CRYPTO_DES_KEY_SIZE])
{
    uint8_t difference = UINT8_C(0);
    size_t index;
    int result;

    /** Parity bits do not contribute to the effective 56-bit DES key. */
    for (index = 0U; index < CRYPTO_DES_KEY_SIZE; ++index)
    {
        difference = (uint8_t)(difference
                               | (uint8_t)((first[index] ^ second[index]) & UINT8_C(0xfe)));
    }
    result = (difference == UINT8_C(0)) ? 1 : 0;
    return result;
}

crypto_status crypto_tdes2_init(crypto_tdes_context *context,
                                const uint8_t *key, size_t key_length)
{
    crypto_status status = CRYPTO_STATUS_OK;

    if ((context == NULL) || (key == NULL))
    {
        status = CRYPTO_STATUS_NULL_ARGUMENT;
    }
    else
    {
        crypto_tdes_secure_zero(context, sizeof(*context));
        if (key_length != CRYPTO_TDES2_KEY_SIZE)
        {
            status = CRYPTO_STATUS_INVALID_LENGTH;
        }
        else if (crypto_tdes_effective_keys_equal(key, key + CRYPTO_DES_KEY_SIZE) != 0)
        {
            status = CRYPTO_STATUS_DEGENERATE_KEY;
        }
        else
        {
            status = crypto_des_init(&context->keys[0], key, CRYPTO_DES_KEY_SIZE);
            if (status == CRYPTO_STATUS_OK)
            {
                status = crypto_des_init(&context->keys[1], key + CRYPTO_DES_KEY_SIZE,
                                         CRYPTO_DES_KEY_SIZE);
            }
            if (status == CRYPTO_STATUS_OK)
            {
                /** Two-key TDES is the EDE sequence K1, K2, K1. */
                context->keys[2] = context->keys[0];
                context->initialized = CRYPTO_TDES_CONTEXT_MAGIC;
            }
            else
            {
                crypto_tdes_secure_zero(context, sizeof(*context));
            }
        }
    }
    return status;
}

crypto_status crypto_tdes3_init(crypto_tdes_context *context,
                                const uint8_t *key, size_t key_length)
{
    crypto_status status = CRYPTO_STATUS_OK;
    size_t key_index;

    if ((context == NULL) || (key == NULL))
    {
        status = CRYPTO_STATUS_NULL_ARGUMENT;
    }
    else
    {
        crypto_tdes_secure_zero(context, sizeof(*context));
        if (key_length != CRYPTO_TDES3_KEY_SIZE)
        {
            status = CRYPTO_STATUS_INVALID_LENGTH;
        }
        else if ((crypto_tdes_effective_keys_equal(key, key + CRYPTO_DES_KEY_SIZE) != 0)
            || (crypto_tdes_effective_keys_equal(key, key + (2U * CRYPTO_DES_KEY_SIZE)) != 0)
            || (crypto_tdes_effective_keys_equal(key + CRYPTO_DES_KEY_SIZE,
                                                  key + (2U * CRYPTO_DES_KEY_SIZE)) != 0))
        {
            status = CRYPTO_STATUS_DEGENERATE_KEY;
        }
        else
        {
            for (key_index = 0U; key_index < 3U; ++key_index)
            {
                if (status == CRYPTO_STATUS_OK)
                {
                    status = crypto_des_init(&context->keys[key_index],
                                             key + (key_index * CRYPTO_DES_KEY_SIZE),
                                             CRYPTO_DES_KEY_SIZE);
                }
            }
            if (status == CRYPTO_STATUS_OK)
            {
                context->initialized = CRYPTO_TDES_CONTEXT_MAGIC;
            }
            else
            {
                crypto_tdes_secure_zero(context, sizeof(*context));
            }
        }
    }
    return status;
}

static crypto_status crypto_tdes_process_block(const crypto_tdes_context *context,
                                               const uint8_t input[CRYPTO_DES_BLOCK_SIZE],
                                               uint8_t output[CRYPTO_DES_BLOCK_SIZE], int decrypt)
{
    crypto_status status = CRYPTO_STATUS_OK;
    uint8_t first[CRYPTO_DES_BLOCK_SIZE];
    uint8_t second[CRYPTO_DES_BLOCK_SIZE];

    if ((context == NULL) || (input == NULL) || (output == NULL))
    {
        status = CRYPTO_STATUS_NULL_ARGUMENT;
    }
    else if (input == output)
    {
        status = CRYPTO_STATUS_OVERLAPPING_BUFFERS;
    }
    else if (context->initialized != CRYPTO_TDES_CONTEXT_MAGIC)
    {
        status = CRYPTO_STATUS_INVALID_CONTEXT;
    }
    else if (decrypt == 0)
    {
        /** TDES encryption applies E(K1), D(K2), E(K3). */
        status = crypto_des_encrypt_block(&context->keys[0], input, first);
        if (status == CRYPTO_STATUS_OK)
        {
            status = crypto_des_decrypt_block(&context->keys[1], first, second);
        }
        if (status == CRYPTO_STATUS_OK)
        {
            status = crypto_des_encrypt_block(&context->keys[2], second, output);
        }
    }
    else
    {
        /** Reverse both the operation and key order for decryption. */
        status = crypto_des_decrypt_block(&context->keys[2], input, first);
        if (status == CRYPTO_STATUS_OK)
        {
            status = crypto_des_encrypt_block(&context->keys[1], first, second);
        }
        if (status == CRYPTO_STATUS_OK)
        {
            status = crypto_des_decrypt_block(&context->keys[0], second, output);
        }
    }
    crypto_tdes_secure_zero(first, sizeof(first));
    crypto_tdes_secure_zero(second, sizeof(second));
    return status;
}

crypto_status crypto_tdes_encrypt_block(const crypto_tdes_context *context,
                                        const uint8_t input[CRYPTO_DES_BLOCK_SIZE],
                                        uint8_t output[CRYPTO_DES_BLOCK_SIZE])
{
    crypto_status status;

    status = crypto_tdes_process_block(context, input, output, 0);
    return status;
}

crypto_status crypto_tdes_decrypt_block(const crypto_tdes_context *context,
                                        const uint8_t input[CRYPTO_DES_BLOCK_SIZE],
                                        uint8_t output[CRYPTO_DES_BLOCK_SIZE])
{
    crypto_status status;

    status = crypto_tdes_process_block(context, input, output, 1);
    return status;
}

crypto_status crypto_tdes_clear(crypto_tdes_context *context)
{
    crypto_status status = CRYPTO_STATUS_OK;

    if (context == NULL)
    {
        status = CRYPTO_STATUS_NULL_ARGUMENT;
    }
    else
    {
        crypto_tdes_secure_zero(context, sizeof(*context));
    }
    return status;
}
