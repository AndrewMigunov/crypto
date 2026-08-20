#include <crypto/des.h>

#include <stddef.h>
#include <stdint.h>

#include "des_internal.h"

/** @brief DES tables use the one-based bit numbering from the specification. */
static const uint8_t initial_permutation[64] = {
    58, 50, 42, 34, 26, 18, 10, 2,  60, 52, 44, 36, 28, 20, 12, 4,  62, 54, 46, 38, 30, 22,
    14, 6,  64, 56, 48, 40, 32, 24, 16, 8,  57, 49, 41, 33, 25, 17, 9,  1,  59, 51, 43, 35,
    27, 19, 11, 3,  61, 53, 45, 37, 29, 21, 13, 5,  63, 55, 47, 39, 31, 23, 15, 7};
static const uint8_t final_permutation[64] = {
    40, 8,  48, 16, 56, 24, 64, 32, 39, 7,  47, 15, 55, 23, 63, 31, 38, 6,  46, 14, 54, 22,
    62, 30, 37, 5,  45, 13, 53, 21, 61, 29, 36, 4,  44, 12, 52, 20, 60, 28, 35, 3,  43, 11,
    51, 19, 59, 27, 34, 2,  42, 10, 50, 18, 58, 26, 33, 1,  41, 9,  49, 17, 57, 25};
static const uint8_t expansion_permutation[48] = {
    32, 1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,  8,  9,  10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1};
static const uint8_t round_permutation[32] = {16, 7, 20, 21, 29, 12, 28, 17, 1,  15, 23,
                                              26, 5, 18, 31, 10, 2,  8,  24, 14, 32, 27,
                                              3,  9, 19, 13, 30, 6,  22, 11, 4,  25};
static const uint8_t permuted_choice_one[56] = {
    57, 49, 41, 33, 25, 17, 9,  1,  58, 50, 42, 34, 26, 18, 10, 2,  59, 51, 43,
    35, 27, 19, 11, 3,  60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7,  62, 54,
    46, 38, 30, 22, 14, 6,  61, 53, 45, 37, 29, 21, 13, 5,  28, 20, 12, 4};
static const uint8_t permuted_choice_two[48] = {
    14, 17, 11, 24, 1,  5,  3,  28, 15, 6,  21, 10, 23, 19, 12, 4,  26, 8,  16, 7,  27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32};
static const uint8_t key_rotations[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
static const uint8_t s_boxes[8][64] = {
    {14, 4,  13, 1, 2,  15, 11, 8, 3, 10, 6, 12, 5,  9,  0,  7,  0,  15, 7,  4,  14, 2,
     13, 1,  10, 6, 12, 11, 9,  5, 3, 8,  4, 1,  14, 8,  13, 6,  2,  11, 15, 12, 9,  7,
     3,  10, 5,  0, 15, 12, 8,  2, 4, 9,  1, 7,  5,  11, 3,  14, 10, 0,  6,  13},
    {15, 1,  8,  14, 6,  11, 3,  4, 9,  7,  2, 13, 12, 0,  5,  10, 3,  13, 4,  7, 15, 2,
     8,  14, 12, 0,  1,  10, 6,  9, 11, 5,  0, 14, 7,  11, 10, 4,  13, 1,  5,  8, 12, 6,
     9,  3,  2,  15, 13, 8,  10, 1, 3,  15, 4, 2,  11, 6,  7,  12, 0,  5,  14, 9},
    {10, 0,  9,  14, 6, 3,  15, 5,  1,  13, 12, 7, 11, 4,  2,  8,  13, 7, 0,  9, 3, 4,
     6,  10, 2,  8,  5, 14, 12, 11, 15, 1,  13, 6, 4,  9,  8,  15, 3,  0, 11, 1, 2, 12,
     5,  10, 14, 7,  1, 10, 13, 0,  6,  9,  8,  7, 4,  15, 14, 3,  11, 5, 2,  12},
    {7, 13, 14, 3, 0, 6,  9, 10, 1,  2, 8,  5, 11, 12, 4,  15, 13, 8,  11, 5, 6, 15,
     0, 3,  4,  7, 2, 12, 1, 10, 14, 9, 10, 6, 9,  0,  12, 11, 7,  13, 15, 1, 3, 14,
     5, 2,  8,  4, 3, 15, 0, 6,  10, 1, 13, 8, 9,  4,  5,  11, 12, 7,  2,  14},
    {2,  12, 4, 1,  7,  10, 11, 6, 8, 5,  3, 15, 13, 0,  14, 9,  14, 11, 2,  12, 4,  7,
     13, 1,  5, 0,  15, 10, 3,  9, 8, 6,  4, 2,  1,  11, 10, 13, 7,  8,  15, 9,  12, 5,
     6,  3,  0, 14, 11, 8,  12, 7, 1, 14, 2, 13, 6,  15, 0,  9,  10, 4,  5,  3},
    {12, 1,  10, 15, 9,  2,  6, 8,  0, 13, 3,  4,  14, 7,  5, 11, 10, 15, 4, 2, 7, 12,
     9,  5,  6,  1,  13, 14, 0, 11, 3, 8,  9,  14, 15, 5,  2, 8,  12, 3,  7, 0, 4, 10,
     1,  13, 11, 6,  4,  3,  2, 12, 9, 5,  15, 10, 11, 14, 1, 7,  6,  0,  8, 13},
    {4, 11, 2,  14, 15, 0,  8,  13, 3, 12, 9,  7, 5,  10, 6,  1,  13, 0,  11, 7,  4, 9,
     1, 10, 14, 3,  5,  12, 2,  15, 8, 6,  1,  4, 11, 13, 12, 3,  7,  14, 10, 15, 6, 8,
     0, 5,  9,  2,  6,  11, 13, 8,  1, 4,  10, 7, 9,  5,  0,  15, 14, 2,  3,  12},
    {13, 2, 8,  4, 6, 15, 11, 1,  10, 9,  3, 14, 5,  0,  12, 7,  1,  15, 13, 8, 10, 3,
     7,  4, 12, 5, 6, 11, 0,  14, 9,  2,  7, 11, 4,  1,  9,  12, 14, 2,  0,  6, 10, 13,
     15, 3, 5,  8, 2, 1,  14, 7,  4,  10, 8, 13, 15, 12, 9,  0,  3,  5,  6,  11}};

/** @brief Apply a permutation while preserving its published bit order. */
static uint64_t crypto_des_permute(uint64_t input, const uint8_t *table, size_t output_bits,
                                   size_t input_bits)
{
    uint64_t output = UINT64_C(0);
    size_t index;

    for (index = 0U; index < output_bits; ++index)
    {
        output <<= 1U;
        output |= (input >> (input_bits - (size_t)table[index])) & UINT64_C(1);
    }

    return output;
}

static uint64_t crypto_des_load_block(const uint8_t block[CRYPTO_DES_BLOCK_SIZE])
{
    uint64_t value = UINT64_C(0);
    size_t index;

    /** External blocks are always interpreted as big-endian byte strings. */
    for (index = 0U; index < CRYPTO_DES_BLOCK_SIZE; ++index)
    {
        value = (value << 8U) | (uint64_t)block[index];
    }

    return value;
}

static void crypto_des_store_block(uint64_t value, uint8_t block[CRYPTO_DES_BLOCK_SIZE])
{
    size_t index;

    for (index = CRYPTO_DES_BLOCK_SIZE; index > 0U; --index)
    {
        block[index - 1U] = (uint8_t)(value & UINT64_C(0xff));
        value >>= 8U;
    }
    return;
}

static uint32_t crypto_des_rotate_28(uint32_t value, uint8_t count)
{
    uint32_t result;

    result = ((value << count) | (value >> (28U - count))) & UINT32_C(0x0fffffff);
    return result;
}

static void crypto_des_make_round_keys(const uint8_t key[CRYPTO_DES_KEY_SIZE],
                                       uint64_t round_keys[CRYPTO_DES_ROUND_COUNT])
{
    uint64_t selected;
    uint64_t combined;
    uint32_t left;
    uint32_t right;
    size_t round;

    /** PC-1 removes parity bits and splits the effective key into C and D halves. */
    selected = crypto_des_permute(crypto_des_load_block(key), permuted_choice_one, 56U, 64U);
    left = (uint32_t)((selected >> 28U) & UINT64_C(0x0fffffff));
    right = (uint32_t)(selected & UINT64_C(0x0fffffff));
    for (round = 0U; round < CRYPTO_DES_ROUND_COUNT; ++round)
    {
        left = crypto_des_rotate_28(left, key_rotations[round]);
        right = crypto_des_rotate_28(right, key_rotations[round]);
        combined = ((uint64_t)left << 28U) | (uint64_t)right;
        /** PC-2 selects the 48 bits consumed by this Feistel round. */
        round_keys[round] = crypto_des_permute(combined, permuted_choice_two, 48U, 56U);
    }
    return;
}

static uint32_t crypto_des_round_function(uint32_t right, uint64_t round_key)
{
    uint64_t mixed;
    uint32_t substituted = UINT32_C(0);
    uint32_t result;
    uint8_t six_bits;
    uint8_t row;
    uint8_t column;
    size_t box;

    /** Expand R, mix in the round key, then apply all eight S-boxes. */
    mixed = crypto_des_permute((uint64_t)right, expansion_permutation, 48U, 32U) ^ round_key;
    for (box = 0U; box < 8U; ++box)
    {
        six_bits = (uint8_t)((mixed >> (42U - (box * 6U))) & UINT64_C(0x3f));
        row = (uint8_t)(((six_bits & UINT8_C(0x20)) >> 4U) | (six_bits & UINT8_C(0x01)));
        column = (uint8_t)((six_bits >> 1U) & UINT8_C(0x0f));
        substituted = (substituted << 4U) | (uint32_t)s_boxes[box][(row * 16U) + column];
    }
    result = (uint32_t)crypto_des_permute((uint64_t)substituted, round_permutation, 32U, 32U);
    return result;
}

static void crypto_des_transform(const crypto_des_schedule *schedule,
                                 const uint8_t input[CRYPTO_DES_BLOCK_SIZE],
                                 uint8_t output[CRYPTO_DES_BLOCK_SIZE], int decrypt)
{
    uint64_t block;
    uint64_t pre_output;
    uint32_t left;
    uint32_t right;
    uint32_t next;
    size_t round;
    size_t key_index;

    /** Encryption and decryption differ only in round-key traversal order. */
    block = crypto_des_permute(crypto_des_load_block(input), initial_permutation, 64U, 64U);
    left = (uint32_t)(block >> 32U);
    right = (uint32_t)(block & UINT64_C(0xffffffff));
    for (round = 0U; round < CRYPTO_DES_ROUND_COUNT; ++round)
    {
        key_index = (decrypt != 0) ? (CRYPTO_DES_ROUND_COUNT - 1U - round) : round;
        next = left ^ crypto_des_round_function(right, schedule->round_keys[key_index]);
        left = right;
        right = next;
    }
    pre_output = ((uint64_t)right << 32U) | (uint64_t)left;
    block = crypto_des_permute(pre_output, final_permutation, 64U, 64U);
    crypto_des_store_block(block, output);
    return;
}

static void crypto_des_secure_zero(void *memory, size_t size)
{
    /** Volatile stores prevent dead-store elimination of sensitive data erasure. */
    volatile uint8_t *bytes = (volatile uint8_t *)memory;
    size_t index;

    for (index = 0U; index < size; ++index)
    {
        bytes[index] = UINT8_C(0);
    }
    return;
}

static int crypto_des_round_keys_are_weak(const uint64_t round_keys[CRYPTO_DES_ROUND_COUNT])
{
    size_t distinct = 0U;
    size_t current;
    size_t previous;
    int already_seen;
    int result;

    /** Weak key classes generate no more than four distinct round keys. */
    for (current = 0U; current < CRYPTO_DES_ROUND_COUNT; ++current)
    {
        already_seen = 0;
        for (previous = 0U; previous < current; ++previous)
        {
            if (round_keys[current] == round_keys[previous])
            {
                already_seen = 1;
            }
        }
        if (already_seen == 0)
        {
            ++distinct;
        }
    }
    result = (distinct <= 4U) ? 1 : 0;
    return result;
}

static crypto_status crypto_des_key_check_parity(const uint8_t *key, size_t key_length)
{
    crypto_status status = CRYPTO_STATUS_OK;
    uint8_t parity;
    uint8_t value;
    size_t byte_index;

    if (key_length != CRYPTO_DES_KEY_SIZE)
    {
        status = CRYPTO_STATUS_INVALID_LENGTH;
    }
    else
    {
        /** Accumulate every byte result instead of returning on the first failure. */
        parity = UINT8_C(1);
        for (byte_index = 0U; byte_index < CRYPTO_DES_KEY_SIZE; ++byte_index)
        {
            value = key[byte_index];
            value ^= (uint8_t)(value >> 4U);
            value ^= (uint8_t)(value >> 2U);
            value ^= (uint8_t)(value >> 1U);
            parity = (uint8_t)(parity & (uint8_t)(value & UINT8_C(1)));
        }
        if (parity == UINT8_C(0))
        {
            status = CRYPTO_STATUS_INVALID_KEY_PARITY;
        }
    }
    return status;
}

static crypto_status crypto_des_key_validate(const uint8_t *key, size_t key_length)
{
    crypto_status status;
    uint64_t round_keys[CRYPTO_DES_ROUND_COUNT];

    status = crypto_des_key_check_parity(key, key_length);
    if (status == CRYPTO_STATUS_OK)
    {
        crypto_des_make_round_keys(key, round_keys);
        if (crypto_des_round_keys_are_weak(round_keys) != 0)
        {
            status = CRYPTO_STATUS_WEAK_KEY;
        }
        crypto_des_secure_zero(round_keys, sizeof(round_keys));
    }
    return status;
}

crypto_status crypto_des_schedule_init(crypto_des_schedule *schedule, const uint8_t *key,
                                       size_t key_length)
{
    crypto_status status = CRYPTO_STATUS_OK;

    crypto_des_secure_zero(schedule, sizeof(*schedule));
    status = crypto_des_key_validate(key, key_length);
    if (status == CRYPTO_STATUS_OK)
    {
        crypto_des_make_round_keys(key, schedule->round_keys);
    }
    return status;
}

void crypto_des_schedule_encrypt(const crypto_des_schedule *schedule,
                                 const uint8_t input[CRYPTO_DES_BLOCK_SIZE],
                                 uint8_t output[CRYPTO_DES_BLOCK_SIZE])
{
    crypto_des_transform(schedule, input, output, 0);
    return;
}

void crypto_des_schedule_decrypt(const crypto_des_schedule *schedule,
                                 const uint8_t input[CRYPTO_DES_BLOCK_SIZE],
                                 uint8_t output[CRYPTO_DES_BLOCK_SIZE])
{
    crypto_des_transform(schedule, input, output, 1);
    return;
}

void crypto_des_schedule_clear(crypto_des_schedule *schedule)
{
    crypto_des_secure_zero(schedule, sizeof(*schedule));
    return;
}

static int crypto_des_buffers_overlap(const uint8_t *input, size_t input_length,
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

static crypto_status crypto_des_crypt(const uint8_t *key, size_t key_length,
                                      crypto_cipher_mode mode, const uint8_t *iv, size_t iv_length,
                                      const uint8_t *input, size_t input_length, uint8_t *output,
                                      size_t output_length, int decrypt)
{
    crypto_status status = CRYPTO_STATUS_OK;
    crypto_des_schedule schedule;
    size_t block_offset;

    crypto_des_secure_zero(&schedule, sizeof(schedule));
    if ((key == NULL) || (input == NULL) || (output == NULL))
    {
        status = CRYPTO_STATUS_NULL_ARGUMENT;
    }
    else if (mode != CRYPTO_CIPHER_MODE_ECB)
    {
        status = CRYPTO_STATUS_INVALID_MODE;
    }
    else if ((iv_length != 0U) || ((input_length % CRYPTO_DES_BLOCK_SIZE) != 0U) ||
             (output_length != input_length))
    {
        status = CRYPTO_STATUS_INVALID_LENGTH;
    }
    else if (crypto_des_buffers_overlap(input, input_length, output, output_length) != 0)
    {
        status = CRYPTO_STATUS_OVERLAPPING_BUFFERS;
    }
    else
    {
        status = crypto_des_schedule_init(&schedule, key, key_length);
        if (status == CRYPTO_STATUS_OK)
        {
            for (block_offset = 0U; block_offset < input_length;
                 block_offset += CRYPTO_DES_BLOCK_SIZE)
            {
                if (decrypt == 0)
                {
                    crypto_des_schedule_encrypt(&schedule, input + block_offset,
                                                output + block_offset);
                }
                else
                {
                    crypto_des_schedule_decrypt(&schedule, input + block_offset,
                                                output + block_offset);
                }
            }
        }
    }
    (void)iv;
    crypto_des_schedule_clear(&schedule);
    return status;
}

crypto_status crypto_des_encrypt(const uint8_t *key, size_t key_length, crypto_cipher_mode mode,
                                 const uint8_t *iv, size_t iv_length, const uint8_t *input,
                                 size_t input_length, uint8_t *output, size_t output_length)
{
    return crypto_des_crypt(key, key_length, mode, iv, iv_length, input, input_length, output,
                            output_length, 0);
}

crypto_status crypto_des_decrypt(const uint8_t *key, size_t key_length, crypto_cipher_mode mode,
                                 const uint8_t *iv, size_t iv_length, const uint8_t *input,
                                 size_t input_length, uint8_t *output, size_t output_length)
{
    return crypto_des_crypt(key, key_length, mode, iv, iv_length, input, input_length, output,
                            output_length, 1);
}
