#include <crypto/des.h>
#include <crypto/status.h>
#include <crypto/tdes.h>

#include <stdio.h>
#include <string.h>

static int expect_status(const char *name, crypto_status actual, crypto_status expected)
{
    int failed = 0;

    if (actual != expected)
    {
        (void)fprintf(stderr, "%s: expected %s, got %s\n", name,
                      crypto_status_string(expected), crypto_status_string(actual));
        failed = 1;
    }
    return failed;
}

static int expect_block(const char *name, const uint8_t actual[CRYPTO_DES_BLOCK_SIZE],
                        const uint8_t expected[CRYPTO_DES_BLOCK_SIZE])
{
    int failed = 0;

    if (memcmp(actual, expected, CRYPTO_DES_BLOCK_SIZE) != 0)
    {
        (void)fprintf(stderr, "%s: block mismatch\n", name);
        failed = 1;
    }
    return failed;
}

static int test_des_known_vector(void)
{
    /** Canonical FIPS DES known-answer test. */
    static const uint8_t key[CRYPTO_DES_KEY_SIZE] =
        {0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1};
    static const uint8_t plaintext[CRYPTO_DES_BLOCK_SIZE] =
        {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    static const uint8_t expected[CRYPTO_DES_BLOCK_SIZE] =
        {0x85, 0xe8, 0x13, 0x54, 0x0f, 0x0a, 0xb4, 0x05};
    crypto_des_context context;
    uint8_t encrypted[CRYPTO_DES_BLOCK_SIZE];
    uint8_t decrypted[CRYPTO_DES_BLOCK_SIZE];
    crypto_status status;
    int failed = 0;

    status = crypto_des_init(&context, key, sizeof(key));
    failed |= expect_status("DES init", status, CRYPTO_STATUS_OK);
    if (status == CRYPTO_STATUS_OK)
    {
        status = crypto_des_encrypt_block(&context, plaintext, encrypted);
        failed |= expect_status("DES encrypt", status, CRYPTO_STATUS_OK);
        failed |= expect_block("DES ciphertext", encrypted, expected);
        status = crypto_des_decrypt_block(&context, encrypted, decrypted);
        failed |= expect_status("DES decrypt", status, CRYPTO_STATUS_OK);
        failed |= expect_block("DES plaintext", decrypted, plaintext);
    }
    failed |= expect_status("DES clear", crypto_des_clear(&context), CRYPTO_STATUS_OK);
    failed |= expect_status("DES use after clear",
                            crypto_des_encrypt_block(&context, plaintext, encrypted),
                            CRYPTO_STATUS_INVALID_CONTEXT);
    return failed;
}

static int test_des_key_validation(void)
{
    uint8_t bad_parity[CRYPTO_DES_KEY_SIZE] =
        {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0};
    static const uint8_t weak_key[CRYPTO_DES_KEY_SIZE] =
        {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    crypto_des_context context;
    int failed = 0;

    failed |= expect_status("bad parity", crypto_des_key_validate(bad_parity, sizeof(bad_parity)),
                            CRYPTO_STATUS_INVALID_KEY_PARITY);
    failed |= expect_status("set parity",
                            crypto_des_key_set_odd_parity(bad_parity, sizeof(bad_parity)),
                            CRYPTO_STATUS_OK);
    failed |= expect_status("corrected parity",
                            crypto_des_key_check_parity(bad_parity, sizeof(bad_parity)),
                            CRYPTO_STATUS_OK);
    failed |= expect_status("weak key", crypto_des_key_validate(weak_key, sizeof(weak_key)),
                            CRYPTO_STATUS_WEAK_KEY);
    failed |= expect_status("null key", crypto_des_key_validate(NULL, 0U),
                            CRYPTO_STATUS_NULL_ARGUMENT);
    failed |= expect_status("null parity output", crypto_des_key_set_odd_parity(NULL, 0U),
                            CRYPTO_STATUS_NULL_ARGUMENT);
    failed |= expect_status("null context", crypto_des_init(NULL, weak_key, sizeof(weak_key)),
                            CRYPTO_STATUS_NULL_ARGUMENT);
    failed |= expect_status("short DES key",
                            crypto_des_key_validate(weak_key, sizeof(weak_key) - 1U),
                            CRYPTO_STATUS_INVALID_LENGTH);
    failed |= expect_status("short DES parity output",
                            crypto_des_key_set_odd_parity(bad_parity,
                                                          sizeof(bad_parity) - 1U),
                            CRYPTO_STATUS_INVALID_LENGTH);
    failed |= expect_status("clear null", crypto_des_clear(NULL),
                            CRYPTO_STATUS_NULL_ARGUMENT);
    (void)memset(&context, 0, sizeof(context));
    failed |= expect_status("invalid context",
                            crypto_des_encrypt_block(&context, weak_key, bad_parity),
                            CRYPTO_STATUS_INVALID_CONTEXT);
    return failed;
}

static int test_des_buffer_contract(void)
{
    static const uint8_t key[CRYPTO_DES_KEY_SIZE] =
        {0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1};
    crypto_des_context context;
    uint8_t block[CRYPTO_DES_BLOCK_SIZE] = {0};
    int failed = 0;

    failed |= expect_status("buffer init", crypto_des_init(&context, key, sizeof(key)),
                            CRYPTO_STATUS_OK);
    failed |= expect_status("same buffer", crypto_des_encrypt_block(&context, block, block),
                            CRYPTO_STATUS_OVERLAPPING_BUFFERS);
    failed |= expect_status("null input", crypto_des_encrypt_block(&context, NULL, block),
                            CRYPTO_STATUS_NULL_ARGUMENT);
    failed |= expect_status("null output", crypto_des_encrypt_block(&context, block, NULL),
                            CRYPTO_STATUS_NULL_ARGUMENT);
    failed |= expect_status("buffer clear", crypto_des_clear(&context), CRYPTO_STATUS_OK);
    return failed;
}

static int test_tdes_three_key_vector(void)
{
    /** Published three-key TDES EDE known-answer test. */
    static const uint8_t key[CRYPTO_TDES3_KEY_SIZE] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x01,
        0x45,0x67,0x89,0xab,0xcd,0xef,0x01,0x23
    };
    static const uint8_t plaintext[CRYPTO_DES_BLOCK_SIZE] =
        {0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    static const uint8_t expected[CRYPTO_DES_BLOCK_SIZE] =
        {0x07,0x37,0xf6,0xc5,0x37,0x50,0xd4,0xa4};
    crypto_tdes_context context;
    uint8_t encrypted[CRYPTO_DES_BLOCK_SIZE];
    uint8_t decrypted[CRYPTO_DES_BLOCK_SIZE];
    crypto_status status;
    int failed = 0;

    status = crypto_tdes3_init(&context, key, sizeof(key));
    failed |= expect_status("3TDES init", status, CRYPTO_STATUS_OK);
    if (status == CRYPTO_STATUS_OK)
    {
        status = crypto_tdes_encrypt_block(&context, plaintext, encrypted);
        failed |= expect_status("3TDES encrypt", status, CRYPTO_STATUS_OK);
        failed |= expect_block("3TDES ciphertext", encrypted, expected);
        status = crypto_tdes_decrypt_block(&context, encrypted, decrypted);
        failed |= expect_status("3TDES decrypt", status, CRYPTO_STATUS_OK);
        failed |= expect_block("3TDES plaintext", decrypted, plaintext);
    }
    failed |= expect_status("3TDES clear", crypto_tdes_clear(&context), CRYPTO_STATUS_OK);
    return failed;
}

static int test_tdes_two_key_round_trip(void)
{
    /** Published two-key TDES EDE known-answer test. */
    static const uint8_t key[CRYPTO_TDES2_KEY_SIZE] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x01
    };
    static const uint8_t plaintext[CRYPTO_DES_BLOCK_SIZE] =
        {0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    static const uint8_t expected[CRYPTO_DES_BLOCK_SIZE] =
        {0xb0,0x8c,0xca,0xef,0xcf,0x22,0x58,0x60};
    crypto_tdes_context context;
    uint8_t encrypted[CRYPTO_DES_BLOCK_SIZE];
    uint8_t decrypted[CRYPTO_DES_BLOCK_SIZE];
    crypto_status status;
    int failed = 0;

    status = crypto_tdes2_init(&context, key, sizeof(key));
    failed |= expect_status("2TDES init", status, CRYPTO_STATUS_OK);
    if (status == CRYPTO_STATUS_OK)
    {
        status = crypto_tdes_encrypt_block(&context, plaintext, encrypted);
        failed |= expect_status("2TDES encrypt", status, CRYPTO_STATUS_OK);
        failed |= expect_block("2TDES ciphertext", encrypted, expected);
        status = crypto_tdes_decrypt_block(&context, encrypted, decrypted);
        failed |= expect_status("2TDES decrypt", status, CRYPTO_STATUS_OK);
        failed |= expect_block("2TDES plaintext", decrypted, plaintext);
    }
    failed |= expect_status("2TDES clear", crypto_tdes_clear(&context), CRYPTO_STATUS_OK);
    failed |= expect_status("2TDES use after clear",
                            crypto_tdes_encrypt_block(&context, plaintext, encrypted),
                            CRYPTO_STATUS_INVALID_CONTEXT);
    return failed;
}

static int test_tdes_validation(void)
{
    static const uint8_t repeated_key[CRYPTO_TDES2_KEY_SIZE] = {
        0x13,0x34,0x57,0x79,0x9b,0xbc,0xdf,0xf1,
        0x13,0x34,0x57,0x79,0x9b,0xbc,0xdf,0xf1
    };
    static const uint8_t repeated_key3[CRYPTO_TDES3_KEY_SIZE] = {
        0x13,0x34,0x57,0x79,0x9b,0xbc,0xdf,0xf1,
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0x13,0x34,0x57,0x79,0x9b,0xbc,0xdf,0xf1
    };
    static const uint8_t bad_parity_key[CRYPTO_TDES2_KEY_SIZE] = {
        0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef
    };
    static const uint8_t weak_component[CRYPTO_TDES2_KEY_SIZE] = {
        0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef
    };
    static const uint8_t weak_component3[CRYPTO_TDES3_KEY_SIZE] = {
        0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0x45,0x67,0x89,0xab,0xcd,0xef,0x01,0x23
    };
    crypto_tdes_context context;
    uint8_t block[CRYPTO_DES_BLOCK_SIZE] = {0};
    uint8_t output[CRYPTO_DES_BLOCK_SIZE] = {0};
    int failed = 0;

    failed |= expect_status("degenerate 2TDES",
                            crypto_tdes2_init(&context, repeated_key, sizeof(repeated_key)),
                            CRYPTO_STATUS_DEGENERATE_KEY);
    failed |= expect_status("degenerate 3TDES",
                            crypto_tdes3_init(&context, repeated_key3, sizeof(repeated_key3)),
                            CRYPTO_STATUS_DEGENERATE_KEY);
    failed |= expect_status("bad TDES parity",
                            crypto_tdes2_init(&context, bad_parity_key, sizeof(bad_parity_key)),
                            CRYPTO_STATUS_INVALID_KEY_PARITY);
    failed |= expect_status("weak TDES component",
                            crypto_tdes2_init(&context, weak_component, sizeof(weak_component)),
                            CRYPTO_STATUS_WEAK_KEY);
    failed |= expect_status("weak 3TDES component",
                            crypto_tdes3_init(&context, weak_component3, sizeof(weak_component3)),
                            CRYPTO_STATUS_WEAK_KEY);
    failed |= expect_status("null TDES",
                            crypto_tdes2_init(NULL, repeated_key, sizeof(repeated_key)),
                            CRYPTO_STATUS_NULL_ARGUMENT);
    failed |= expect_status("null 3TDES key", crypto_tdes3_init(&context, NULL, 0U),
                            CRYPTO_STATUS_NULL_ARGUMENT);
    failed |= expect_status("short 2TDES key",
                            crypto_tdes2_init(&context, repeated_key, sizeof(repeated_key) - 1U),
                            CRYPTO_STATUS_INVALID_LENGTH);
    failed |= expect_status("short 3TDES key",
                            crypto_tdes3_init(&context, repeated_key3, sizeof(repeated_key3) - 1U),
                            CRYPTO_STATUS_INVALID_LENGTH);
    (void)memset(&context, 0, sizeof(context));
    failed |= expect_status("invalid TDES context",
                            crypto_tdes_encrypt_block(&context, block, output),
                            CRYPTO_STATUS_INVALID_CONTEXT);
    failed |= expect_status("same TDES buffer",
                            crypto_tdes_encrypt_block(&context, block, block),
                            CRYPTO_STATUS_OVERLAPPING_BUFFERS);
    failed |= expect_status("null TDES input",
                            crypto_tdes_encrypt_block(&context, NULL, output),
                            CRYPTO_STATUS_NULL_ARGUMENT);
    failed |= expect_status("clear null TDES", crypto_tdes_clear(NULL),
                            CRYPTO_STATUS_NULL_ARGUMENT);
    return failed;
}

static int test_status_strings(void)
{
    int failed = 0;
    int value;

    for (value = (int)CRYPTO_STATUS_OK;
         value <= (int)CRYPTO_STATUS_INVALID_LENGTH; ++value)
    {
        if (strcmp(crypto_status_string((crypto_status)value), "unknown status") == 0)
        {
            failed = 1;
        }
    }
    if (strcmp(crypto_status_string((crypto_status)999), "unknown status") != 0)
    {
        failed = 1;
    }
    return failed;
}

int main(void)
{
    int failed = 0;

    failed |= test_des_known_vector();
    failed |= test_des_key_validation();
    failed |= test_des_buffer_contract();
    failed |= test_tdes_three_key_vector();
    failed |= test_tdes_two_key_round_trip();
    failed |= test_tdes_validation();
    failed |= test_status_strings();
    if (failed == 0)
    {
        (void)puts("All crypto tests passed.");
    }
    return failed;
}
