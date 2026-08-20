#include <acutest.h>

#include <crypto/des.h>
#include <crypto/status.h>
#include <crypto/tdes.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/** @brief Signature shared by all public one-shot cipher operations. */
typedef crypto_status (*cipher_operation)(const uint8_t *key, size_t key_length,
                                          crypto_cipher_mode mode, const uint8_t *iv,
                                          size_t iv_length, const uint8_t *input,
                                          size_t input_length, uint8_t *output,
                                          size_t output_length);

/** @brief Known-answer vector for a one-shot block cipher. */
typedef struct cipher_vector
{
    const char *name;          /**< Name shown by the test runner. */
    cipher_operation encrypt;  /**< Encryption operation. */
    cipher_operation decrypt;  /**< Decryption operation. */
    const uint8_t *key;        /**< Encoded key. */
    size_t key_length;         /**< Encoded key length. */
    const uint8_t *plaintext;  /**< Expected plaintext block. */
    const uint8_t *ciphertext; /**< Expected ciphertext block. */
} cipher_vector;

/** @brief Expected result for a key-validation call. */
typedef struct key_validation_case
{
    const char *name;           /**< Name shown by the test runner. */
    cipher_operation operation; /**< Operation used to validate the key. */
    const uint8_t *key;         /**< Encoded key under test. */
    size_t key_length;          /**< Encoded key length. */
    crypto_status expected;     /**< Expected validation status. */
} key_validation_case;

/** @brief Fully specified public operation used for table-driven contract tests. */
typedef struct contract_case
{
    const char *name;           /**< Name shown by the test runner. */
    cipher_operation operation; /**< Public operation under test. */
    const uint8_t *key;         /**< Key argument. */
    size_t key_length;          /**< Key-length argument. */
    crypto_cipher_mode mode;    /**< Mode argument. */
    const uint8_t *iv;          /**< Initialization-vector argument. */
    size_t iv_length;           /**< Initialization-vector length. */
    const uint8_t *input;       /**< Input argument. */
    size_t input_length;        /**< Input-length argument. */
    uint8_t *output;            /**< Output argument. */
    size_t output_length;       /**< Output-length argument. */
    crypto_status expected;     /**< Expected operation status. */
} contract_case;

/** @brief Canonical DES key with valid odd parity. */
static const uint8_t des_key[CRYPTO_DES_KEY_SIZE] = {0x13, 0x34, 0x57, 0x79,
                                                     0x9b, 0xbc, 0xdf, 0xf1};

/** @brief Canonical DES plaintext block. */
static const uint8_t des_plaintext[CRYPTO_DES_BLOCK_SIZE] = {0x01, 0x23, 0x45, 0x67,
                                                             0x89, 0xab, 0xcd, 0xef};

/** @brief Canonical DES ciphertext block. */
static const uint8_t des_ciphertext[CRYPTO_DES_BLOCK_SIZE] = {0x85, 0xe8, 0x13, 0x54,
                                                              0x0f, 0x0a, 0xb4, 0x05};

/** @brief Published two-key TDES key. */
static const uint8_t tdes2_key[CRYPTO_TDES2_KEY_SIZE] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01};

/** @brief Published three-key TDES key. */
static const uint8_t tdes3_key[CRYPTO_TDES3_KEY_SIZE] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x23, 0x45, 0x67, 0x89,
    0xab, 0xcd, 0xef, 0x01, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23};

/** @brief Published TDES plaintext block. */
static const uint8_t tdes_plaintext[CRYPTO_DES_BLOCK_SIZE] = {0xfe, 0xdc, 0xba, 0x98,
                                                              0x76, 0x54, 0x32, 0x10};

/** @brief Published two-key TDES ciphertext block. */
static const uint8_t tdes2_ciphertext[CRYPTO_DES_BLOCK_SIZE] = {0xb0, 0x8c, 0xca, 0xef,
                                                                0xcf, 0x22, 0x58, 0x60};

/** @brief Published three-key TDES ciphertext block. */
static const uint8_t tdes3_ciphertext[CRYPTO_DES_BLOCK_SIZE] = {0x07, 0x37, 0xf6, 0xc5,
                                                                0x37, 0x50, 0xd4, 0xa4};

/** @brief Block used when only validation behavior matters. */
static const uint8_t zero_block[CRYPTO_DES_BLOCK_SIZE] = {0};

/** @brief Report a status comparison with readable status strings. */
static void check_status(crypto_status actual, crypto_status expected)
{
    TEST_CHECK_(actual == expected, "expected %s, got %s", crypto_status_string(expected),
                crypto_status_string(actual));
    return;
}

/** @brief Compare cipher blocks and dump both values on failure. */
static void check_block(const uint8_t actual[CRYPTO_DES_BLOCK_SIZE],
                        const uint8_t expected[CRYPTO_DES_BLOCK_SIZE])
{
    TEST_CHECK(memcmp(actual, expected, CRYPTO_DES_BLOCK_SIZE) == 0);
    TEST_DUMP("Expected:", expected, CRYPTO_DES_BLOCK_SIZE);
    TEST_DUMP("Actual:", actual, CRYPTO_DES_BLOCK_SIZE);
    return;
}

/** @brief Exercise DES, two-key TDES, and three-key TDES known-answer vectors. */
static void test_known_answer_vectors(void)
{
    static const cipher_vector vectors[] = {
        {"DES", crypto_des_encrypt, crypto_des_decrypt, des_key, sizeof(des_key), des_plaintext,
         des_ciphertext},
        {"2TDES", crypto_tdes_encrypt, crypto_tdes_decrypt, tdes2_key, sizeof(tdes2_key),
         tdes_plaintext, tdes2_ciphertext},
        {"3TDES", crypto_tdes_encrypt, crypto_tdes_decrypt, tdes3_key, sizeof(tdes3_key),
         tdes_plaintext, tdes3_ciphertext}};
    uint8_t encrypted[CRYPTO_DES_BLOCK_SIZE] = {0};
    uint8_t decrypted[CRYPTO_DES_BLOCK_SIZE] = {0};
    crypto_status status;
    const cipher_vector *vector;
    size_t index;

    for (index = 0U; index < (sizeof(vectors) / sizeof(vectors[0])); ++index)
    {
        vector = &vectors[index];
        TEST_CASE(vector->name);
        status =
            vector->encrypt(vector->key, vector->key_length, CRYPTO_CIPHER_MODE_ECB, NULL, 0U,
                            vector->plaintext, CRYPTO_DES_BLOCK_SIZE, encrypted, sizeof(encrypted));
        check_status(status, CRYPTO_STATUS_OK);
        check_block(encrypted, vector->ciphertext);
        status = vector->decrypt(vector->key, vector->key_length, CRYPTO_CIPHER_MODE_ECB, NULL, 0U,
                                 encrypted, sizeof(encrypted), decrypted, sizeof(decrypted));
        check_status(status, CRYPTO_STATUS_OK);
        check_block(decrypted, vector->plaintext);
    }
    return;
}

/** @brief Exercise multi-block ECB encryption and decryption. */
static void test_multiple_blocks(void)
{
    static const cipher_vector vectors[] = {
        {"DES", crypto_des_encrypt, crypto_des_decrypt, des_key, sizeof(des_key), des_plaintext,
         des_ciphertext},
        {"2TDES", crypto_tdes_encrypt, crypto_tdes_decrypt, tdes2_key, sizeof(tdes2_key),
         tdes_plaintext, tdes2_ciphertext},
        {"3TDES", crypto_tdes_encrypt, crypto_tdes_decrypt, tdes3_key, sizeof(tdes3_key),
         tdes_plaintext, tdes3_ciphertext}};
    uint8_t plaintext[2U * CRYPTO_DES_BLOCK_SIZE];
    uint8_t expected[2U * CRYPTO_DES_BLOCK_SIZE];
    uint8_t encrypted[2U * CRYPTO_DES_BLOCK_SIZE] = {0};
    uint8_t decrypted[2U * CRYPTO_DES_BLOCK_SIZE] = {0};
    const cipher_vector *vector;
    crypto_status status;
    size_t index;

    for (index = 0U; index < (sizeof(vectors) / sizeof(vectors[0])); ++index)
    {
        vector = &vectors[index];
        TEST_CASE(vector->name);
        memcpy(plaintext, vector->plaintext, CRYPTO_DES_BLOCK_SIZE);
        memcpy(plaintext + CRYPTO_DES_BLOCK_SIZE, vector->plaintext, CRYPTO_DES_BLOCK_SIZE);
        memcpy(expected, vector->ciphertext, CRYPTO_DES_BLOCK_SIZE);
        memcpy(expected + CRYPTO_DES_BLOCK_SIZE, vector->ciphertext, CRYPTO_DES_BLOCK_SIZE);
        status = vector->encrypt(vector->key, vector->key_length, CRYPTO_CIPHER_MODE_ECB, NULL, 0U,
                                 plaintext, sizeof(plaintext), encrypted, sizeof(encrypted));
        check_status(status, CRYPTO_STATUS_OK);
        TEST_CHECK(memcmp(encrypted, expected, sizeof(expected)) == 0);
        status = vector->decrypt(vector->key, vector->key_length, CRYPTO_CIPHER_MODE_ECB, NULL, 0U,
                                 encrypted, sizeof(encrypted), decrypted, sizeof(decrypted));
        check_status(status, CRYPTO_STATUS_OK);
        TEST_CHECK(memcmp(decrypted, plaintext, sizeof(plaintext)) == 0);
    }
    return;
}

/** @brief Verify that DES and TDES operations ignore every encoded parity bit. */
static void test_parity_ignored(void)
{
    static const uint8_t des_even_parity[CRYPTO_DES_KEY_SIZE] = {0x12, 0x35, 0x56, 0x78,
                                                                 0x9a, 0xbd, 0xde, 0xf0};
    static const uint8_t tdes2_even_parity[CRYPTO_TDES2_KEY_SIZE] = {
        0x00, 0x22, 0x44, 0x66, 0x88, 0xaa, 0xcc, 0xee,
        0x22, 0x44, 0x66, 0x88, 0xaa, 0xcc, 0xee, 0x00};
    static const uint8_t tdes3_even_parity[CRYPTO_TDES3_KEY_SIZE] = {
        0x00, 0x22, 0x44, 0x66, 0x88, 0xaa, 0xcc, 0xee, 0x22, 0x44, 0x66, 0x88,
        0xaa, 0xcc, 0xee, 0x00, 0x44, 0x66, 0x88, 0xaa, 0xcc, 0xee, 0x00, 0x22};
    static const cipher_vector vectors[] = {
        {"DES", crypto_des_encrypt, crypto_des_decrypt, des_even_parity, sizeof(des_even_parity),
         des_plaintext, des_ciphertext},
        {"2TDES", crypto_tdes_encrypt, crypto_tdes_decrypt, tdes2_even_parity,
         sizeof(tdes2_even_parity), tdes_plaintext, tdes2_ciphertext},
        {"3TDES", crypto_tdes_encrypt, crypto_tdes_decrypt, tdes3_even_parity,
         sizeof(tdes3_even_parity), tdes_plaintext, tdes3_ciphertext}};
    uint8_t encrypted[CRYPTO_DES_BLOCK_SIZE] = {0};
    uint8_t decrypted[CRYPTO_DES_BLOCK_SIZE] = {0};
    const cipher_vector *vector;
    crypto_status status;
    size_t index;

    for (index = 0U; index < (sizeof(vectors) / sizeof(vectors[0])); ++index)
    {
        vector = &vectors[index];
        TEST_CASE(vector->name);
        status =
            vector->encrypt(vector->key, vector->key_length, CRYPTO_CIPHER_MODE_ECB, NULL, 0U,
                            vector->plaintext, CRYPTO_DES_BLOCK_SIZE, encrypted, sizeof(encrypted));
        check_status(status, CRYPTO_STATUS_OK);
        check_block(encrypted, vector->ciphertext);
        status = vector->decrypt(vector->key, vector->key_length, CRYPTO_CIPHER_MODE_ECB, NULL, 0U,
                                 vector->ciphertext, CRYPTO_DES_BLOCK_SIZE, decrypted,
                                 sizeof(decrypted));
        check_status(status, CRYPTO_STATUS_OK);
        check_block(decrypted, vector->plaintext);
    }
    return;
}

/** @brief Exercise weak-key and TDES degeneracy rejection. */
static void test_key_validation(void)
{
    static const uint8_t weak_key[CRYPTO_DES_KEY_SIZE] = {0x01, 0x01, 0x01, 0x01,
                                                          0x01, 0x01, 0x01, 0x01};
    static const uint8_t weak_key_even_parity[CRYPTO_DES_KEY_SIZE] = {0};
    static const uint8_t parity_different_repeated_key[CRYPTO_TDES2_KEY_SIZE] = {
        0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1,
        0x12, 0x35, 0x56, 0x78, 0x9a, 0xbd, 0xde, 0xf0};
    static const uint8_t repeated_first_key3[CRYPTO_TDES3_KEY_SIZE] = {
        0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1, 0x01, 0x23, 0x45, 0x67,
        0x89, 0xab, 0xcd, 0xef, 0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1};
    static const uint8_t repeated_last_key3[CRYPTO_TDES3_KEY_SIZE] = {
        0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1, 0x01, 0x23, 0x45, 0x67,
        0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    static const uint8_t weak_tdes_component[CRYPTO_TDES3_KEY_SIZE] = {
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x23, 0x45, 0x67,
        0x89, 0xab, 0xcd, 0xef, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23};
    static const key_validation_case cases[] = {
        {"DES/weak-key", crypto_des_encrypt, weak_key, sizeof(weak_key), CRYPTO_STATUS_WEAK_KEY},
        {"DES/weak-key-even-parity", crypto_des_encrypt, weak_key_even_parity,
         sizeof(weak_key_even_parity), CRYPTO_STATUS_WEAK_KEY},
        {"2TDES/parity-different-repeated-key", crypto_tdes_encrypt, parity_different_repeated_key,
         sizeof(parity_different_repeated_key), CRYPTO_STATUS_DEGENERATE_KEY},
        {"3TDES/first-equals-third", crypto_tdes_encrypt, repeated_first_key3,
         sizeof(repeated_first_key3), CRYPTO_STATUS_DEGENERATE_KEY},
        {"3TDES/second-equals-third", crypto_tdes_encrypt, repeated_last_key3,
         sizeof(repeated_last_key3), CRYPTO_STATUS_DEGENERATE_KEY},
        {"3TDES/weak-component", crypto_tdes_encrypt, weak_tdes_component,
         sizeof(weak_tdes_component), CRYPTO_STATUS_WEAK_KEY}};
    uint8_t output[CRYPTO_DES_BLOCK_SIZE] = {0};
    const key_validation_case *test_case;
    crypto_status status;
    size_t index;

    for (index = 0U; index < (sizeof(cases) / sizeof(cases[0])); ++index)
    {
        test_case = &cases[index];
        TEST_CASE(test_case->name);
        status =
            test_case->operation(test_case->key, test_case->key_length, CRYPTO_CIPHER_MODE_ECB,
                                 NULL, 0U, zero_block, sizeof(zero_block), output, sizeof(output));
        check_status(status, test_case->expected);
    }
    return;
}

/** @brief Exercise every public argument-validation branch for DES and TDES. */
static void test_public_contract(void)
{
    uint8_t storage[(2U * CRYPTO_DES_BLOCK_SIZE) + 1U] = {0};
    uint8_t output[2U * CRYPTO_DES_BLOCK_SIZE] = {0};
    const contract_case cases[] = {
        {"DES/null-key", crypto_des_encrypt, NULL, sizeof(des_key), CRYPTO_CIPHER_MODE_ECB, NULL,
         0U, storage, CRYPTO_DES_BLOCK_SIZE, output, CRYPTO_DES_BLOCK_SIZE,
         CRYPTO_STATUS_NULL_ARGUMENT},
        {"DES/null-input", crypto_des_encrypt, des_key, sizeof(des_key), CRYPTO_CIPHER_MODE_ECB,
         NULL, 0U, NULL, CRYPTO_DES_BLOCK_SIZE, output, CRYPTO_DES_BLOCK_SIZE,
         CRYPTO_STATUS_NULL_ARGUMENT},
        {"DES/null-output", crypto_des_encrypt, des_key, sizeof(des_key), CRYPTO_CIPHER_MODE_ECB,
         NULL, 0U, storage, CRYPTO_DES_BLOCK_SIZE, NULL, CRYPTO_DES_BLOCK_SIZE,
         CRYPTO_STATUS_NULL_ARGUMENT},
        {"DES/invalid-mode", crypto_des_encrypt, des_key, sizeof(des_key), (crypto_cipher_mode)99,
         NULL, 0U, storage, CRYPTO_DES_BLOCK_SIZE, output, CRYPTO_DES_BLOCK_SIZE,
         CRYPTO_STATUS_INVALID_MODE},
        {"DES/invalid-iv-length", crypto_des_encrypt, des_key, sizeof(des_key),
         CRYPTO_CIPHER_MODE_ECB, storage, 1U, storage, CRYPTO_DES_BLOCK_SIZE, output,
         CRYPTO_DES_BLOCK_SIZE, CRYPTO_STATUS_INVALID_LENGTH},
        {"DES/invalid-input-length", crypto_des_encrypt, des_key, sizeof(des_key),
         CRYPTO_CIPHER_MODE_ECB, NULL, 0U, storage, CRYPTO_DES_BLOCK_SIZE - 1U, output,
         CRYPTO_DES_BLOCK_SIZE, CRYPTO_STATUS_INVALID_LENGTH},
        {"DES/invalid-output-length", crypto_des_encrypt, des_key, sizeof(des_key),
         CRYPTO_CIPHER_MODE_ECB, NULL, 0U, storage, CRYPTO_DES_BLOCK_SIZE, output,
         (2U * CRYPTO_DES_BLOCK_SIZE), CRYPTO_STATUS_INVALID_LENGTH},
        {"DES/invalid-key-length", crypto_des_encrypt, des_key, sizeof(des_key) - 1U,
         CRYPTO_CIPHER_MODE_ECB, NULL, 0U, storage, CRYPTO_DES_BLOCK_SIZE, output,
         CRYPTO_DES_BLOCK_SIZE, CRYPTO_STATUS_INVALID_LENGTH},
        {"DES/empty-input", crypto_des_encrypt, des_key, sizeof(des_key), CRYPTO_CIPHER_MODE_ECB,
         NULL, 0U, storage, 0U, output, 0U, CRYPTO_STATUS_OK},
        {"DES/same-buffer", crypto_des_encrypt, des_key, sizeof(des_key), CRYPTO_CIPHER_MODE_ECB,
         NULL, 0U, storage, CRYPTO_DES_BLOCK_SIZE, storage, CRYPTO_DES_BLOCK_SIZE,
         CRYPTO_STATUS_OVERLAPPING_BUFFERS},
        {"DES/forward-overlap", crypto_des_encrypt, des_key, sizeof(des_key),
         CRYPTO_CIPHER_MODE_ECB, NULL, 0U, storage, CRYPTO_DES_BLOCK_SIZE, storage + 1U,
         CRYPTO_DES_BLOCK_SIZE, CRYPTO_STATUS_OVERLAPPING_BUFFERS},
        {"DES/reverse-overlap", crypto_des_encrypt, des_key, sizeof(des_key),
         CRYPTO_CIPHER_MODE_ECB, NULL, 0U, storage + 1U, CRYPTO_DES_BLOCK_SIZE, storage,
         CRYPTO_DES_BLOCK_SIZE, CRYPTO_STATUS_OVERLAPPING_BUFFERS},
        {"TDES/null-key", crypto_tdes_encrypt, NULL, sizeof(tdes2_key), CRYPTO_CIPHER_MODE_ECB,
         NULL, 0U, storage, CRYPTO_DES_BLOCK_SIZE, output, CRYPTO_DES_BLOCK_SIZE,
         CRYPTO_STATUS_NULL_ARGUMENT},
        {"TDES/null-input", crypto_tdes_encrypt, tdes2_key, sizeof(tdes2_key),
         CRYPTO_CIPHER_MODE_ECB, NULL, 0U, NULL, CRYPTO_DES_BLOCK_SIZE, output,
         CRYPTO_DES_BLOCK_SIZE, CRYPTO_STATUS_NULL_ARGUMENT},
        {"TDES/null-output", crypto_tdes_encrypt, tdes2_key, sizeof(tdes2_key),
         CRYPTO_CIPHER_MODE_ECB, NULL, 0U, storage, CRYPTO_DES_BLOCK_SIZE, NULL,
         CRYPTO_DES_BLOCK_SIZE, CRYPTO_STATUS_NULL_ARGUMENT},
        {"TDES/invalid-mode", crypto_tdes_encrypt, tdes2_key, sizeof(tdes2_key),
         (crypto_cipher_mode)99, NULL, 0U, storage, CRYPTO_DES_BLOCK_SIZE, output,
         CRYPTO_DES_BLOCK_SIZE, CRYPTO_STATUS_INVALID_MODE},
        {"TDES/invalid-iv-length", crypto_tdes_encrypt, tdes2_key, sizeof(tdes2_key),
         CRYPTO_CIPHER_MODE_ECB, storage, 1U, storage, CRYPTO_DES_BLOCK_SIZE, output,
         CRYPTO_DES_BLOCK_SIZE, CRYPTO_STATUS_INVALID_LENGTH},
        {"TDES/invalid-input-length", crypto_tdes_encrypt, tdes2_key, sizeof(tdes2_key),
         CRYPTO_CIPHER_MODE_ECB, NULL, 0U, storage, CRYPTO_DES_BLOCK_SIZE - 1U, output,
         CRYPTO_DES_BLOCK_SIZE, CRYPTO_STATUS_INVALID_LENGTH},
        {"TDES/invalid-output-length", crypto_tdes_encrypt, tdes2_key, sizeof(tdes2_key),
         CRYPTO_CIPHER_MODE_ECB, NULL, 0U, storage, CRYPTO_DES_BLOCK_SIZE, output,
         (2U * CRYPTO_DES_BLOCK_SIZE), CRYPTO_STATUS_INVALID_LENGTH},
        {"TDES/invalid-key-length", crypto_tdes_encrypt, tdes2_key, sizeof(tdes2_key) - 1U,
         CRYPTO_CIPHER_MODE_ECB, NULL, 0U, storage, CRYPTO_DES_BLOCK_SIZE, output,
         CRYPTO_DES_BLOCK_SIZE, CRYPTO_STATUS_INVALID_LENGTH},
        {"TDES/empty-input", crypto_tdes_encrypt, tdes2_key, sizeof(tdes2_key),
         CRYPTO_CIPHER_MODE_ECB, NULL, 0U, storage, 0U, output, 0U, CRYPTO_STATUS_OK},
        {"TDES/same-buffer", crypto_tdes_encrypt, tdes2_key, sizeof(tdes2_key),
         CRYPTO_CIPHER_MODE_ECB, NULL, 0U, storage, CRYPTO_DES_BLOCK_SIZE, storage,
         CRYPTO_DES_BLOCK_SIZE, CRYPTO_STATUS_OVERLAPPING_BUFFERS},
        {"TDES/forward-overlap", crypto_tdes_encrypt, tdes2_key, sizeof(tdes2_key),
         CRYPTO_CIPHER_MODE_ECB, NULL, 0U, storage, CRYPTO_DES_BLOCK_SIZE, storage + 1U,
         CRYPTO_DES_BLOCK_SIZE, CRYPTO_STATUS_OVERLAPPING_BUFFERS},
        {"TDES/reverse-overlap", crypto_tdes_encrypt, tdes2_key, sizeof(tdes2_key),
         CRYPTO_CIPHER_MODE_ECB, NULL, 0U, storage + 1U, CRYPTO_DES_BLOCK_SIZE, storage,
         CRYPTO_DES_BLOCK_SIZE, CRYPTO_STATUS_OVERLAPPING_BUFFERS}};
    const contract_case *test_case;
    crypto_status status;
    size_t index;

    for (index = 0U; index < (sizeof(cases) / sizeof(cases[0])); ++index)
    {
        test_case = &cases[index];
        TEST_CASE(test_case->name);
        status = test_case->operation(test_case->key, test_case->key_length, test_case->mode,
                                      test_case->iv, test_case->iv_length, test_case->input,
                                      test_case->input_length, test_case->output,
                                      test_case->output_length);
        check_status(status, test_case->expected);
    }
    return;
}

/** @brief Verify that every published status has a stable description. */
static void test_status_strings(void)
{
    int value;

    for (value = (int)CRYPTO_STATUS_OK; value <= (int)CRYPTO_STATUS_INVALID_MODE; ++value)
    {
        TEST_CASE(crypto_status_string((crypto_status)value));
        TEST_CHECK(strcmp(crypto_status_string((crypto_status)value), "unknown status") != 0);
    }
    TEST_CASE("out-of-range");
    TEST_CHECK(strcmp(crypto_status_string((crypto_status)999), "unknown status") == 0);
    return;
}

TEST_LIST = {{"vectors/known-answer", test_known_answer_vectors},
             {"ecb/multiple-blocks", test_multiple_blocks},
             {"keys/parity-ignored", test_parity_ignored},
             {"keys/validation", test_key_validation},
             {"api/contract", test_public_contract},
             {"status/strings", test_status_strings},
             {NULL, NULL}};
