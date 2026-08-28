#include <acutest.h>

#include <des.h>
#include <status.h>
#include <tdes.h>
#include <version.h>

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

/** @brief Known-answer vector for a one-shot block-chaining operation. */
typedef struct mode_vector
{
    const char *name;           /**< Name shown by the test runner. */
    cipher_operation encrypt;   /**< Encryption operation. */
    cipher_operation decrypt;   /**< Decryption operation. */
    const uint8_t *key;         /**< Encoded key. */
    size_t key_length;          /**< Encoded key length. */
    const uint8_t *iv;          /**< Initialization vector. */
    const uint8_t *plaintext;   /**< Expected plaintext blocks. */
    size_t plaintext_length;    /**< Plaintext length in bytes. */
    const uint8_t *ciphertext;  /**< Expected ciphertext blocks. */
} mode_vector;

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

/** @brief DES key with every encoded parity bit inverted. */
static const uint8_t des_even_parity[CRYPTO_DES_KEY_SIZE] = {0x12, 0x35, 0x56, 0x78,
                                                             0x9a, 0xbd, 0xde, 0xf0};

/** @brief Two-key TDES bundle with every encoded parity bit inverted. */
static const uint8_t tdes2_even_parity[CRYPTO_TDES2_KEY_SIZE] = {
    0x00, 0x22, 0x44, 0x66, 0x88, 0xaa, 0xcc, 0xee,
    0x22, 0x44, 0x66, 0x88, 0xaa, 0xcc, 0xee, 0x00};

/** @brief Three-key TDES bundle with every encoded parity bit inverted. */
static const uint8_t tdes3_even_parity[CRYPTO_TDES3_KEY_SIZE] = {
    0x00, 0x22, 0x44, 0x66, 0x88, 0xaa, 0xcc, 0xee, 0x22, 0x44, 0x66, 0x88,
    0xaa, 0xcc, 0xee, 0x00, 0x44, 0x66, 0x88, 0xaa, 0xcc, 0xee, 0x00, 0x22};

/** @brief Published DES CBC example key. */
static const uint8_t des_cbc_key[CRYPTO_DES_KEY_SIZE] = {0x01, 0x23, 0x45, 0x67,
                                                         0x89, 0xab, 0xcd, 0xef};

/** @brief DES CBC example key with every encoded parity bit inverted. */
static const uint8_t des_cbc_even_parity[CRYPTO_DES_KEY_SIZE] = {0x00, 0x22, 0x44, 0x66,
                                                                 0x88, 0xaa, 0xcc, 0xee};

/** @brief Published DES CBC example initialization vector. */
static const uint8_t des_cbc_iv[CRYPTO_DES_BLOCK_SIZE] = {0x12, 0x34, 0x56, 0x78,
                                                          0x90, 0xab, 0xcd, 0xef};

/** @brief Published DES CBC example plaintext ("Now is the time for all "). */
static const uint8_t des_cbc_plaintext[3U * CRYPTO_DES_BLOCK_SIZE] = {
    0x4e, 0x6f, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20, 0x74,
    0x69, 0x6d, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x61, 0x6c, 0x6c, 0x20};

/** @brief Published DES CBC example ciphertext. */
static const uint8_t des_cbc_ciphertext[3U * CRYPTO_DES_BLOCK_SIZE] = {
    0xe5, 0xc7, 0xcd, 0xde, 0x87, 0x2b, 0xf2, 0x7c, 0x43, 0xe9, 0x34, 0x00,
    0x8c, 0x38, 0x9c, 0x0f, 0x68, 0x37, 0x88, 0x49, 0x9a, 0x7c, 0x05, 0xf6};

/** @brief TDES CBC initialization vector derived from the published ECB vectors. */
static const uint8_t tdes_cbc_iv[CRYPTO_DES_BLOCK_SIZE] = {0xca, 0xfe, 0xba, 0xbe,
                                                           0xca, 0xfe, 0xba, 0xbe};

/** @brief TDES CBC plaintext: the published ECB block repeated three times. */
static const uint8_t tdes_cbc_plaintext[3U * CRYPTO_DES_BLOCK_SIZE] = {
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x98,
    0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

/** @brief Two-key TDES CBC ciphertext verified against an independent implementation. */
static const uint8_t tdes2_cbc_ciphertext[3U * CRYPTO_DES_BLOCK_SIZE] = {
    0x1e, 0xb5, 0x00, 0x95, 0x25, 0xac, 0xfe, 0x2b, 0xda, 0x45, 0xc2, 0xdd,
    0xa9, 0xe4, 0x0f, 0xcc, 0xd7, 0xfe, 0x61, 0x6c, 0x79, 0x6a, 0x1f, 0xfd};

/** @brief Three-key TDES CBC ciphertext verified against an independent implementation. */
static const uint8_t tdes3_cbc_ciphertext[3U * CRYPTO_DES_BLOCK_SIZE] = {
    0xc2, 0xea, 0x00, 0x0c, 0x16, 0x90, 0xda, 0xdf, 0x2f, 0x11, 0x21, 0x0b,
    0xb3, 0xc1, 0xdc, 0x2c, 0x2c, 0xa3, 0xd8, 0x9a, 0x53, 0xd4, 0x96, 0xf1};

/** @brief DES CFB64 ciphertext verified against an independent implementation. */
static const uint8_t des_cfb64_ciphertext[3U * CRYPTO_DES_BLOCK_SIZE] = {
    0xf3, 0x09, 0x62, 0x49, 0xc7, 0xf4, 0x6e, 0x51, 0xa6, 0x9e, 0x83, 0x9b,
    0x1a, 0x92, 0xf7, 0x84, 0x03, 0x46, 0x71, 0x33, 0x89, 0x8e, 0xa6, 0x22};

/** @brief Two-key TDES CFB64 ciphertext verified against an independent implementation. */
static const uint8_t tdes2_cfb64_ciphertext[3U * CRYPTO_DES_BLOCK_SIZE] = {
    0xe5, 0x97, 0xdc, 0xb1, 0x16, 0x0f, 0xc3, 0xe3, 0x86, 0x7b, 0xe6, 0x44,
    0xaa, 0x14, 0x11, 0xc2, 0xc1, 0x0f, 0x5c, 0x57, 0xed, 0x9b, 0x54, 0x97};

/** @brief Three-key TDES CFB64 ciphertext verified against an independent implementation. */
static const uint8_t tdes3_cfb64_ciphertext[3U * CRYPTO_DES_BLOCK_SIZE] = {
    0x43, 0x1e, 0xd7, 0xd7, 0xf3, 0x75, 0x19, 0x29, 0xb5, 0xa6, 0xf0, 0x4f,
    0x01, 0xf3, 0x52, 0xd0, 0xce, 0x2d, 0xcd, 0xff, 0x57, 0x6e, 0x29, 0x90};

/** @brief DES OFB64 ciphertext verified against an independent implementation. */
static const uint8_t des_ofb64_ciphertext[3U * CRYPTO_DES_BLOCK_SIZE] = {
    0xf3, 0x09, 0x62, 0x49, 0xc7, 0xf4, 0x6e, 0x51, 0x35, 0xf2, 0x4a, 0x24,
    0x2e, 0xeb, 0x3d, 0x3f, 0x3d, 0x6d, 0x5b, 0xe3, 0x25, 0x5a, 0xf8, 0xc3};

/** @brief Two-key TDES OFB64 ciphertext verified against an independent implementation. */
static const uint8_t tdes2_ofb64_ciphertext[3U * CRYPTO_DES_BLOCK_SIZE] = {
    0xe5, 0x97, 0xdc, 0xb1, 0x16, 0x0f, 0xc3, 0xe3, 0x8f, 0x28, 0xbe, 0x08,
    0x7d, 0xba, 0xbd, 0x85, 0xff, 0x82, 0xae, 0xb0, 0xb2, 0x57, 0x5b, 0xa1};

/** @brief Three-key TDES OFB64 ciphertext verified against an independent implementation. */
static const uint8_t tdes3_ofb64_ciphertext[3U * CRYPTO_DES_BLOCK_SIZE] = {
    0x43, 0x1e, 0xd7, 0xd7, 0xf3, 0x75, 0x19, 0x29, 0xdf, 0x68, 0xb1, 0x32,
    0x0a, 0x87, 0x3b, 0xb8, 0x7c, 0xed, 0x02, 0x54, 0x8f, 0xc3, 0x00, 0x58};

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

/** @brief Exercise DES, two-key TDES, and three-key TDES CBC known-answer vectors. */
static void test_cbc_known_answer_vectors(void)
{
    static const mode_vector vectors[] = {
        {"DES", crypto_des_encrypt, crypto_des_decrypt, des_cbc_key, sizeof(des_cbc_key),
         des_cbc_iv, des_cbc_plaintext, sizeof(des_cbc_plaintext), des_cbc_ciphertext},
        {"2TDES", crypto_tdes_encrypt, crypto_tdes_decrypt, tdes2_key, sizeof(tdes2_key),
         tdes_cbc_iv, tdes_cbc_plaintext, sizeof(tdes_cbc_plaintext), tdes2_cbc_ciphertext},
        {"3TDES", crypto_tdes_encrypt, crypto_tdes_decrypt, tdes3_key, sizeof(tdes3_key),
         tdes_cbc_iv, tdes_cbc_plaintext, sizeof(tdes_cbc_plaintext), tdes3_cbc_ciphertext}};
    uint8_t encrypted[3U * CRYPTO_DES_BLOCK_SIZE] = {0};
    uint8_t decrypted[3U * CRYPTO_DES_BLOCK_SIZE] = {0};
    const mode_vector *vector;
    crypto_status status;
    size_t index;

    for (index = 0U; index < (sizeof(vectors) / sizeof(vectors[0])); ++index)
    {
        vector = &vectors[index];
        TEST_CASE(vector->name);
        status =
            vector->encrypt(vector->key, vector->key_length, CRYPTO_CIPHER_MODE_CBC, vector->iv,
                            CRYPTO_DES_BLOCK_SIZE, vector->plaintext, vector->plaintext_length,
                            encrypted, sizeof(encrypted));
        check_status(status, CRYPTO_STATUS_OK);
        TEST_CHECK(memcmp(encrypted, vector->ciphertext, sizeof(encrypted)) == 0);
        status = vector->decrypt(vector->key, vector->key_length, CRYPTO_CIPHER_MODE_CBC,
                                 vector->iv, CRYPTO_DES_BLOCK_SIZE, encrypted, sizeof(encrypted),
                                 decrypted, sizeof(decrypted));
        check_status(status, CRYPTO_STATUS_OK);
        TEST_CHECK(memcmp(decrypted, vector->plaintext, sizeof(decrypted)) == 0);
    }
    return;
}

/** @brief Verify that CBC ignores every encoded parity bit, matching the ECB results. */
static void test_cbc_parity_ignored(void)
{
    static const mode_vector vectors[] = {
        {"DES", crypto_des_encrypt, crypto_des_decrypt, des_cbc_even_parity,
         sizeof(des_cbc_even_parity), des_cbc_iv, des_cbc_plaintext, sizeof(des_cbc_plaintext),
         des_cbc_ciphertext},
        {"2TDES", crypto_tdes_encrypt, crypto_tdes_decrypt, tdes2_even_parity,
         sizeof(tdes2_even_parity), tdes_cbc_iv, tdes_cbc_plaintext, sizeof(tdes_cbc_plaintext),
         tdes2_cbc_ciphertext},
        {"3TDES", crypto_tdes_encrypt, crypto_tdes_decrypt, tdes3_even_parity,
         sizeof(tdes3_even_parity), tdes_cbc_iv, tdes_cbc_plaintext, sizeof(tdes_cbc_plaintext),
         tdes3_cbc_ciphertext}};
    uint8_t encrypted[3U * CRYPTO_DES_BLOCK_SIZE] = {0};
    uint8_t decrypted[3U * CRYPTO_DES_BLOCK_SIZE] = {0};
    const mode_vector *vector;
    crypto_status status;
    size_t index;

    for (index = 0U; index < (sizeof(vectors) / sizeof(vectors[0])); ++index)
    {
        vector = &vectors[index];
        TEST_CASE(vector->name);
        status =
            vector->encrypt(vector->key, vector->key_length, CRYPTO_CIPHER_MODE_CBC, vector->iv,
                            CRYPTO_DES_BLOCK_SIZE, vector->plaintext, vector->plaintext_length,
                            encrypted, sizeof(encrypted));
        check_status(status, CRYPTO_STATUS_OK);
        TEST_CHECK(memcmp(encrypted, vector->ciphertext, sizeof(encrypted)) == 0);
        status = vector->decrypt(vector->key, vector->key_length, CRYPTO_CIPHER_MODE_CBC,
                                 vector->iv, CRYPTO_DES_BLOCK_SIZE, encrypted, sizeof(encrypted),
                                 decrypted, sizeof(decrypted));
        check_status(status, CRYPTO_STATUS_OK);
        TEST_CHECK(memcmp(decrypted, vector->plaintext, sizeof(decrypted)) == 0);
    }
    return;
}

/** @brief Verify that CFB64 ignores every encoded parity bit, matching the CBC results. */
static void test_cfb64_parity_ignored(void)
{
    static const mode_vector vectors[] = {
        {"DES", crypto_des_encrypt, crypto_des_decrypt, des_cbc_even_parity,
         sizeof(des_cbc_even_parity), des_cbc_iv, des_cbc_plaintext, sizeof(des_cbc_plaintext),
         des_cfb64_ciphertext},
        {"2TDES", crypto_tdes_encrypt, crypto_tdes_decrypt, tdes2_even_parity,
         sizeof(tdes2_even_parity), tdes_cbc_iv, tdes_cbc_plaintext, sizeof(tdes_cbc_plaintext),
         tdes2_cfb64_ciphertext},
        {"3TDES", crypto_tdes_encrypt, crypto_tdes_decrypt, tdes3_even_parity,
         sizeof(tdes3_even_parity), tdes_cbc_iv, tdes_cbc_plaintext, sizeof(tdes_cbc_plaintext),
         tdes3_cfb64_ciphertext}};
    uint8_t encrypted[3U * CRYPTO_DES_BLOCK_SIZE] = {0};
    uint8_t decrypted[3U * CRYPTO_DES_BLOCK_SIZE] = {0};
    const mode_vector *vector;
    crypto_status status;
    size_t index;

    for (index = 0U; index < (sizeof(vectors) / sizeof(vectors[0])); ++index)
    {
        vector = &vectors[index];
        TEST_CASE(vector->name);
        status = vector->encrypt(vector->key, vector->key_length, CRYPTO_CIPHER_MODE_CFB64,
                                 vector->iv, CRYPTO_DES_BLOCK_SIZE, vector->plaintext,
                                 vector->plaintext_length, encrypted, sizeof(encrypted));
        check_status(status, CRYPTO_STATUS_OK);
        TEST_CHECK(memcmp(encrypted, vector->ciphertext, sizeof(encrypted)) == 0);
        status = vector->decrypt(vector->key, vector->key_length, CRYPTO_CIPHER_MODE_CFB64,
                                 vector->iv, CRYPTO_DES_BLOCK_SIZE, encrypted, sizeof(encrypted),
                                 decrypted, sizeof(decrypted));
        check_status(status, CRYPTO_STATUS_OK);
        TEST_CHECK(memcmp(decrypted, vector->plaintext, sizeof(decrypted)) == 0);
    }
    return;
}

/** @brief Exercise DES, two-key TDES, and three-key TDES CFB64 known-answer vectors. */
static void test_cfb64_known_answer_vectors(void)
{
    static const mode_vector vectors[] = {
        {"DES", crypto_des_encrypt, crypto_des_decrypt, des_cbc_key, sizeof(des_cbc_key),
         des_cbc_iv, des_cbc_plaintext, sizeof(des_cbc_plaintext), des_cfb64_ciphertext},
        {"2TDES", crypto_tdes_encrypt, crypto_tdes_decrypt, tdes2_key, sizeof(tdes2_key),
         tdes_cbc_iv, tdes_cbc_plaintext, sizeof(tdes_cbc_plaintext), tdes2_cfb64_ciphertext},
        {"3TDES", crypto_tdes_encrypt, crypto_tdes_decrypt, tdes3_key, sizeof(tdes3_key),
         tdes_cbc_iv, tdes_cbc_plaintext, sizeof(tdes_cbc_plaintext), tdes3_cfb64_ciphertext}};
    uint8_t encrypted[3U * CRYPTO_DES_BLOCK_SIZE] = {0};
    uint8_t decrypted[3U * CRYPTO_DES_BLOCK_SIZE] = {0};
    const mode_vector *vector;
    crypto_status status;
    size_t index;

    for (index = 0U; index < (sizeof(vectors) / sizeof(vectors[0])); ++index)
    {
        vector = &vectors[index];
        TEST_CASE(vector->name);
        status = vector->encrypt(vector->key, vector->key_length, CRYPTO_CIPHER_MODE_CFB64,
                                 vector->iv, CRYPTO_DES_BLOCK_SIZE, vector->plaintext,
                                 vector->plaintext_length, encrypted, sizeof(encrypted));
        check_status(status, CRYPTO_STATUS_OK);
        TEST_CHECK(memcmp(encrypted, vector->ciphertext, sizeof(encrypted)) == 0);
        status = vector->decrypt(vector->key, vector->key_length, CRYPTO_CIPHER_MODE_CFB64,
                                 vector->iv, CRYPTO_DES_BLOCK_SIZE, encrypted, sizeof(encrypted),
                                 decrypted, sizeof(decrypted));
        check_status(status, CRYPTO_STATUS_OK);
        TEST_CHECK(memcmp(decrypted, vector->plaintext, sizeof(decrypted)) == 0);
    }
    return;
}

/** @brief Verify that the first CFB64 block is the ECB encryption of the IV XOR the plaintext. */
static void test_cfb64_first_block_identity(void)
{
    uint8_t keystream[CRYPTO_DES_BLOCK_SIZE] = {0};
    uint8_t expected[CRYPTO_DES_BLOCK_SIZE] = {0};
    uint8_t actual[CRYPTO_DES_BLOCK_SIZE] = {0};
    crypto_status status;
    size_t index;

    status = crypto_des_encrypt(des_cbc_key, sizeof(des_cbc_key), CRYPTO_CIPHER_MODE_ECB, NULL, 0U,
                                des_cbc_iv, sizeof(des_cbc_iv), keystream, sizeof(keystream));
    check_status(status, CRYPTO_STATUS_OK);
    for (index = 0U; index < CRYPTO_DES_BLOCK_SIZE; ++index)
    {
        expected[index] = (uint8_t)(des_cbc_plaintext[index] ^ keystream[index]);
    }
    status = crypto_des_encrypt(des_cbc_key, sizeof(des_cbc_key), CRYPTO_CIPHER_MODE_CFB64,
                                des_cbc_iv, sizeof(des_cbc_iv), des_cbc_plaintext,
                                CRYPTO_DES_BLOCK_SIZE, actual, sizeof(actual));
    check_status(status, CRYPTO_STATUS_OK);
    check_block(actual, expected);
    return;
}

/** @brief Verify that the first OFB64 block is the ECB encryption of the IV XOR the plaintext. */
static void test_ofb64_first_block_identity(void)
{
    uint8_t keystream[CRYPTO_DES_BLOCK_SIZE] = {0};
    uint8_t expected[CRYPTO_DES_BLOCK_SIZE] = {0};
    uint8_t actual[CRYPTO_DES_BLOCK_SIZE] = {0};
    crypto_status status;
    size_t index;

    status = crypto_des_encrypt(des_cbc_key, sizeof(des_cbc_key), CRYPTO_CIPHER_MODE_ECB, NULL, 0U,
                                des_cbc_iv, sizeof(des_cbc_iv), keystream, sizeof(keystream));
    check_status(status, CRYPTO_STATUS_OK);
    for (index = 0U; index < CRYPTO_DES_BLOCK_SIZE; ++index)
    {
        expected[index] = (uint8_t)(des_cbc_plaintext[index] ^ keystream[index]);
    }
    status = crypto_des_encrypt(des_cbc_key, sizeof(des_cbc_key), CRYPTO_CIPHER_MODE_OFB64,
                                des_cbc_iv, sizeof(des_cbc_iv), des_cbc_plaintext,
                                CRYPTO_DES_BLOCK_SIZE, actual, sizeof(actual));
    check_status(status, CRYPTO_STATUS_OK);
    check_block(actual, expected);
    return;
}

/** @brief Exercise DES, two-key TDES, and three-key TDES OFB64 known-answer vectors. */
static void test_ofb64_known_answer_vectors(void)
{
    static const mode_vector vectors[] = {
        {"DES", crypto_des_encrypt, crypto_des_decrypt, des_cbc_key, sizeof(des_cbc_key),
         des_cbc_iv, des_cbc_plaintext, sizeof(des_cbc_plaintext), des_ofb64_ciphertext},
        {"2TDES", crypto_tdes_encrypt, crypto_tdes_decrypt, tdes2_key, sizeof(tdes2_key),
         tdes_cbc_iv, tdes_cbc_plaintext, sizeof(tdes_cbc_plaintext), tdes2_ofb64_ciphertext},
        {"3TDES", crypto_tdes_encrypt, crypto_tdes_decrypt, tdes3_key, sizeof(tdes3_key),
         tdes_cbc_iv, tdes_cbc_plaintext, sizeof(tdes_cbc_plaintext), tdes3_ofb64_ciphertext}};
    uint8_t encrypted[3U * CRYPTO_DES_BLOCK_SIZE] = {0};
    uint8_t decrypted[3U * CRYPTO_DES_BLOCK_SIZE] = {0};
    const mode_vector *vector;
    crypto_status status;
    size_t index;

    for (index = 0U; index < (sizeof(vectors) / sizeof(vectors[0])); ++index)
    {
        vector = &vectors[index];
        TEST_CASE(vector->name);
        status = vector->encrypt(vector->key, vector->key_length, CRYPTO_CIPHER_MODE_OFB64,
                                 vector->iv, CRYPTO_DES_BLOCK_SIZE, vector->plaintext,
                                 vector->plaintext_length, encrypted, sizeof(encrypted));
        check_status(status, CRYPTO_STATUS_OK);
        TEST_CHECK(memcmp(encrypted, vector->ciphertext, sizeof(encrypted)) == 0);
        status = vector->decrypt(vector->key, vector->key_length, CRYPTO_CIPHER_MODE_OFB64,
                                 vector->iv, CRYPTO_DES_BLOCK_SIZE, encrypted, sizeof(encrypted),
                                 decrypted, sizeof(decrypted));
        check_status(status, CRYPTO_STATUS_OK);
        TEST_CHECK(memcmp(decrypted, vector->plaintext, sizeof(decrypted)) == 0);
    }
    return;
}

/** @brief Verify that OFB64 ignores every key parity bit. */
static void test_ofb64_parity_ignored(void)
{
    static const mode_vector vectors[] = {
        {"DES", crypto_des_encrypt, crypto_des_decrypt, des_cbc_even_parity,
         sizeof(des_cbc_even_parity), des_cbc_iv, des_cbc_plaintext, sizeof(des_cbc_plaintext),
         des_ofb64_ciphertext},
        {"2TDES", crypto_tdes_encrypt, crypto_tdes_decrypt, tdes2_even_parity,
         sizeof(tdes2_even_parity), tdes_cbc_iv, tdes_cbc_plaintext, sizeof(tdes_cbc_plaintext),
         tdes2_ofb64_ciphertext},
        {"3TDES", crypto_tdes_encrypt, crypto_tdes_decrypt, tdes3_even_parity,
         sizeof(tdes3_even_parity), tdes_cbc_iv, tdes_cbc_plaintext, sizeof(tdes_cbc_plaintext),
         tdes3_ofb64_ciphertext}};
    uint8_t encrypted[3U * CRYPTO_DES_BLOCK_SIZE] = {0};
    uint8_t decrypted[3U * CRYPTO_DES_BLOCK_SIZE] = {0};
    const mode_vector *vector;
    crypto_status status;
    size_t index;

    for (index = 0U; index < (sizeof(vectors) / sizeof(vectors[0])); ++index)
    {
        vector = &vectors[index];
        TEST_CASE(vector->name);
        status = vector->encrypt(vector->key, vector->key_length, CRYPTO_CIPHER_MODE_OFB64,
                                 vector->iv, CRYPTO_DES_BLOCK_SIZE, vector->plaintext,
                                 vector->plaintext_length, encrypted, sizeof(encrypted));
        check_status(status, CRYPTO_STATUS_OK);
        TEST_CHECK(memcmp(encrypted, vector->ciphertext, sizeof(encrypted)) == 0);
        status = vector->decrypt(vector->key, vector->key_length, CRYPTO_CIPHER_MODE_OFB64,
                                 vector->iv, CRYPTO_DES_BLOCK_SIZE, encrypted, sizeof(encrypted),
                                 decrypted, sizeof(decrypted));
        check_status(status, CRYPTO_STATUS_OK);
        TEST_CHECK(memcmp(decrypted, vector->plaintext, sizeof(decrypted)) == 0);
    }
    return;
}

/** @brief Verify that a single-block CBC with a zero IV equals the ECB result. */
static void test_cbc_zero_iv_equals_ecb(void)
{
    static const uint8_t zero_iv[CRYPTO_DES_BLOCK_SIZE] = {0};
    uint8_t ecb_output[CRYPTO_DES_BLOCK_SIZE] = {0};
    uint8_t cbc_output[CRYPTO_DES_BLOCK_SIZE] = {0};
    crypto_status status;

    status = crypto_des_encrypt(des_key, sizeof(des_key), CRYPTO_CIPHER_MODE_ECB, NULL, 0U,
                                des_plaintext, sizeof(des_plaintext), ecb_output,
                                sizeof(ecb_output));
    check_status(status, CRYPTO_STATUS_OK);
    status = crypto_des_encrypt(des_key, sizeof(des_key), CRYPTO_CIPHER_MODE_CBC, zero_iv,
                                sizeof(zero_iv), des_plaintext, sizeof(des_plaintext), cbc_output,
                                sizeof(cbc_output));
    check_status(status, CRYPTO_STATUS_OK);
    TEST_CHECK(memcmp(ecb_output, cbc_output, CRYPTO_DES_BLOCK_SIZE) == 0);

    status = crypto_tdes_encrypt(tdes3_key, sizeof(tdes3_key), CRYPTO_CIPHER_MODE_ECB, NULL, 0U,
                                 tdes_plaintext, sizeof(tdes_plaintext), ecb_output,
                                 sizeof(ecb_output));
    check_status(status, CRYPTO_STATUS_OK);
    status = crypto_tdes_encrypt(tdes3_key, sizeof(tdes3_key), CRYPTO_CIPHER_MODE_CBC, zero_iv,
                                 sizeof(zero_iv), tdes_plaintext, sizeof(tdes_plaintext),
                                 cbc_output, sizeof(cbc_output));
    check_status(status, CRYPTO_STATUS_OK);
    TEST_CHECK(memcmp(ecb_output, cbc_output, CRYPTO_DES_BLOCK_SIZE) == 0);
    return;
}

/** @brief Verify one degenerate TDES bundle against its equivalent lower keying option. */
static void check_degenerate_tdes_case(const uint8_t *tdes_key, size_t tdes_key_length,
                                       cipher_operation equivalent_operation,
                                       const uint8_t *equivalent_key, size_t equivalent_key_length)
{
    static const uint8_t iv[CRYPTO_DES_BLOCK_SIZE] = {0x12, 0x34, 0x56, 0x78,
                                                      0x90, 0xab, 0xcd, 0xef};
    uint8_t expected[CRYPTO_DES_BLOCK_SIZE] = {0};
    uint8_t actual[CRYPTO_DES_BLOCK_SIZE] = {0};
    uint8_t decrypted[CRYPTO_DES_BLOCK_SIZE] = {0};
    crypto_status status;

    status =
        equivalent_operation(equivalent_key, equivalent_key_length, CRYPTO_CIPHER_MODE_ECB, NULL,
                             0U, zero_block, sizeof(zero_block), expected, sizeof(expected));
    check_status(status, CRYPTO_STATUS_OK);
    status = crypto_tdes_encrypt(tdes_key, tdes_key_length, CRYPTO_CIPHER_MODE_ECB, NULL, 0U,
                                 zero_block, sizeof(zero_block), actual, sizeof(actual));
    check_status(status, CRYPTO_STATUS_OK);
    check_block(actual, expected);
    status = crypto_tdes_decrypt(tdes_key, tdes_key_length, CRYPTO_CIPHER_MODE_ECB, NULL, 0U,
                                 actual, sizeof(actual), decrypted, sizeof(decrypted));
    check_status(status, CRYPTO_STATUS_OK);
    check_block(decrypted, zero_block);
    status =
        equivalent_operation(equivalent_key, equivalent_key_length, CRYPTO_CIPHER_MODE_CBC, iv,
                             sizeof(iv), zero_block, sizeof(zero_block), expected, sizeof(expected));
    check_status(status, CRYPTO_STATUS_OK);
    status = crypto_tdes_encrypt(tdes_key, tdes_key_length, CRYPTO_CIPHER_MODE_CBC, iv,
                                 sizeof(iv), zero_block, sizeof(zero_block), actual, sizeof(actual));
    check_status(status, CRYPTO_STATUS_OK);
    check_block(actual, expected);
    status = crypto_tdes_decrypt(tdes_key, tdes_key_length, CRYPTO_CIPHER_MODE_CBC, iv,
                                 sizeof(iv), actual, sizeof(actual), decrypted, sizeof(decrypted));
    check_status(status, CRYPTO_STATUS_OK);
    check_block(decrypted, zero_block);
    status =
        equivalent_operation(equivalent_key, equivalent_key_length, CRYPTO_CIPHER_MODE_CFB64, iv,
                             sizeof(iv), zero_block, sizeof(zero_block), expected, sizeof(expected));
    check_status(status, CRYPTO_STATUS_OK);
    status = crypto_tdes_encrypt(tdes_key, tdes_key_length, CRYPTO_CIPHER_MODE_CFB64, iv,
                                 sizeof(iv), zero_block, sizeof(zero_block), actual, sizeof(actual));
    check_status(status, CRYPTO_STATUS_OK);
    check_block(actual, expected);
    status = crypto_tdes_decrypt(tdes_key, tdes_key_length, CRYPTO_CIPHER_MODE_CFB64, iv,
                                 sizeof(iv), actual, sizeof(actual), decrypted, sizeof(decrypted));
    check_status(status, CRYPTO_STATUS_OK);
    check_block(decrypted, zero_block);
    status =
        equivalent_operation(equivalent_key, equivalent_key_length, CRYPTO_CIPHER_MODE_OFB64, iv,
                             sizeof(iv), zero_block, sizeof(zero_block), expected, sizeof(expected));
    check_status(status, CRYPTO_STATUS_OK);
    status = crypto_tdes_encrypt(tdes_key, tdes_key_length, CRYPTO_CIPHER_MODE_OFB64, iv,
                                 sizeof(iv), zero_block, sizeof(zero_block), actual, sizeof(actual));
    check_status(status, CRYPTO_STATUS_OK);
    check_block(actual, expected);
    status = crypto_tdes_decrypt(tdes_key, tdes_key_length, CRYPTO_CIPHER_MODE_OFB64, iv,
                                 sizeof(iv), actual, sizeof(actual), decrypted, sizeof(decrypted));
    check_status(status, CRYPTO_STATUS_OK);
    check_block(decrypted, zero_block);
    return;
}

/** @brief Verify processing of every TDES degeneracy class. */
static void test_degenerate_tdes_keys(void)
{
    static const uint8_t repeated_key2[CRYPTO_TDES2_KEY_SIZE] = {0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc,
                                                                 0xdf, 0xf1, 0x12, 0x35, 0x56, 0x78,
                                                                 0x9a, 0xbd, 0xde, 0xf0};
    static const uint8_t repeated_first_key3[CRYPTO_TDES3_KEY_SIZE] = {
        0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1, 0x12, 0x35, 0x56, 0x78,
        0x9a, 0xbd, 0xde, 0xf0, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01};
    static const uint8_t repeated_last_key3[CRYPTO_TDES3_KEY_SIZE] = {
        0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1, 0x23, 0x45, 0x67, 0x89,
        0xab, 0xcd, 0xef, 0x01, 0x22, 0x44, 0x66, 0x88, 0xaa, 0xcc, 0xee, 0x00};
    static const uint8_t repeated_outer_key3[CRYPTO_TDES3_KEY_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x23, 0x45, 0x67, 0x89,
        0xab, 0xcd, 0xef, 0x01, 0x00, 0x22, 0x44, 0x66, 0x88, 0xaa, 0xcc, 0xee};

    TEST_CASE("2TDES/K1-equals-K2");
    check_degenerate_tdes_case(repeated_key2, sizeof(repeated_key2), crypto_des_encrypt,
                               repeated_key2, CRYPTO_DES_KEY_SIZE);
    TEST_CASE("3TDES/K1-equals-K2");
    check_degenerate_tdes_case(repeated_first_key3, sizeof(repeated_first_key3), crypto_des_encrypt,
                               repeated_first_key3 + (2U * CRYPTO_DES_KEY_SIZE),
                               CRYPTO_DES_KEY_SIZE);
    TEST_CASE("3TDES/K2-equals-K3");
    check_degenerate_tdes_case(repeated_last_key3, sizeof(repeated_last_key3), crypto_des_encrypt,
                               repeated_last_key3, CRYPTO_DES_KEY_SIZE);
    TEST_CASE("3TDES/K1-equals-K3");
    check_degenerate_tdes_case(repeated_outer_key3, sizeof(repeated_outer_key3),
                               crypto_tdes_encrypt, repeated_outer_key3, CRYPTO_TDES2_KEY_SIZE);
    return;
}

/** @brief Exercise weak-key rejection for DES and TDES components. */
static void test_key_validation(void)
{
    static const uint8_t weak_key[CRYPTO_DES_KEY_SIZE] = {0x01, 0x01, 0x01, 0x01,
                                                          0x01, 0x01, 0x01, 0x01};
    static const uint8_t weak_key_even_parity[CRYPTO_DES_KEY_SIZE] = {0};
    static const uint8_t weak_tdes_component[CRYPTO_TDES3_KEY_SIZE] = {
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x23, 0x45, 0x67,
        0x89, 0xab, 0xcd, 0xef, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23};
    static const key_validation_case cases[] = {
        {"DES/weak-key", crypto_des_encrypt, weak_key, sizeof(weak_key), CRYPTO_STATUS_WEAK_KEY},
        {"DES/weak-key-even-parity", crypto_des_encrypt, weak_key_even_parity,
         sizeof(weak_key_even_parity), CRYPTO_STATUS_WEAK_KEY},
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
        {"DES/cbc-null-iv", crypto_des_encrypt, des_key, sizeof(des_key), CRYPTO_CIPHER_MODE_CBC,
         NULL, CRYPTO_DES_BLOCK_SIZE, storage, CRYPTO_DES_BLOCK_SIZE, output,
         CRYPTO_DES_BLOCK_SIZE, CRYPTO_STATUS_NULL_ARGUMENT},
        {"DES/cbc-short-iv", crypto_des_encrypt, des_key, sizeof(des_key),
         CRYPTO_CIPHER_MODE_CBC, zero_block, 1U, storage, CRYPTO_DES_BLOCK_SIZE, output,
         CRYPTO_DES_BLOCK_SIZE, CRYPTO_STATUS_INVALID_LENGTH},
        {"DES/cbc-zero-iv-length", crypto_des_encrypt, des_key, sizeof(des_key),
         CRYPTO_CIPHER_MODE_CBC, zero_block, 0U, storage, CRYPTO_DES_BLOCK_SIZE, output,
         CRYPTO_DES_BLOCK_SIZE, CRYPTO_STATUS_INVALID_LENGTH},
        {"DES/cbc-empty-input", crypto_des_encrypt, des_key, sizeof(des_key),
         CRYPTO_CIPHER_MODE_CBC, zero_block, CRYPTO_DES_BLOCK_SIZE, storage, 0U, output, 0U,
         CRYPTO_STATUS_OK},
        {"DES/cbc-same-buffer", crypto_des_encrypt, des_key, sizeof(des_key),
         CRYPTO_CIPHER_MODE_CBC, zero_block, CRYPTO_DES_BLOCK_SIZE, storage,
         CRYPTO_DES_BLOCK_SIZE, storage, CRYPTO_DES_BLOCK_SIZE,
         CRYPTO_STATUS_OVERLAPPING_BUFFERS},
        {"DES/cbc-forward-overlap", crypto_des_encrypt, des_key, sizeof(des_key),
         CRYPTO_CIPHER_MODE_CBC, zero_block, CRYPTO_DES_BLOCK_SIZE, storage,
         CRYPTO_DES_BLOCK_SIZE, storage + 1U, CRYPTO_DES_BLOCK_SIZE,
         CRYPTO_STATUS_OVERLAPPING_BUFFERS},
        {"DES/cfb64-null-iv", crypto_des_encrypt, des_key, sizeof(des_key),
         CRYPTO_CIPHER_MODE_CFB64, NULL, CRYPTO_DES_BLOCK_SIZE, storage, CRYPTO_DES_BLOCK_SIZE,
         output, CRYPTO_DES_BLOCK_SIZE, CRYPTO_STATUS_NULL_ARGUMENT},
        {"DES/cfb64-short-iv", crypto_des_encrypt, des_key, sizeof(des_key),
         CRYPTO_CIPHER_MODE_CFB64, zero_block, 1U, storage, CRYPTO_DES_BLOCK_SIZE, output,
         CRYPTO_DES_BLOCK_SIZE, CRYPTO_STATUS_INVALID_LENGTH},
        {"DES/cfb64-zero-iv-length", crypto_des_encrypt, des_key, sizeof(des_key),
         CRYPTO_CIPHER_MODE_CFB64, zero_block, 0U, storage, CRYPTO_DES_BLOCK_SIZE, output,
         CRYPTO_DES_BLOCK_SIZE, CRYPTO_STATUS_INVALID_LENGTH},
        {"DES/cfb64-empty-input", crypto_des_encrypt, des_key, sizeof(des_key),
         CRYPTO_CIPHER_MODE_CFB64, zero_block, CRYPTO_DES_BLOCK_SIZE, storage, 0U, output, 0U,
         CRYPTO_STATUS_OK},
        {"DES/cfb64-same-buffer", crypto_des_encrypt, des_key, sizeof(des_key),
         CRYPTO_CIPHER_MODE_CFB64, zero_block, CRYPTO_DES_BLOCK_SIZE, storage,
         CRYPTO_DES_BLOCK_SIZE, storage, CRYPTO_DES_BLOCK_SIZE,
         CRYPTO_STATUS_OVERLAPPING_BUFFERS},
        {"DES/cfb64-forward-overlap", crypto_des_encrypt, des_key, sizeof(des_key),
         CRYPTO_CIPHER_MODE_CFB64, zero_block, CRYPTO_DES_BLOCK_SIZE, storage,
         CRYPTO_DES_BLOCK_SIZE, storage + 1U, CRYPTO_DES_BLOCK_SIZE,
         CRYPTO_STATUS_OVERLAPPING_BUFFERS},
        {"DES/ofb64-null-iv", crypto_des_encrypt, des_key, sizeof(des_key),
         CRYPTO_CIPHER_MODE_OFB64, NULL, CRYPTO_DES_BLOCK_SIZE, storage, CRYPTO_DES_BLOCK_SIZE,
         output, CRYPTO_DES_BLOCK_SIZE, CRYPTO_STATUS_NULL_ARGUMENT},
        {"DES/ofb64-short-iv", crypto_des_encrypt, des_key, sizeof(des_key),
         CRYPTO_CIPHER_MODE_OFB64, zero_block, 1U, storage, CRYPTO_DES_BLOCK_SIZE, output,
         CRYPTO_DES_BLOCK_SIZE, CRYPTO_STATUS_INVALID_LENGTH},
        {"DES/ofb64-zero-iv-length", crypto_des_encrypt, des_key, sizeof(des_key),
         CRYPTO_CIPHER_MODE_OFB64, zero_block, 0U, storage, CRYPTO_DES_BLOCK_SIZE, output,
         CRYPTO_DES_BLOCK_SIZE, CRYPTO_STATUS_INVALID_LENGTH},
        {"DES/ofb64-empty-input", crypto_des_encrypt, des_key, sizeof(des_key),
         CRYPTO_CIPHER_MODE_OFB64, zero_block, CRYPTO_DES_BLOCK_SIZE, storage, 0U, output, 0U,
         CRYPTO_STATUS_OK},
        {"DES/ofb64-same-buffer", crypto_des_encrypt, des_key, sizeof(des_key),
         CRYPTO_CIPHER_MODE_OFB64, zero_block, CRYPTO_DES_BLOCK_SIZE, storage,
         CRYPTO_DES_BLOCK_SIZE, storage, CRYPTO_DES_BLOCK_SIZE,
         CRYPTO_STATUS_OVERLAPPING_BUFFERS},
        {"DES/ofb64-forward-overlap", crypto_des_encrypt, des_key, sizeof(des_key),
         CRYPTO_CIPHER_MODE_OFB64, zero_block, CRYPTO_DES_BLOCK_SIZE, storage,
         CRYPTO_DES_BLOCK_SIZE, storage + 1U, CRYPTO_DES_BLOCK_SIZE,
         CRYPTO_STATUS_OVERLAPPING_BUFFERS},
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
         CRYPTO_DES_BLOCK_SIZE, CRYPTO_STATUS_OVERLAPPING_BUFFERS},
        {"TDES/cbc-null-iv", crypto_tdes_encrypt, tdes2_key, sizeof(tdes2_key),
         CRYPTO_CIPHER_MODE_CBC, NULL, CRYPTO_DES_BLOCK_SIZE, storage, CRYPTO_DES_BLOCK_SIZE,
         output, CRYPTO_DES_BLOCK_SIZE, CRYPTO_STATUS_NULL_ARGUMENT},
        {"TDES/cbc-short-iv", crypto_tdes_encrypt, tdes2_key, sizeof(tdes2_key),
         CRYPTO_CIPHER_MODE_CBC, zero_block, 1U, storage, CRYPTO_DES_BLOCK_SIZE, output,
         CRYPTO_DES_BLOCK_SIZE, CRYPTO_STATUS_INVALID_LENGTH},
        {"TDES/cbc-zero-iv-length", crypto_tdes_encrypt, tdes2_key, sizeof(tdes2_key),
         CRYPTO_CIPHER_MODE_CBC, zero_block, 0U, storage, CRYPTO_DES_BLOCK_SIZE, output,
         CRYPTO_DES_BLOCK_SIZE, CRYPTO_STATUS_INVALID_LENGTH},
        {"TDES/cbc-empty-input", crypto_tdes_encrypt, tdes2_key, sizeof(tdes2_key),
         CRYPTO_CIPHER_MODE_CBC, zero_block, CRYPTO_DES_BLOCK_SIZE, storage, 0U, output, 0U,
         CRYPTO_STATUS_OK},
        {"TDES/cbc-same-buffer", crypto_tdes_encrypt, tdes2_key, sizeof(tdes2_key),
         CRYPTO_CIPHER_MODE_CBC, zero_block, CRYPTO_DES_BLOCK_SIZE, storage,
         CRYPTO_DES_BLOCK_SIZE, storage, CRYPTO_DES_BLOCK_SIZE,
         CRYPTO_STATUS_OVERLAPPING_BUFFERS},
        {"TDES/cbc-forward-overlap", crypto_tdes_encrypt, tdes2_key, sizeof(tdes2_key),
         CRYPTO_CIPHER_MODE_CBC, zero_block, CRYPTO_DES_BLOCK_SIZE, storage,
         CRYPTO_DES_BLOCK_SIZE, storage + 1U, CRYPTO_DES_BLOCK_SIZE,
         CRYPTO_STATUS_OVERLAPPING_BUFFERS},
        {"TDES/cfb64-null-iv", crypto_tdes_encrypt, tdes2_key, sizeof(tdes2_key),
         CRYPTO_CIPHER_MODE_CFB64, NULL, CRYPTO_DES_BLOCK_SIZE, storage, CRYPTO_DES_BLOCK_SIZE,
         output, CRYPTO_DES_BLOCK_SIZE, CRYPTO_STATUS_NULL_ARGUMENT},
        {"TDES/cfb64-short-iv", crypto_tdes_encrypt, tdes2_key, sizeof(tdes2_key),
         CRYPTO_CIPHER_MODE_CFB64, zero_block, 1U, storage, CRYPTO_DES_BLOCK_SIZE, output,
         CRYPTO_DES_BLOCK_SIZE, CRYPTO_STATUS_INVALID_LENGTH},
        {"TDES/cfb64-zero-iv-length", crypto_tdes_encrypt, tdes2_key, sizeof(tdes2_key),
         CRYPTO_CIPHER_MODE_CFB64, zero_block, 0U, storage, CRYPTO_DES_BLOCK_SIZE, output,
         CRYPTO_DES_BLOCK_SIZE, CRYPTO_STATUS_INVALID_LENGTH},
        {"TDES/cfb64-empty-input", crypto_tdes_encrypt, tdes2_key, sizeof(tdes2_key),
         CRYPTO_CIPHER_MODE_CFB64, zero_block, CRYPTO_DES_BLOCK_SIZE, storage, 0U, output, 0U,
         CRYPTO_STATUS_OK},
        {"TDES/cfb64-same-buffer", crypto_tdes_encrypt, tdes2_key, sizeof(tdes2_key),
         CRYPTO_CIPHER_MODE_CFB64, zero_block, CRYPTO_DES_BLOCK_SIZE, storage,
         CRYPTO_DES_BLOCK_SIZE, storage, CRYPTO_DES_BLOCK_SIZE,
         CRYPTO_STATUS_OVERLAPPING_BUFFERS},
        {"TDES/cfb64-forward-overlap", crypto_tdes_encrypt, tdes2_key, sizeof(tdes2_key),
         CRYPTO_CIPHER_MODE_CFB64, zero_block, CRYPTO_DES_BLOCK_SIZE, storage,
         CRYPTO_DES_BLOCK_SIZE, storage + 1U, CRYPTO_DES_BLOCK_SIZE,
         CRYPTO_STATUS_OVERLAPPING_BUFFERS},
        {"TDES/ofb64-null-iv", crypto_tdes_encrypt, tdes2_key, sizeof(tdes2_key),
         CRYPTO_CIPHER_MODE_OFB64, NULL, CRYPTO_DES_BLOCK_SIZE, storage, CRYPTO_DES_BLOCK_SIZE,
         output, CRYPTO_DES_BLOCK_SIZE, CRYPTO_STATUS_NULL_ARGUMENT},
        {"TDES/ofb64-short-iv", crypto_tdes_encrypt, tdes2_key, sizeof(tdes2_key),
         CRYPTO_CIPHER_MODE_OFB64, zero_block, 1U, storage, CRYPTO_DES_BLOCK_SIZE, output,
         CRYPTO_DES_BLOCK_SIZE, CRYPTO_STATUS_INVALID_LENGTH},
        {"TDES/ofb64-zero-iv-length", crypto_tdes_encrypt, tdes2_key, sizeof(tdes2_key),
         CRYPTO_CIPHER_MODE_OFB64, zero_block, 0U, storage, CRYPTO_DES_BLOCK_SIZE, output,
         CRYPTO_DES_BLOCK_SIZE, CRYPTO_STATUS_INVALID_LENGTH},
        {"TDES/ofb64-empty-input", crypto_tdes_encrypt, tdes2_key, sizeof(tdes2_key),
         CRYPTO_CIPHER_MODE_OFB64, zero_block, CRYPTO_DES_BLOCK_SIZE, storage, 0U, output, 0U,
         CRYPTO_STATUS_OK},
        {"TDES/ofb64-same-buffer", crypto_tdes_encrypt, tdes2_key, sizeof(tdes2_key),
         CRYPTO_CIPHER_MODE_OFB64, zero_block, CRYPTO_DES_BLOCK_SIZE, storage,
         CRYPTO_DES_BLOCK_SIZE, storage, CRYPTO_DES_BLOCK_SIZE,
         CRYPTO_STATUS_OVERLAPPING_BUFFERS},
        {"TDES/ofb64-forward-overlap", crypto_tdes_encrypt, tdes2_key, sizeof(tdes2_key),
         CRYPTO_CIPHER_MODE_OFB64, zero_block, CRYPTO_DES_BLOCK_SIZE, storage,
         CRYPTO_DES_BLOCK_SIZE, storage + 1U, CRYPTO_DES_BLOCK_SIZE,
         CRYPTO_STATUS_OVERLAPPING_BUFFERS}};
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

/** @brief Verify the generated version constants and public version functions. */
static void test_version(void)
{
    TEST_CHECK(strcmp(crypto_version(), CRYPTOMOON_VERSION) == 0);
    TEST_CHECK(strcmp(crypto_full_version(), CRYPTOMOON_FULL_VERSION) == 0);
    TEST_CHECK(strlen(CRYPTOMOON_GIT_COMMIT_SHORT) > 0U);
    return;
}

TEST_LIST = {{"vectors/known-answer", test_known_answer_vectors},
             {"ecb/multiple-blocks", test_multiple_blocks},
             {"cbc/known-answer", test_cbc_known_answer_vectors},
             {"cbc/zero-iv-equals-ecb", test_cbc_zero_iv_equals_ecb},
             {"cfb64/known-answer", test_cfb64_known_answer_vectors},
             {"cfb64/first-block-identity", test_cfb64_first_block_identity},
             {"cfb64/parity-ignored", test_cfb64_parity_ignored},
             {"ofb64/known-answer", test_ofb64_known_answer_vectors},
             {"ofb64/first-block-identity", test_ofb64_first_block_identity},
             {"ofb64/parity-ignored", test_ofb64_parity_ignored},
             {"keys/parity-ignored", test_parity_ignored},
             {"keys/cbc-parity-ignored", test_cbc_parity_ignored},
             {"keys/degenerate-compatible", test_degenerate_tdes_keys},
             {"keys/validation", test_key_validation},
             {"api/contract", test_public_contract},
             {"status/strings", test_status_strings},
             {"version/generated", test_version},
             {NULL, NULL}};
