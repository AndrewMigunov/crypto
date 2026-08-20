#include <acutest.h>

#include <tdes_internal.h>

#include <stddef.h>
#include <stdint.h>

/** @brief Fully specified internal TDES key-validation case. */
typedef struct tdes_validation_case
{
    const char *name;       /**< Name shown by the test runner. */
    const uint8_t *key;     /**< Encoded key bundle under test. */
    size_t key_length;      /**< Encoded key length. */
    crypto_status expected; /**< Expected validation status. */
} tdes_validation_case;

/** @brief Exercise private TDES component-distinctness validation. */
static void test_tdes_key_validate_distinct(void)
{
    static const uint8_t distinct_key2[CRYPTO_TDES2_KEY_SIZE] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                                                                 0xcd, 0xef, 0x23, 0x45, 0x67, 0x89,
                                                                 0xab, 0xcd, 0xef, 0x01};
    static const uint8_t distinct_key3[CRYPTO_TDES3_KEY_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x23, 0x45, 0x67, 0x89,
        0xab, 0xcd, 0xef, 0x01, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23};
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
    static const tdes_validation_case cases[] = {
        {"null-key", NULL, CRYPTO_TDES2_KEY_SIZE, CRYPTO_STATUS_NULL_ARGUMENT},
        {"invalid-length", distinct_key2, CRYPTO_TDES2_KEY_SIZE - 1U, CRYPTO_STATUS_INVALID_LENGTH},
        {"distinct-2TDES", distinct_key2, sizeof(distinct_key2), CRYPTO_STATUS_OK},
        {"distinct-3TDES", distinct_key3, sizeof(distinct_key3), CRYPTO_STATUS_OK},
        {"2TDES/K1-equals-K2", repeated_key2, sizeof(repeated_key2), CRYPTO_STATUS_DEGENERATE_KEY},
        {"3TDES/K1-equals-K2", repeated_first_key3, sizeof(repeated_first_key3),
         CRYPTO_STATUS_DEGENERATE_KEY},
        {"3TDES/K2-equals-K3", repeated_last_key3, sizeof(repeated_last_key3),
         CRYPTO_STATUS_DEGENERATE_KEY},
        {"3TDES/K1-equals-K3", repeated_outer_key3, sizeof(repeated_outer_key3),
         CRYPTO_STATUS_DEGENERATE_KEY}};
    const tdes_validation_case *test_case;
    crypto_status status;
    size_t index;

    for (index = 0U; index < (sizeof(cases) / sizeof(cases[0])); ++index)
    {
        test_case = &cases[index];
        TEST_CASE(test_case->name);
        status = crypto_tdes_key_validate_distinct(test_case->key, test_case->key_length);
        TEST_CHECK_(status == test_case->expected, "expected %s, got %s",
                    crypto_status_string(test_case->expected), crypto_status_string(status));
    }
    return;
}

TEST_LIST = {{"keys/distinct-components", test_tdes_key_validate_distinct}, {NULL, NULL}};
