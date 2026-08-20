#ifndef CRYPTO_TDES_INTERNAL_H
#define CRYPTO_TDES_INTERNAL_H

/**
 * @file tdes_internal.h
 * @brief Private Triple DES key-validation operations.
 */

#include <stddef.h>
#include <stdint.h>

#include <status.h>
#include <tdes.h>

/**
 * @brief Validate that all encoded TDES components have distinct effective keys.
 * @param key Pointer to the encoded TDES key bundle.
 * @param key_length Encoded key length.
 * @return CRYPTO_STATUS_OK when all components are distinct or a validation error.
 */
crypto_status crypto_tdes_key_validate_distinct(const uint8_t *key, size_t key_length);

#endif
