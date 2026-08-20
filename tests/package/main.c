#include <crypto/des.h>

#include <string.h>

int main(void)
{
    static const uint8_t key[CRYPTO_DES_KEY_SIZE] = {0x13, 0x34, 0x57, 0x79,
                                                     0x9b, 0xbc, 0xdf, 0xf1};
    static const uint8_t plaintext[CRYPTO_DES_BLOCK_SIZE] = {0x01, 0x23, 0x45, 0x67,
                                                             0x89, 0xab, 0xcd, 0xef};
    static const uint8_t expected[CRYPTO_DES_BLOCK_SIZE] = {0x85, 0xe8, 0x13, 0x54,
                                                            0x0f, 0x0a, 0xb4, 0x05};
    uint8_t output[CRYPTO_DES_BLOCK_SIZE];
    crypto_status status;
    int result = 1;

    status = crypto_des_encrypt(key, sizeof(key), CRYPTO_CIPHER_MODE_ECB, NULL, 0U, plaintext,
                                sizeof(plaintext), output, sizeof(output));
    if ((status == CRYPTO_STATUS_OK) && (memcmp(output, expected, sizeof(output)) == 0))
    {
        result = 0;
    }
    return result;
}
