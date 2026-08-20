#include <crypto/status.h>

const char *crypto_status_string(crypto_status status)
{
    const char *result;

    switch (status)
    {
    case CRYPTO_STATUS_OK:
        result = "success";
        break;
    case CRYPTO_STATUS_NULL_ARGUMENT:
        result = "null argument";
        break;
    case CRYPTO_STATUS_INVALID_KEY_PARITY:
        result = "invalid DES key parity";
        break;
    case CRYPTO_STATUS_WEAK_KEY:
        result = "weak DES key";
        break;
    case CRYPTO_STATUS_DEGENERATE_KEY:
        result = "degenerate TDES key";
        break;
    case CRYPTO_STATUS_INVALID_CONTEXT:
        result = "invalid or uninitialized context";
        break;
    case CRYPTO_STATUS_OVERLAPPING_BUFFERS:
        result = "overlapping input and output buffers";
        break;
    case CRYPTO_STATUS_INVALID_LENGTH:
        result = "invalid buffer length";
        break;
    case CRYPTO_STATUS_INVALID_MODE:
        result = "invalid or unsupported cipher mode";
        break;
    default:
        result = "unknown status";
        break;
    }

    return result;
}
