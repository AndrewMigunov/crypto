#include <crypto/status.h>

#include <string.h>

int main(void)
{
    int result;

    result = (strcmp(crypto_status_string(CRYPTO_STATUS_OK), "success") == 0) ? 0 : 1;
    return result;
}
