#include <des.h>
#include <status.h>
#include <tdes.h>
#include <version.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/** @brief Successful command completion. */
#define CLI_EXIT_OK 0
/** @brief Invalid command-line input. */
#define CLI_EXIT_USAGE 2
/** @brief File or stream operation failure. */
#define CLI_EXIT_IO 3
/** @brief Cryptographic operation failure. */
#define CLI_EXIT_CRYPTO 4

/** @brief Supported command operation. */
typedef enum cli_operation
{
    CLI_OPERATION_NONE = 0,
    CLI_OPERATION_ENCRYPT,
    CLI_OPERATION_DECRYPT
} cli_operation;

/** @brief Supported command algorithm. */
typedef enum cli_algorithm
{
    CLI_ALGORITHM_NONE = 0,
    CLI_ALGORITHM_DES,
    CLI_ALGORITHM_TDES2,
    CLI_ALGORITHM_TDES3
} cli_algorithm;

/** @brief Parsed command-line configuration. */
typedef struct cli_config
{
    cli_operation operation;
    cli_algorithm algorithm;
    const char *key_hex;
    const char *key_path;
    const char *input_hex;
    const char *input_path;
    const char *output_path;
} cli_config;

/** @brief Erase bounded sensitive storage through volatile writes. */
static void cli_secure_zero(void *memory, size_t size)
{
    volatile uint8_t *bytes = (volatile uint8_t *)memory;
    size_t index;

    for (index = 0U; index < size; ++index)
    {
        bytes[index] = 0U;
    }
    return;
}

/** @brief Print command usage to the selected stream. */
static void cli_print_usage(FILE *stream)
{
    (void)fprintf(stream,
                  "Usage:\n"
                  "  cryptomoon-cli --help\n"
                  "  cryptomoon-cli --version\n"
                  "  cryptomoon-cli <encrypt|decrypt> --algorithm <des|2tdes|3tdes>\n"
                  "      (--key <hex> | --key-file <path>)\n"
                  "      (--input <hex> | --file <path>) [--output <path>]\n"
                  "\n"
                  "Without --output, the result is written as lowercase hex to stdout.\n"
                  "With --output, the result is written as raw bytes to the selected file.\n"
                  "Input must contain complete 8-byte blocks; no padding is applied.\n"
                  "\n"
                  "Warning: DES, TDES, and ECB are obsolete and are provided only for\n"
                  "education and legacy interoperability.\n");
    return;
}

/** @brief Print the complete build version. */
static int cli_print_version(void)
{
    int result = CLI_EXIT_OK;

    if (printf("cryptomoon-cli %s\n", crypto_full_version()) < 0)
    {
        result = CLI_EXIT_IO;
    }
    return result;
}

/** @brief Parse the operation name. */
static cli_operation cli_parse_operation(const char *text)
{
    cli_operation operation = CLI_OPERATION_NONE;

    if (strcmp(text, "encrypt") == 0)
    {
        operation = CLI_OPERATION_ENCRYPT;
    }
    else if (strcmp(text, "decrypt") == 0)
    {
        operation = CLI_OPERATION_DECRYPT;
    }
    return operation;
}

/** @brief Parse the algorithm name. */
static cli_algorithm cli_parse_algorithm(const char *text)
{
    cli_algorithm algorithm = CLI_ALGORITHM_NONE;

    if (strcmp(text, "des") == 0)
    {
        algorithm = CLI_ALGORITHM_DES;
    }
    else if (strcmp(text, "2tdes") == 0)
    {
        algorithm = CLI_ALGORITHM_TDES2;
    }
    else if (strcmp(text, "3tdes") == 0)
    {
        algorithm = CLI_ALGORITHM_TDES3;
    }
    return algorithm;
}

/** @brief Store one option value while rejecting duplicate options. */
static int cli_set_option(const char **destination, const char *value)
{
    int result = CLI_EXIT_OK;

    if (*destination != NULL)
    {
        result = CLI_EXIT_USAGE;
    }
    else
    {
        *destination = value;
    }
    return result;
}

/** @brief Parse and validate all command-line arguments. */
static int cli_parse_arguments(int argc, char *argv[], cli_config *config)
{
    int argument_index = 2;
    int result = CLI_EXIT_OK;

    (void)memset(config, 0, sizeof(*config));
    if (argc < 2)
    {
        result = CLI_EXIT_USAGE;
    }
    else
    {
        config->operation = cli_parse_operation(argv[1]);
        if (config->operation == CLI_OPERATION_NONE)
        {
            result = CLI_EXIT_USAGE;
        }
    }
    while ((result == CLI_EXIT_OK) && (argument_index < argc))
    {
        const char *option = argv[argument_index];

        if ((argument_index + 1) >= argc)
        {
            result = CLI_EXIT_USAGE;
        }
        else if (strcmp(option, "--algorithm") == 0)
        {
            if (config->algorithm != CLI_ALGORITHM_NONE)
            {
                result = CLI_EXIT_USAGE;
            }
            else
            {
                config->algorithm = cli_parse_algorithm(argv[argument_index + 1]);
                if (config->algorithm == CLI_ALGORITHM_NONE)
                {
                    result = CLI_EXIT_USAGE;
                }
            }
        }
        else if (strcmp(option, "--key") == 0)
        {
            result = cli_set_option(&config->key_hex, argv[argument_index + 1]);
        }
        else if (strcmp(option, "--key-file") == 0)
        {
            result = cli_set_option(&config->key_path, argv[argument_index + 1]);
        }
        else if (strcmp(option, "--input") == 0)
        {
            result = cli_set_option(&config->input_hex, argv[argument_index + 1]);
        }
        else if (strcmp(option, "--file") == 0)
        {
            result = cli_set_option(&config->input_path, argv[argument_index + 1]);
        }
        else if (strcmp(option, "--output") == 0)
        {
            result = cli_set_option(&config->output_path, argv[argument_index + 1]);
        }
        else
        {
            result = CLI_EXIT_USAGE;
        }
        argument_index += 2;
    }
    if ((result == CLI_EXIT_OK) && (((config->key_hex == NULL) && (config->key_path == NULL)) ||
                                    ((config->key_hex != NULL) && (config->key_path != NULL)) ||
                                    ((config->input_hex == NULL) && (config->input_path == NULL)) ||
                                    ((config->input_hex != NULL) && (config->input_path != NULL)) ||
                                    (config->algorithm == CLI_ALGORITHM_NONE)))
    {
        result = CLI_EXIT_USAGE;
    }
    if ((result == CLI_EXIT_OK) && (config->output_path != NULL) &&
        (((config->input_path != NULL) && (strcmp(config->output_path, config->input_path) == 0)) ||
         ((config->key_path != NULL) && (strcmp(config->output_path, config->key_path) == 0))))
    {
        (void)fprintf(stderr, "cryptomoon-cli: output must not overwrite an input or key file\n");
        result = CLI_EXIT_USAGE;
    }
    return result;
}

/** @brief Return the required encoded key size for an algorithm. */
static size_t cli_key_size(cli_algorithm algorithm)
{
    size_t key_size = CRYPTO_DES_KEY_SIZE;

    if (algorithm == CLI_ALGORITHM_TDES2)
    {
        key_size = CRYPTO_TDES2_KEY_SIZE;
    }
    else if (algorithm == CLI_ALGORITHM_TDES3)
    {
        key_size = CRYPTO_TDES3_KEY_SIZE;
    }
    return key_size;
}

/** @brief Decode one hexadecimal character. */
static int cli_decode_nibble(char character, uint8_t *value)
{
    int result = CLI_EXIT_OK;

    if ((character >= '0') && (character <= '9'))
    {
        *value = (uint8_t)(character - '0');
    }
    else if ((character >= 'a') && (character <= 'f'))
    {
        *value = (uint8_t)(character - 'a' + 10);
    }
    else if ((character >= 'A') && (character <= 'F'))
    {
        *value = (uint8_t)(character - 'A' + 10);
    }
    else
    {
        result = CLI_EXIT_USAGE;
    }
    return result;
}

/** @brief Decode an exact number of hexadecimal bytes. */
static int cli_decode_hex(const char *text, size_t byte_count, uint8_t *bytes)
{
    size_t byte_index;
    int result = CLI_EXIT_OK;

    for (byte_index = 0U; (byte_index < byte_count) && (result == CLI_EXIT_OK); ++byte_index)
    {
        uint8_t high = 0U;
        uint8_t low = 0U;

        result = cli_decode_nibble(text[2U * byte_index], &high);
        if (result == CLI_EXIT_OK)
        {
            result = cli_decode_nibble(text[(2U * byte_index) + 1U], &low);
        }
        bytes[byte_index] = (uint8_t)((uint8_t)(high << 4U) | low);
    }
    return result;
}

/** @brief Load a fixed-size key from hex or a raw key file. */
static int cli_load_key(const cli_config *config, uint8_t *key, size_t key_size)
{
    int result = CLI_EXIT_OK;

    if (config->key_hex != NULL)
    {
        if (strlen(config->key_hex) != (2U * key_size))
        {
            result = CLI_EXIT_USAGE;
        }
        else
        {
            result = cli_decode_hex(config->key_hex, key_size, key);
        }
    }
    else
    {
        FILE *key_file = fopen(config->key_path, "rb");

        if (key_file == NULL)
        {
            (void)fprintf(stderr, "cryptomoon-cli: cannot open key file '%s'\n", config->key_path);
            result = CLI_EXIT_IO;
        }
        else
        {
            size_t bytes_read = fread(key, 1U, key_size, key_file);
            int extra_byte = fgetc(key_file);

            if (ferror(key_file) != 0)
            {
                (void)fprintf(stderr, "cryptomoon-cli: cannot read key file '%s'\n",
                              config->key_path);
                result = CLI_EXIT_IO;
            }
            else if ((bytes_read != key_size) || (extra_byte != EOF))
            {
                result = CLI_EXIT_USAGE;
            }
            if ((fclose(key_file) != 0) && (result == CLI_EXIT_OK))
            {
                (void)fprintf(stderr, "cryptomoon-cli: cannot close key file '%s'\n",
                              config->key_path);
                result = CLI_EXIT_IO;
            }
        }
    }
    if (result == CLI_EXIT_USAGE)
    {
        (void)fprintf(stderr, "cryptomoon-cli: key has an invalid encoding or length\n");
    }
    return result;
}

/** @brief Apply the selected library operation to one block. */
static crypto_status cli_transform_block(const cli_config *config, const uint8_t *key,
                                         size_t key_size, const uint8_t *input, uint8_t *output)
{
    crypto_status status;

    if (config->algorithm == CLI_ALGORITHM_DES)
    {
        if (config->operation == CLI_OPERATION_ENCRYPT)
        {
            status = crypto_des_encrypt(key, key_size, CRYPTO_CIPHER_MODE_ECB, NULL, 0U, input,
                                        CRYPTO_DES_BLOCK_SIZE, output, CRYPTO_DES_BLOCK_SIZE);
        }
        else
        {
            status = crypto_des_decrypt(key, key_size, CRYPTO_CIPHER_MODE_ECB, NULL, 0U, input,
                                        CRYPTO_DES_BLOCK_SIZE, output, CRYPTO_DES_BLOCK_SIZE);
        }
    }
    else if (config->operation == CLI_OPERATION_ENCRYPT)
    {
        status = crypto_tdes_encrypt(key, key_size, CRYPTO_CIPHER_MODE_ECB, NULL, 0U, input,
                                     CRYPTO_DES_BLOCK_SIZE, output, CRYPTO_DES_BLOCK_SIZE);
    }
    else
    {
        status = crypto_tdes_decrypt(key, key_size, CRYPTO_CIPHER_MODE_ECB, NULL, 0U, input,
                                     CRYPTO_DES_BLOCK_SIZE, output, CRYPTO_DES_BLOCK_SIZE);
    }
    return status;
}

/** @brief Write one transformed block as raw bytes or hexadecimal text. */
static int cli_write_block(FILE *output_file, const uint8_t *block)
{
    size_t byte_index;
    int result = CLI_EXIT_OK;

    if (output_file != NULL)
    {
        if (fwrite(block, 1U, CRYPTO_DES_BLOCK_SIZE, output_file) != CRYPTO_DES_BLOCK_SIZE)
        {
            (void)fprintf(stderr, "cryptomoon-cli: cannot write output file\n");
            result = CLI_EXIT_IO;
        }
    }
    else
    {
        for (byte_index = 0U; byte_index < CRYPTO_DES_BLOCK_SIZE; ++byte_index)
        {
            if (printf("%02x", (unsigned int)block[byte_index]) < 0)
            {
                result = CLI_EXIT_IO;
            }
        }
    }
    return result;
}

/** @brief Transform and write a single complete block. */
static int cli_process_block(const cli_config *config, const uint8_t *key, size_t key_size,
                             const uint8_t *input, FILE *output_file)
{
    uint8_t output[CRYPTO_DES_BLOCK_SIZE];
    crypto_status status;
    int result;

    status = cli_transform_block(config, key, key_size, input, output);
    if (status != CRYPTO_STATUS_OK)
    {
        (void)fprintf(stderr, "cryptomoon-cli: cryptographic operation failed: %s\n",
                      crypto_status_string(status));
        result = CLI_EXIT_CRYPTO;
    }
    else
    {
        result = cli_write_block(output_file, output);
    }
    cli_secure_zero(output, sizeof(output));
    return result;
}

/** @brief Process hexadecimal command-line input block by block. */
static int cli_process_hex_input(const cli_config *config, const uint8_t *key, size_t key_size,
                                 FILE *output_file)
{
    size_t text_length = strlen(config->input_hex);
    size_t text_offset;
    int result = CLI_EXIT_OK;

    if ((text_length % (2U * CRYPTO_DES_BLOCK_SIZE)) != 0U)
    {
        (void)fprintf(stderr, "cryptomoon-cli: hex input must contain complete 8-byte blocks\n");
        result = CLI_EXIT_USAGE;
    }
    for (text_offset = 0U; (text_offset < text_length) && (result == CLI_EXIT_OK);
         text_offset += (2U * CRYPTO_DES_BLOCK_SIZE))
    {
        uint8_t input[CRYPTO_DES_BLOCK_SIZE];

        result = cli_decode_hex(config->input_hex + text_offset, CRYPTO_DES_BLOCK_SIZE, input);
        if (result == CLI_EXIT_OK)
        {
            result = cli_process_block(config, key, key_size, input, output_file);
        }
        else
        {
            (void)fprintf(stderr, "cryptomoon-cli: input is not valid hexadecimal data\n");
        }
        cli_secure_zero(input, sizeof(input));
    }
    return result;
}

/** @brief Process a raw input file block by block. */
static int cli_process_file_input(const cli_config *config, const uint8_t *key, size_t key_size,
                                  FILE *output_file)
{
    FILE *input_file = fopen(config->input_path, "rb");
    int result = CLI_EXIT_OK;
    int finished = 0;

    if (input_file == NULL)
    {
        (void)fprintf(stderr, "cryptomoon-cli: cannot open input file '%s'\n", config->input_path);
        result = CLI_EXIT_IO;
    }
    while ((result == CLI_EXIT_OK) && (finished == 0))
    {
        uint8_t input[CRYPTO_DES_BLOCK_SIZE];
        size_t bytes_read = fread(input, 1U, sizeof(input), input_file);

        if (bytes_read == sizeof(input))
        {
            result = cli_process_block(config, key, key_size, input, output_file);
        }
        else if (ferror(input_file) != 0)
        {
            (void)fprintf(stderr, "cryptomoon-cli: cannot read input file '%s'\n",
                          config->input_path);
            result = CLI_EXIT_IO;
        }
        else if (bytes_read != 0U)
        {
            (void)fprintf(stderr,
                          "cryptomoon-cli: input file must contain complete 8-byte blocks\n");
            result = CLI_EXIT_USAGE;
        }
        else
        {
            finished = 1;
        }
        cli_secure_zero(input, sizeof(input));
    }
    if ((input_file != NULL) && (fclose(input_file) != 0) && (result == CLI_EXIT_OK))
    {
        (void)fprintf(stderr, "cryptomoon-cli: cannot close input file '%s'\n", config->input_path);
        result = CLI_EXIT_IO;
    }
    return result;
}

/** @brief Execute a validated CLI configuration. */
static int cli_execute(const cli_config *config)
{
    uint8_t key[CRYPTO_TDES3_KEY_SIZE];
    size_t key_size = cli_key_size(config->algorithm);
    FILE *output_file = NULL;
    int result;

    cli_secure_zero(key, sizeof(key));
    result = cli_load_key(config, key, key_size);
    if ((result == CLI_EXIT_OK) && (config->output_path != NULL))
    {
        output_file = fopen(config->output_path, "wb");
        if (output_file == NULL)
        {
            (void)fprintf(stderr, "cryptomoon-cli: cannot open output file '%s'\n",
                          config->output_path);
            result = CLI_EXIT_IO;
        }
    }
    if ((result == CLI_EXIT_OK) && (config->input_hex != NULL))
    {
        result = cli_process_hex_input(config, key, key_size, output_file);
    }
    else if (result == CLI_EXIT_OK)
    {
        result = cli_process_file_input(config, key, key_size, output_file);
    }
    if ((output_file != NULL) && (fclose(output_file) != 0) && (result == CLI_EXIT_OK))
    {
        (void)fprintf(stderr, "cryptomoon-cli: cannot close output file '%s'\n",
                      config->output_path);
        result = CLI_EXIT_IO;
    }
    if ((output_file == NULL) && (result == CLI_EXIT_OK) && (putchar('\n') == EOF))
    {
        result = CLI_EXIT_IO;
    }
    cli_secure_zero(key, sizeof(key));
    return result;
}

/** @brief Parse and execute the command-line application. */
static int cli_run(int argc, char *argv[])
{
    cli_config config;
    int result;

    if ((argc == 2) && (strcmp(argv[1], "--help") == 0))
    {
        cli_print_usage(stdout);
        result = CLI_EXIT_OK;
    }
    else if ((argc == 2) && (strcmp(argv[1], "--version") == 0))
    {
        result = cli_print_version();
    }
    else
    {
        result = cli_parse_arguments(argc, argv, &config);
        if (result == CLI_EXIT_OK)
        {
            result = cli_execute(&config);
        }
        else
        {
            cli_print_usage(stderr);
        }
    }
    return result;
}

/** @brief Program entry point. */
int main(int argc, char *argv[])
{
    return cli_run(argc, argv);
}
