file(MAKE_DIRECTORY "${TEST_DIRECTORY}")

set(input_file "${TEST_DIRECTORY}/input.bin")
set(key_file "${TEST_DIRECTORY}/key.bin")
set(encrypted_file "${TEST_DIRECTORY}/encrypted.bin")
set(recovered_file "${TEST_DIRECTORY}/recovered.bin")

file(WRITE "${input_file}" "OpenAI!!OpenAI!!")
file(WRITE "${key_file}" "CEFIJLRQ")

execute_process(
    COMMAND "${CRYPTOMOON_CLI}" encrypt --algorithm des --mode ctr
        --nonce 0000 --iv fffffffffffe
        --key-file "${key_file}"
        --file "${input_file}" --output "${encrypted_file}"
    RESULT_VARIABLE encrypt_result
    ERROR_VARIABLE encrypt_error
)
if(NOT encrypt_result EQUAL 0)
    message(FATAL_ERROR "CTR nonce file encryption failed: ${encrypt_error}")
endif()

execute_process(
    COMMAND "${CRYPTOMOON_CLI}" decrypt --algorithm des --mode ctr
        --nonce 0000 --iv fffffffffffe
        --key-file "${key_file}"
        --file "${encrypted_file}" --output "${recovered_file}"
    RESULT_VARIABLE decrypt_result
    ERROR_VARIABLE decrypt_error
)
if(NOT decrypt_result EQUAL 0)
    message(FATAL_ERROR "CTR nonce file decryption failed: ${decrypt_error}")
endif()

file(READ "${input_file}" input_hex HEX)
file(READ "${encrypted_file}" encrypted_hex HEX)
file(READ "${recovered_file}" recovered_hex HEX)

if(input_hex STREQUAL encrypted_hex)
    message(FATAL_ERROR "CTR nonce encryption did not change the input data")
endif()
string(TOUPPER "${encrypted_hex}" encrypted_upper)
if(NOT encrypted_upper STREQUAL "FA2576340B21BF1DAF8A1CEC1D21626D")
    message(FATAL_ERROR "CTR nonce file ciphertext does not match the expected value: ${encrypted_upper}")
endif()
if(NOT input_hex STREQUAL recovered_hex)
    message(FATAL_ERROR "CTR nonce decrypted file does not match the original input")
endif()
