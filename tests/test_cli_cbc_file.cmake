file(MAKE_DIRECTORY "${TEST_DIRECTORY}")

set(input_file "${TEST_DIRECTORY}/input.bin")
set(key_file "${TEST_DIRECTORY}/key.bin")
set(iv_file "${TEST_DIRECTORY}/iv.bin")
set(encrypted_file "${TEST_DIRECTORY}/encrypted.bin")
set(recovered_file "${TEST_DIRECTORY}/recovered.bin")

file(WRITE "${input_file}" "OpenAI!!OpenAI!!")
file(WRITE "${key_file}" "CEFIJLRQ")
file(WRITE "${iv_file}" "IVIVIVIV")

execute_process(
    COMMAND "${CRYPTOMOON_CLI}" encrypt --algorithm des --mode cbc
        --key-file "${key_file}" --iv-file "${iv_file}"
        --file "${input_file}" --output "${encrypted_file}"
    RESULT_VARIABLE encrypt_result
    ERROR_VARIABLE encrypt_error
)
if(NOT encrypt_result EQUAL 0)
    message(FATAL_ERROR "CBC file encryption failed: ${encrypt_error}")
endif()

execute_process(
    COMMAND "${CRYPTOMOON_CLI}" decrypt --algorithm des --mode cbc
        --key-file "${key_file}" --iv-file "${iv_file}"
        --file "${encrypted_file}" --output "${recovered_file}"
    RESULT_VARIABLE decrypt_result
    ERROR_VARIABLE decrypt_error
)
if(NOT decrypt_result EQUAL 0)
    message(FATAL_ERROR "CBC file decryption failed: ${decrypt_error}")
endif()

file(READ "${input_file}" input_hex HEX)
file(READ "${encrypted_file}" encrypted_hex HEX)
file(READ "${recovered_file}" recovered_hex HEX)

if(input_hex STREQUAL encrypted_hex)
    message(FATAL_ERROR "CBC encryption did not change the input data")
endif()
if(NOT input_hex STREQUAL recovered_hex)
    message(FATAL_ERROR "CBC decrypted file does not match the original input")
endif()