enable_testing()

set(MODES ECB CBC CFB OFB CTR)
set(ALGOS vigenere aes)

foreach(ALG IN LISTS ALGOS)
  foreach(M IN LISTS MODES)
    set(cfg "${CMAKE_BINARY_DIR}/config_${ALG}_${M}.json")
    file(WRITE ${cfg} "{
  \"algorithm\": \"${ALG}\",
  \"block_size_bits\": ${ALG STREQUAL \"vigenere\" ? 8 : 128},
  \"mode\": \"${M}\",
  \"padding\": \"zero\",
  \"encrypt\": true,
  \"key\": \"MYSECRETKEY\",
  \"iv_hex\": \"000102030405060708090A0B0C0D0E0F\",
  \"input_file\": \"${CMAKE_BINARY_DIR}/input.bin\",
  \"output_file\": \"${CMAKE_BINARY_DIR}/out_${ALG}_${M}.bin\"
}")
    add_test(NAME ${ALG}_${M}
             COMMAND cipher ${cfg})
  endforeach()
endforeach()
