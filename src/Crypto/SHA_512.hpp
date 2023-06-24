#include <vector>
#include <iostream>
#include <stdexcept>

#include <openssl/evp.h>

class SHA_512 {
public:
    SHA_512() {}
    SHA_512(const SHA_512&) = delete;
    ~SHA_512() {}

    static void generate(const unsigned char* input_buffer, size_t input_buffer_size, std::vector<uint8_t>& digest, unsigned int& digest_size);
    static bool verify(const unsigned char* input_buffer, size_t input_buffer_size, const unsigned char* input_digest);
};
