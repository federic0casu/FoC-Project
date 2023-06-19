#include <openssl/evp.h>
#include <stdexcept>

class SHA_512 {
public:
    SHA_512() {}
    SHA_512(const SHA_512&) = delete;
    ~SHA_512() {}

    static void generate(const unsigned char* input_buffer, size_t input_buffer_size, unsigned char*& digest, unsigned int& digest_size);
    static bool verify(const unsigned char* input_buffer, size_t input_buffer_size, const unsigned char* input_digest);
};
