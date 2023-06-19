#include <vector>
#include <cstring>
#include <openssl/hmac.h>

#define HMAC_DIGEST_SIZE 32

class HMac {

    unsigned char* m_key;

public:
    HMac(const unsigned char* key);
    HMac(const HMac&) = delete;
    ~HMac();

    void generate(unsigned char* input_buffer, size_t input_buffer_size, std::vector<unsigned char>& digest, unsigned int& digest_size);
    bool verify(unsigned char* input_buffer, size_t input_buffer_size, std::vector<unsigned char>& input_digest);
};