#include <ctime>
#include <string>
#include <vector>
#include <iomanip>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <algorithm>
#include <stdexcept>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evperr.h>
#include <openssl/crypto.h>

#define ENCRYPT         0
#define DECRYPT         1
#define AES_KEY_SIZE    256


class AES_CBC {
public:
    AES_CBC(uint8_t type, const std::vector<uint8_t>& key);
    AES_CBC(uint8_t type, const std::vector<uint8_t>& key, const bool iv);
    AES_CBC(const AES_CBC&) = delete;
    ~AES_CBC();
    void run(const std::vector<uint8_t>& input_buffer, std::vector<uint8_t>& output_buffer, std::vector<uint8_t>& iv);
    static int getIvSize() { return EVP_CIPHER_iv_length(EVP_aes_256_cbc()); }

private:
    uint8_t type;
    std::vector<uint8_t> key;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> plaintext;
    std::vector<uint8_t> ciphertext;
    uint32_t processed_bytes;

    bool iv_type;

    EVP_CIPHER_CTX* ctx;

    // encrypt methods
    void initializeEncrypt();
    void updateEncrypt();
    void finalizeEncrypt();

    // decrypt methods
    void initializeDecrypt();
    void updateDecrypt();
    void finalizeDecrypt();
};
