#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <openssl/rand.h>

#include "../Security/AES_CBC.hpp"
#include "../Security/HMAC.hpp"

// ---------------------------------- SESSION MESSAGE ----------------------------------

struct SessionMessage {

    std::vector<uint8_t> iv;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> hmac;

    SessionMessage() {}
    SessionMessage(int ciphertext_size);
    SessionMessage(const std::vector<uint8_t>& session_key, const std::vector<uint8_t>& hmac_key, const std::vector<uint8_t>& plaintext);
    ~SessionMessage();
    bool verify_HMAC(const unsigned char* key);
    uint16_t decrypt(const std::vector<uint8_t>& key, std::vector<unsigned char>& plaintext);
    std::vector<uint8_t> serialize() const;
    static SessionMessage deserialize(const std::vector<uint8_t>& buffer, const int ciphertext_size);
    static int get_size(int plaintext_size);
    void print() const;
};