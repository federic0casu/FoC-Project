#include "../Crypto/HMAC.hpp"
#include "../Crypto/AES_CBC.hpp"

#include "../Generic/Utility.hpp"

#include "SessionMessage.hpp"

SessionMessage::SessionMessage(int ciphertext_size)
{
    iv.resize(EVP_CIPHER_iv_length(EVP_aes_256_cbc()));
    ciphertext.resize(ciphertext_size);
    hmac.resize(HMAC_DIGEST_SIZE);
}

SessionMessage::SessionMessage(const std::vector<uint8_t>& session_key, const std::vector<uint8_t>& hmac_key, const std::vector<uint8_t>& plaintext) 
{
    iv.resize(EVP_CIPHER_iv_length(EVP_aes_256_cbc()));
    // generate the ciphertext
    AES_CBC encryptor(ENCRYPT, session_key);
    encryptor.run(plaintext, ciphertext, iv);

    // concatenate IV and ciphertext
    std::vector<uint8_t> buffer(iv.size() + ciphertext.size());
    std::copy(iv.begin(), iv.end(), buffer.begin());
    std::copy(ciphertext.begin(), ciphertext.end(), buffer.begin() + iv.size());

    // generate the HMAC
    HMac hmac(hmac_key.data());
    std::vector<uint8_t> digest;
    unsigned int digest_size = 0;
    hmac.generate(buffer.data(), iv.size() + ciphertext.size(), digest, digest_size);
    this->hmac.resize(digest_size);
    std::copy(digest.begin(), digest.end(), this->hmac.begin());

    std::memset(reinterpret_cast<void*>(buffer.data()), 0, buffer.size() * sizeof(uint8_t));
    buffer.clear();

    std::memset(reinterpret_cast<void*>(digest.data()), 0, digest.size() * sizeof(uint8_t));
    digest.clear();
}

SessionMessage::~SessionMessage() 
{
    std::memset(reinterpret_cast<void*>(iv.data()), 0, iv.size() * sizeof(uint8_t));
    iv.clear();

    std::memset(reinterpret_cast<void*>(ciphertext.data()), 0, ciphertext.size() * sizeof(uint8_t));
    ciphertext.clear();

    std::memset(reinterpret_cast<void*>(hmac.data()), 0, hmac.size() * sizeof(uint8_t));
    hmac.clear();
}

bool SessionMessage::verify_HMAC(const unsigned char* key) 
{    
    // concatenate IV and ciphertext
    std::vector<uint8_t> buffer((iv.size() + ciphertext.size()) * sizeof(uint8_t));
    std::memcpy(buffer.data(), iv.data(), iv.size() * sizeof(uint8_t));
    std::memcpy(buffer.data() + iv.size(), ciphertext.data(), ciphertext.size() * sizeof(uint8_t));

    // verify the HMAC
    HMac hmac(key);
    bool res = hmac.verify(buffer.data(), (iv.size() + ciphertext.size()) * sizeof(uint8_t), this->hmac);

    return res;
}

uint16_t SessionMessage::decrypt(const std::vector<uint8_t>& key, std::vector<uint8_t>& plaintext) 
{
    // decrypt the ciphertext
    AES_CBC decryptor(DECRYPT, key);
    decryptor.run(ciphertext, plaintext, iv);

    // return the packet type
    uint16_t type;
    std::memcpy(&type, plaintext.data(), sizeof(uint16_t));

    return type;
}

std::vector<uint8_t> SessionMessage::serialize() const
{
    size_t buffer_size = iv.size() + ciphertext.size() + hmac.size();
    std::vector<uint8_t> buffer(buffer_size);

    size_t position = 0;

    // Serialize IV
    std::copy(iv.begin(), iv.end(), buffer.begin() + position);
    position += iv.size();
#ifdef _DEBUG_
    std::cout << "--------------- " << RED_BOLD << "SERIALIZED SESSION MESSAGE" << RESET << " ---------------" << std::endl;
    std::cout << "SERIALIZED IV: ";
    for (long unsigned int i = 0; i < iv.size(); i++) {
        std::cout << std::hex << static_cast<int>(buffer[i]);
    }
    std::cout << std::dec << std::endl;
#endif

    // Serialize ciphertext
    std::copy(ciphertext.begin(), ciphertext.end(), buffer.begin() + position);
#ifdef _DEBUG_
    std::cout << "CIPHERTEXT: ";
    for (long unsigned int i = 0; i < ciphertext.size(); i++) {
        std::cout << std::hex << static_cast<int>(buffer[i + position]);
    }
    std::cout << std::dec << std::endl;
#endif
    position += ciphertext.size();

    // Serialize HMAC
    std::copy(hmac.begin(), hmac.end(), buffer.begin() + position);
#ifdef _DEBUG_
    std::cout << "SERIALIZED HMAC: ";
    for (long unsigned int i = 0; i < hmac.size(); i++) {
        std::cout << std::hex << static_cast<int>(buffer[i + position]);
    }
    std::cout << std::dec << std::endl;
    std::cout << "-----------------------------------------------------------" << std::endl;
#endif

    return buffer;
}

SessionMessage SessionMessage::deserialize(const std::vector<uint8_t>& buffer, const int plaintext_size) 
{
    // calculate the ciphertext size
    int ciphertext_size = plaintext_size + (EVP_CIPHER_iv_length(EVP_aes_256_cbc()) - (plaintext_size % EVP_CIPHER_iv_length(EVP_aes_256_cbc())));
    SessionMessage sessionMessage(ciphertext_size);

    size_t position = 0;

    std::copy(buffer.begin(), buffer.begin() + (EVP_CIPHER_iv_length(EVP_aes_256_cbc()) * sizeof(uint8_t)), sessionMessage.iv.begin());
    position += EVP_CIPHER_iv_length(EVP_aes_256_cbc()) * sizeof(uint8_t);

    std::copy(buffer.begin() + position, buffer.begin() + position + (sessionMessage.ciphertext.size() * sizeof(uint8_t)), sessionMessage.ciphertext.begin());
    position += sessionMessage.ciphertext.size() * sizeof(uint8_t);

    //SessionMessage::remove_garbage(sessionMessage.ciphertext, EVP_CIPHER_block_size(EVP_aes_256_cbc()));

    std::memcpy(sessionMessage.hmac.data(), buffer.data() + position, HMAC_DIGEST_SIZE * sizeof(uint8_t));

    return sessionMessage;
}

int SessionMessage::get_size(int plaintext_size) 
{
    // calculate the ciphertext size
    int block_size = EVP_CIPHER_block_size(EVP_aes_256_cbc());
    int ciphertext_size = (plaintext_size % block_size == 0) ? plaintext_size : (plaintext_size + (block_size - (plaintext_size % block_size)));

    int size = 0;

    size += EVP_CIPHER_iv_length(EVP_aes_256_cbc()) * sizeof(uint8_t);
    size += ciphertext_size * sizeof(uint8_t);
    size += HMAC_DIGEST_SIZE * sizeof(uint8_t);

    return size;
}

void SessionMessage::print() const 
{
    std::cout << "--------------------- " << GREEN_BOLD << "SESSION MESSAGE" << RESET << " ---------------------" << std::endl;
    std::cout << "IV SIZE: " << iv.size() << std::endl;
    std::cout << "IV: ";
    for (long unsigned int i = 0; i < iv.size(); ++i)
        std::cout << std::hex << (int)iv[i];
    std::cout << std::dec << std::endl;
    std::cout << "CIPHERTEXT SIZE: " << ciphertext.size() << std::endl;
    std::cout << "CIPHERTEXT: ";
    for (long unsigned int i = 0; i < ciphertext.size(); ++i)
        std::cout << std::hex << (int)ciphertext[i];
    std::cout << std::dec << std::endl;
    std::cout << "HMAC SIZE: " << hmac.size() << std::endl;
    std::cout << "HMAC: ";
    for (long unsigned int i = 0; i < hmac.size(); ++i)
        std::cout << std::hex << (int)hmac[i];
    std::cout << std::dec << std::endl;
    std::cout << "----------------------------------------------------------" << std::endl;
}