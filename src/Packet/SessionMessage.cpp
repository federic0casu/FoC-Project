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
    ciphertext.resize(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    
    // generate the ciphertext
    AES_CBC encryptor(ENCRYPT, session_key);
    encryptor.run(plaintext, ciphertext, iv);

    // concatenate IV and ciphertext
    std::vector<uint8_t> buffer((iv.size() + ciphertext.size()) * sizeof(uint8_t));
    std::copy(iv.begin(), iv.end(), buffer.begin());
    std::copy(ciphertext.begin(), ciphertext.end(), buffer.begin() + (AES_BLOCK_SIZE * sizeof(uint8_t)));

    // generate the HMAC
    HMac hmac(hmac_key.data());
    std::vector<uint8_t> digest;
    unsigned int digest_size = 0;
    hmac.generate(buffer.data(), (iv.size() + ciphertext.size()) * sizeof(uint8_t), digest, digest_size);
    this->hmac.resize(digest_size * sizeof(uint8_t));
    std::copy(digest.begin(), digest.end(), this->hmac.begin());

    buffer.clear();
    digest.clear();
}

SessionMessage::~SessionMessage() 
{
    iv.clear();
    ciphertext.clear();
    hmac.clear();
}

bool SessionMessage::verify_HMAC(const unsigned char* key) 
{    
    // concatenate IV and ciphertext
    std::vector<uint8_t> buffer((iv.size() + ciphertext.size()) * sizeof(uint8_t));
    std::memcpy(buffer.data(), iv.data(), AES_BLOCK_SIZE * sizeof(uint8_t));
    std::memcpy(buffer.data() + (AES_BLOCK_SIZE * sizeof(uint8_t)), ciphertext.data(), ciphertext.size() * sizeof(uint8_t));

    // verify the HMAC
    HMac hmac(key);
    bool res = hmac.verify(buffer.data(), (AES_BLOCK_SIZE + ciphertext.size()) * sizeof(uint8_t), this->hmac);

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
    std::copy(iv.begin(), iv.end(), buffer.begin());
    position += (iv.size() * sizeof(uint8_t));

    std::copy(ciphertext.begin(), ciphertext.end(), buffer.begin() + position);
    position += (ciphertext.size() * sizeof(uint8_t));

    std::copy(hmac.begin(), hmac.end(), buffer.begin() + position);

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

    std::memcpy(sessionMessage.hmac.data(), buffer.data() + position, HMAC_DIGEST_SIZE * sizeof(uint8_t));

    return sessionMessage;
}

int SessionMessage::get_size(int plaintext_size) 
{
    // calculate the ciphertext size
    int ciphertext_size = plaintext_size + (EVP_CIPHER_iv_length(EVP_aes_256_cbc()) - (plaintext_size % EVP_CIPHER_iv_length(EVP_aes_256_cbc())));

    int size = 0;

    size += EVP_CIPHER_iv_length(EVP_aes_256_cbc()) * sizeof(uint8_t);
    size += ciphertext_size * sizeof(uint8_t);
    size += HMAC_DIGEST_SIZE * sizeof(uint8_t);

    return size;
}

void SessionMessage::print() const 
{
    std::cout << "--------------------- SESSION MESSAGE ---------------------" << std::endl;
    std::cout << "IV: ";
    for (auto i = 0; i < EVP_CIPHER_iv_length(EVP_aes_256_cbc()); ++i)
        std::cout << std::hex << (int)iv[i];
    std::cout << std::dec << std::endl;
    std::cout << "CIPHERTEXT: ";
    for (long unsigned int i = 0; i < ciphertext.size(); ++i)
        std::cout << std::hex << (int)ciphertext[i];
    std::cout << std::dec << std::endl;
    std::cout << "HMAC: ";
    for (auto i = 0; i < HMAC_DIGEST_SIZE; ++i)
        std::cout << std::hex << (int)hmac[i];
    std::cout << std::dec << std::endl;
    std::cout << "----------------------------------------------------------" << std::endl;
}