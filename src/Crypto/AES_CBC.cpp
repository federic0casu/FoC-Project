#include "AES_CBC.hpp"


AES_CBC::AES_CBC(uint8_t type, const std::vector<unsigned char>& session_key) : type(type), processed_bytes(0)
{
    if (type != ENCRYPT && type != DECRYPT)
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m AES_CBC::AES_CBC() >> Invalid type specified.");

    key.resize(AES_KEY_SIZE);
    std::copy(session_key.begin(), session_key.end(), key.begin());
}

AES_CBC::~AES_CBC()
{
    iv.clear();
    key.clear();
    plaintext.clear();
    ciphertext.clear();
}

void AES_CBC::initializeEncrypt()
{
    iv.resize(EVP_CIPHER_iv_length(EVP_aes_256_cbc()));
    const long unsigned int block_size = EVP_CIPHER_block_size(EVP_aes_256_cbc());
    
    // Seed OpenSSL PRNG
    RAND_poll();

    // Generate IV
    if (RAND_bytes(iv.data(), iv.size()) != 1)
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m AES_CBC::initializeEncrypt() >> Failed to generate random bytes for IV.");

    // Check for possible integer overflow in (plaintext_size + block_size) --> PADDING!
    if (plaintext.size() > INT_MAX - block_size)
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m AES_CBC::initializeEncrypt() >> Integer overflow (file too big?).");

    if (!(ctx = EVP_CIPHER_CTX_new()))
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m AES_CBC::initializeEncrypt() >> Failed to create EVP_CIPHER_CTX.");

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()) != 1)
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m AES_CBC::initializeEncrypt() >> Failed to initialize encryption.");

    ciphertext.resize(plaintext.size() + block_size);
}

void AES_CBC::updateEncrypt()
{
    int update_len = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &update_len, plaintext.data(), plaintext.size()) != 1)
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m AES_CBC::updateEncrypt() >> Encryption update failed.");

    processed_bytes += update_len;
}

void AES_CBC::finalizeEncrypt()
{
    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + processed_bytes, &final_len) != 1)
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m AES_CBC::finalizeEncrypt() >> Encryption finalization failed.");


    EVP_CIPHER_CTX_free(ctx);

    processed_bytes += final_len;
    plaintext.clear();
}

void AES_CBC::initializeDecrypt()
{
    plaintext.clear();
    plaintext.resize(ciphertext.size());

    if (iv.empty() || key.empty() || ciphertext.empty())
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m AES_CBC::initializeDecrypt() >> IV, key or ciphertext empty.");

    if (!(ctx = EVP_CIPHER_CTX_new()))
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m AES_CBC::initializeDecrypt() >> Failed to create EVP_CIPHER_CTX.");
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()) != 1)
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m AES_CBC::initializeDecrypt() >> Failed to initialize decryption.");

    processed_bytes = 0;
}

void AES_CBC::updateDecrypt()
{
    int update_len = 0;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &update_len, ciphertext.data(), ciphertext.size()) != 1)
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m AES_CBC::updateDecrypt() >> Decryption update failed.");

    processed_bytes += update_len;
}

void AES_CBC::finalizeDecrypt()
{
    int final_len = 0;

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + processed_bytes, &final_len) != 1)
    {
        int error = ERR_get_error();
        if (error == EVP_R_BAD_DECRYPT)
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m AES_CBC::finalizeDecrypt() >> Decryption failed: Authentication failure or ciphertext tampered.");
        else
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m AES_CBC::finalizeDecrypt() >> Decryption failed: Unknown error.");
    }

    processed_bytes += final_len;

    EVP_CIPHER_CTX_free(ctx);
}

void AES_CBC::run(const std::vector<uint8_t>& input_buffer, std::vector<uint8_t>& output_buffer, std::vector<uint8_t>& iv)
{
    if (type == ENCRYPT)
    {
        plaintext.resize(input_buffer.size());
        std::copy(input_buffer.begin(), input_buffer.end(), plaintext.begin());

        initializeEncrypt();
        std::copy(this->iv.begin(), this->iv.end(), iv.begin());
        updateEncrypt();
        finalizeEncrypt();

        output_buffer.resize(processed_bytes);
        std::copy(ciphertext.begin(), ciphertext.end(), output_buffer.begin());
    }
    else if (type == DECRYPT)
    {
        ciphertext.resize(input_buffer.size());
        std::copy(input_buffer.begin(), input_buffer.end(), ciphertext.begin());

        this->iv.resize(EVP_CIPHER_iv_length(EVP_aes_256_cbc()));
        std::copy(iv.begin(), iv.end(), this->iv.begin());

        initializeDecrypt();
        updateDecrypt();
        finalizeDecrypt();

        output_buffer.resize(plaintext.size());
        std::copy(plaintext.begin(), plaintext.end(), output_buffer.begin());
    }
    else
    {
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m AES_CBC::run() >> Invalid type specified");
    }
}
