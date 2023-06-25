#include "AES_CBC.hpp"


AES_CBC::AES_CBC(uint8_t type, const std::vector<uint8_t>& session_key) : type(type), processed_bytes(0), iv_type(false)
{
    if (type != ENCRYPT && type != DECRYPT)
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m AES_CBC::AES_CBC() >> Invalid type specified.");

    this->key.resize(session_key.size());
    std::copy(session_key.begin(), session_key.end(), this->key.begin());
}

AES_CBC::AES_CBC(uint8_t type, const std::vector<uint8_t>& session_key, const bool iv) : type(type), processed_bytes(0), iv_type(iv)
{
    if (type != ENCRYPT && type != DECRYPT)
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m AES_CBC::AES_CBC() >> Invalid type specified.");

    this->key.resize(session_key.size());
    std::copy(session_key.begin(), session_key.end(), this->key.begin());
}

AES_CBC::~AES_CBC()
{
    EVP_CIPHER_CTX_free(ctx);

    std::memset(reinterpret_cast<void*>(this->iv.data()), 0, this->iv.size());
    this->iv.clear();

    std::memset(reinterpret_cast<void*>(this->key.data()), 0, this->key.size());
    this->key.clear();

    std::memset(reinterpret_cast<void*>(this->plaintext.data()), 0, this->plaintext.size());
    this->plaintext.clear();

    std::memset(reinterpret_cast<void*>(this->ciphertext.data()), 0, this->ciphertext.size());
    this->ciphertext.clear();
}

void AES_CBC::initializeEncrypt()
{
    auto iv_lenght = EVP_CIPHER_iv_length(EVP_aes_256_cbc());
    this->iv.resize(iv_lenght);

    const long unsigned int block_size = EVP_CIPHER_block_size(EVP_aes_256_cbc());
    
    // Seed OpenSSL PRNG
    RAND_poll();

    // Generate IV
    if (iv_type == true)
        // genera iv constante
        this->iv.assign(this->iv.size(), 0);
    else {
        if (RAND_bytes(reinterpret_cast<unsigned char*>(iv.data()), static_cast<int>(iv.size())) != 1)
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m AES_CBC::initializeEncrypt() >> Failed to generate random bytes for IV.");
    }

    // Check for possible integer overflow in (plaintext_size + block_size) --> PADDING!
    if (plaintext.size() > INT_MAX - block_size)
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m AES_CBC::initializeEncrypt() >> Integer overflow (file too big?).");

    if (!(ctx = EVP_CIPHER_CTX_new()))
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m AES_CBC::initializeEncrypt() >> Failed to create EVP_CIPHER_CTX.");

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, reinterpret_cast<const unsigned char*>(key.data()), reinterpret_cast<const unsigned char*>(iv.data())) != 1)
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m AES_CBC::initializeEncrypt() >> Failed to initialize encryption.");

    ciphertext.resize(plaintext.size() + block_size);
}

void AES_CBC::updateEncrypt()
{
    int update_len = 0;
    if (EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(ciphertext.data()), &update_len, reinterpret_cast<const unsigned char*>(plaintext.data()), static_cast<int>(plaintext.size())) != 1)
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m AES_CBC::updateEncrypt() >> Encryption update failed.");

    processed_bytes += update_len;
}

void AES_CBC::finalizeEncrypt()
{
    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(ciphertext.data() + processed_bytes*sizeof(uint8_t)), &final_len) != 1) {
        
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m AES_CBC::finalizeEncrypt() >> Encryption finalization failed.");
    }

    processed_bytes += final_len;
    ciphertext.erase(ciphertext.begin() + processed_bytes, ciphertext.end());

    std::memset(reinterpret_cast<void*>(plaintext.data()), 0, plaintext.size());
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
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, reinterpret_cast<const unsigned char*>(key.data()), reinterpret_cast<const unsigned char*>(iv.data())) != 1)
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m AES_CBC::initializeDecrypt() >> Failed to initialize decryption.");

    processed_bytes = 0;
}

void AES_CBC::updateDecrypt()
{
    int update_len = 0;
    if (EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(plaintext.data()), &update_len, reinterpret_cast<const unsigned char*>(ciphertext.data()), static_cast<int>(ciphertext.size())) != 1) {
        
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m AES_CBC::updateDecrypt() >> Decryption update failed.");
    }

    processed_bytes += update_len;
}

void AES_CBC::finalizeDecrypt()
{
    int final_len = 0;

    if (EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(plaintext.data() + processed_bytes*sizeof(uint8_t)), &final_len) != 1) {
        
        auto error_code = ERR_get_error();
        std::cout << error_code << std::endl;

        char error_string[1024];
        ERR_error_string(error_code, error_string);

        std::cout << error_string << std::endl;

        ERR_print_errors_fp(stderr);
        
        if (error_code == EVP_R_BAD_DECRYPT)
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m AES_CBC::finalizeDecrypt() >> Decryption failed: Authentication failure or ciphertext tampered.");
        else {
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m AES_CBC::finalizeDecrypt() >> Decryption failed: Unknown error.");
        }

    }
    processed_bytes += final_len;
}

void AES_CBC::run(const std::vector<uint8_t>& input_buffer, std::vector<uint8_t>& output_buffer, std::vector<uint8_t>& iv)
{
    if (this->type == ENCRYPT)
    {
        this->plaintext.resize(input_buffer.size());
        std::copy(input_buffer.begin(), input_buffer.end(), this->plaintext.begin());

        initializeEncrypt();
        std::copy(this->iv.begin(), this->iv.end(), iv.begin());
        updateEncrypt();
        finalizeEncrypt();

        output_buffer.resize(this->ciphertext.size());
        std::copy(this->ciphertext.begin(), this->ciphertext.end(), output_buffer.begin());
        output_buffer.shrink_to_fit();
    }
    else if (this->type == DECRYPT)
    {
        this->ciphertext.resize(input_buffer.size());
        std::copy(input_buffer.begin(), input_buffer.end(), this->ciphertext.begin());

        this->iv.resize(EVP_CIPHER_iv_length(EVP_aes_256_cbc()));
        std::copy(iv.begin(), iv.end(), this->iv.begin());

        initializeDecrypt();
        updateDecrypt();
        finalizeDecrypt();

        output_buffer.resize(this->plaintext.size());
        std::copy(this->plaintext.begin(), this->plaintext.end(), output_buffer.begin());
        output_buffer.shrink_to_fit();
    }
    else
    {
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m AES_CBC::run() >> Invalid type specified");
    }
}
