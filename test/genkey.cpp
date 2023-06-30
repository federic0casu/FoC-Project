#include <mutex>
#include <string>
#include <atomic>
#include <thread>
#include <vector>
#include <csignal>
#include <cstring>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <iostream>
#include <stdexcept>
#include <algorithm>

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


std::string vectorToString(std::vector<uint8_t> vec);
std::string GetSalt(std::vector<uint8_t>& serialized_salt);
void stringToVector(std::string &str, std::vector<uint8_t> &vec, long unsigned int size);
void SHA_512__generate(const unsigned char* input_buffer, size_t input_buffer_size, std::vector<uint8_t>& digest, unsigned int& digest_size);

int main() {

    std::string password;
    std::string _username;
    int amount = 0;
    std::vector<uint8_t> serialized_salt(20, 0);

    std::cout << "Username: ";
    std::cin >> _username;
    std::cout << "Password: ";
    std::cin >> password;
    std::cout << "Amount: ";
    std::cin >> amount;

    std::string file_path = "../res/archive/account/" + _username + ".txt";

    // Seed OpenSSL PRNG
    RAND_poll();

    if (RAND_bytes(reinterpret_cast<unsigned char*>(serialized_salt.data()), static_cast<int>(serialized_salt.size())) != 1)
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Failed to generate random bytes for SALT.");

    std::ofstream _file(file_path, std::ios::binary);

    try {
        if (!_file) {
            std::cerr << "\033[1;31m[ERROR]\033[0m Failed to open file." << std::endl;
            return false;
        }

        std::vector<uint8_t> username(30, 0);
        stringToVector(_username, username, 30);

        // scrivi username
        _file.write(reinterpret_cast<const char*>(username.data()), username.size());
        std::cout << "Username >> " << reinterpret_cast<const char*>(username.data()) << " OK " << std::endl;
        
        //scrivi salt
        _file.write(reinterpret_cast<const char*>(serialized_salt.data()), serialized_salt.size());
        std::cout << "Salt >> " << reinterpret_cast<const char*>(serialized_salt.data()) << " OK " << std::endl;

        std::vector<uint8_t> vector(50, 0);
        std::string _salted_password = password + GetSalt(serialized_salt);
        stringToVector(_salted_password, vector, 50);

        std::vector<uint8_t> _digest;
        unsigned int _digest_size;
        SHA_512__generate(reinterpret_cast<unsigned char*>(vector.data()), vector.size(), _digest, _digest_size);
        _file.write(reinterpret_cast<const char*>(_digest.data()), _digest_size );

        std::vector<uint8_t> cleartext(20, 0);
        std::string amountstr = std::to_string(amount);
        stringToVector(amountstr, cleartext, 20);

        std::vector<uint8_t> ciphertext;
        std::vector<uint8_t> session_key(32);
        session_key.assign(session_key.size(), 2);
        std::vector<uint8_t> iv(EVP_CIPHER_iv_length(EVP_aes_256_cbc()));

        try {
            AES_CBC encryptor(ENCRYPT, session_key, true);
            encryptor.run(cleartext , ciphertext, iv);
        } catch (std::runtime_error& ex) {
            std::cerr << ex.what() << std::endl;
            _file.close();
            return false;
        }

        _file.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
        _file.close();
    } catch(const std::runtime_error& ex) {
        std::cerr << ex.what() << std::endl;
    }
}

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

// ritorna il salt in formato stringa 
std::string GetSalt(std::vector<uint8_t>& serialized_salt) 
{
    std::string string_salt;
    string_salt = vectorToString(serialized_salt);
    return string_salt;
}

void stringToVector(std::string &str, std::vector<uint8_t> &vec, long unsigned int size) 
{
    for (long unsigned int i = 0; i < size && i < str.length(); i++)
        vec[i] = static_cast<uint8_t>(str[i]);
}

std::string vectorToString(std::vector<uint8_t> vec) 
{
    std::string str;
    for (const auto& elem : vec)
        str += static_cast<char>(elem);
    return str;
}

void SHA_512__generate(const unsigned char* input_buffer, size_t input_buffer_size, std::vector<uint8_t>& digest, unsigned int& digest_size) 
{
    digest.resize(EVP_MD_size(EVP_sha512()));
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    if (!ctx)
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m SHA_512::generate() >> Failed to create EVP_MD_CTX.");

    if (EVP_DigestInit(ctx, EVP_sha512()) != 1) 
    {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m SHA_512::generate() >> Failed to initialize digest.");
    }

    if (EVP_DigestUpdate(ctx, input_buffer, input_buffer_size) != 1) 
    {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m SHA_512::generate() >> Failed to update digest.");
    }

    if (EVP_DigestFinal(ctx, digest.data(), &digest_size) != 1) 
    {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m SHA_512::generate() >> Failed to finalize digest.");
    }

    EVP_MD_CTX_free(ctx);
}