#include "SHA_512.hpp"


void SHA_512::generate(const unsigned char* input_buffer, size_t input_buffer_size, std::vector<uint8_t>& digest, unsigned int& digest_size) 
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

bool SHA_512::verify(const unsigned char* input_buffer, size_t input_buffer_size, const unsigned char* input_digest) 
{
    std::vector<uint8_t> generated_digest;
    unsigned int generated_digest_size = 0;

    try {
        SHA_512::generate(input_buffer, input_buffer_size, generated_digest, generated_digest_size);
        return CRYPTO_memcmp(input_digest, generated_digest.data(), EVP_MD_size(EVP_sha256())) == 0;
    } catch (...) {
        throw;
    }
}
