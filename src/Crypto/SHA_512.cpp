#include "SHA_512.hpp"

#include <iostream>

void SHA_512::generate(const unsigned char* input_buffer, size_t input_buffer_size, unsigned char*& digest, unsigned int& digest_size) 
{
    digest = new uint8_t[EVP_MD_size(EVP_sha512())];
    if (!digest)
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m SHA_512::generate() >> Failed to allocate digest.");

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

    if (EVP_DigestFinal(ctx, digest, &digest_size) != 1) 
    {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m SHA_512::generate() >> Failed to finalize digest.");
    }

    EVP_MD_CTX_free(ctx);
}

bool SHA_512::verify(const unsigned char* input_buffer, size_t input_buffer_size, const unsigned char* input_digest) 
{
    unsigned char* generated_digest = nullptr;
    unsigned int generated_digest_size = 0;

    try {
        SHA_512::generate(input_buffer, input_buffer_size, generated_digest, generated_digest_size);
        bool res = CRYPTO_memcmp(input_digest, generated_digest, EVP_MD_size(EVP_sha256())) == 0;

        delete[] generated_digest;
        return res;
    } catch (...) {
        delete[] generated_digest;
        throw;
    }
}
