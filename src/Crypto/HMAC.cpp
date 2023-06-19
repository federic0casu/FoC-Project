#include "HMAC.hpp"


HMac::HMac(const unsigned char* key) 
{
    m_key = new unsigned char[HMAC_DIGEST_SIZE];
    memcpy(m_key, key, HMAC_DIGEST_SIZE);
}

HMac::~HMac() 
{
    memset(m_key, 0, HMAC_DIGEST_SIZE);
    delete[] m_key;
}

void HMac::generate(unsigned char* input_buffer, size_t input_buffer_size, std::vector<unsigned char>& digest, unsigned int& digest_size) 
{    
    digest.resize(EVP_MD_size(EVP_sha256()));
    HMAC_CTX* ctx = HMAC_CTX_new();

    HMAC_Init_ex(ctx, m_key, HMAC_DIGEST_SIZE, EVP_sha256(), nullptr);
    HMAC_Update(ctx, input_buffer, input_buffer_size);
    HMAC_Final(ctx, digest.data(), &digest_size);    

    HMAC_CTX_free(ctx);
}

bool HMac::verify(unsigned char* input_buffer, size_t input_buffer_size, std::vector<unsigned char>& input_digest) 
{
    std::vector<unsigned char> generated_digest;
    unsigned int generated_digest_size = 0;

    generate(input_buffer, input_buffer_size, generated_digest, generated_digest_size);
    bool res = CRYPTO_memcmp(input_digest.data(), generated_digest.data(), EVP_MD_size(EVP_sha256())) == 0;

    return res;
}