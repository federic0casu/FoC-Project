#include "RSASignature.hpp"

#include <iostream>

RSASignature::RSASignature(const std::string& private_key_file, const std::string& public_key_file) {
    public_key = nullptr;
    private_key = nullptr;
    
    if (!private_key_file.empty()) {
        BIO * bp = nullptr;
        bp = BIO_new_file(private_key_file.c_str(), "r");
        if (!bp) 
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m RSASignature::RSASignature() >> Failed to open private key file: " + private_key_file);

        private_key = PEM_read_bio_PrivateKey(bp, NULL, NULL, NULL);
        BIO_free(bp); 
        if (!private_key) {
            ERR_print_errors_fp(stderr);
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m RSASignature::RSASignature() >> Failed to read private key.");
        }
    }

    if (!public_key_file.empty()) { 
        // Load public key
        BIO * bp = nullptr;
        bp = BIO_new_file(public_key_file.c_str(), "r");
        if (!bp) 
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m RSASignature::RSASignature() >> Failed to open public key file: " + public_key_file);

        public_key = PEM_read_bio_PUBKEY(bp, NULL, NULL, NULL);
        BIO_free(bp); 
        if (!public_key) {
            ERR_print_errors_fp(stderr);
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m RSASignature::RSASignature() >> Failed to read public key.");
        }
    }
}

std::vector<unsigned char> RSASignature::sign(const std::vector<unsigned char>& buffer) {
    if (!private_key)
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m RSASignature::sign() >> Private key not loaded.");

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_PKEY* privkey = private_key;

    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, privkey) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(privkey);
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m RSASignature::sign() >> Failed to initialize signing context.");
    }

    if (EVP_DigestSignUpdate(ctx, buffer.data(), buffer.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(privkey);
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m RSASignature::sign() >> Failed to update signing context.");
    }

    size_t signatureLen;
    if (EVP_DigestSignFinal(ctx, nullptr, &signatureLen) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(privkey);
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m RSASignature::sign() >> Failed to determine signature length.");
    }

    std::vector<unsigned char> signature(signatureLen);
    if (EVP_DigestSignFinal(ctx, signature.data(), &signatureLen) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(privkey);
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m RSASignature::sign() >> Failed to sign the buffer.");
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(privkey);

    return signature;
}

bool RSASignature::verify(const std::vector<unsigned char>& buffer, const std::vector<unsigned char>& signature) {
    if (!public_key)
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m RSASignature::verify() >> Public key not loaded.");

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_PKEY* pubkey = public_key;

    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pubkey) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pubkey);
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m RSASignature::verify() >> Failed to initialize verification context.");
    }

    if (EVP_DigestVerifyUpdate(ctx, buffer.data(), buffer.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pubkey);
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m RSASignature::verify() >> Failed to update verification context.");
    }

    int result = EVP_DigestVerifyFinal(ctx, signature.data(), signature.size());
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pubkey);

    if (result == 1) {
        return true; // Signature verified successfully
    } else if (result == 0) {
        return false; // Signature verification failed
    } else {
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m RSASignature::verify() >> Error occurred during signature verification.");
    }
}
