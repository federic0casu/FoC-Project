#include <vector>
#include <fstream>
#include <stdexcept>

#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>

class RSASignature {
public:
    RSASignature(const std::string& private_key_file, const std::string& public_key_file);
    std::vector<unsigned char> sign(const std::vector<unsigned char>& buffer);
    bool verify(const std::vector<unsigned char>& buffer, const std::vector<unsigned char>& signature);

private:
    EVP_PKEY* public_key;
    EVP_PKEY* private_key;
};
