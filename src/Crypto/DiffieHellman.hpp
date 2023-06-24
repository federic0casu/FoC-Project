#include <vector>
#include <openssl/evp.h>

class DiffieHellman {

    EVP_PKEY *m_dh_parameters;

public:
    DiffieHellman();
    DiffieHellman(const DiffieHellman&) = delete;
    ~DiffieHellman();

    EVP_PKEY* generateEphemeralKey();
    void generateSharedSecret(EVP_PKEY* private_key, EVP_PKEY* peer_ephemeral_key, std::vector<uint8_t>& shared_secret, size_t& shared_secret_size);

    static std::vector<uint8_t> serializeKey(EVP_PKEY* key);
    static EVP_PKEY* deserializeKey(uint8_t* serialized_key, int serialized_key_size);
};
