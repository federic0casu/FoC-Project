#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>

#include <arpa/inet.h>
#include <openssl/rand.h>

#include "../Generic/Codes.hpp"

#include "../Crypto/SHA_512.hpp"
#include "../Crypto/AES_CBC.hpp"
#include "../Crypto/HMAC.hpp"
#include "../Crypto/CertificateStore.hpp"
#include "../Crypto/DigitalSignature.hpp"


#define ENCRYPTED_SIGNATURE_SIZE 144 
#define EPHEMERAL_KEY_SIZE       1024
#define USERNAME_SIZE            32

struct HandshakeM1
{
    uint32_t key_size;
    uint8_t ephemeral_key[EPHEMERAL_KEY_SIZE];
    uint8_t username[USERNAME_SIZE];

    HandshakeM1() {}

    HandshakeM1(uint8_t *ephemeral_key, int key_size, const unsigned char* username)
    {    
        this->key_size = (uint32_t) key_size;

        std::memset(this->ephemeral_key, 0, EPHEMERAL_KEY_SIZE);
        std::memcpy(this->ephemeral_key, ephemeral_key, this->key_size);
        std::memset(this->username, 0, sizeof(this->username));
        std::memcpy(this->username, username, sizeof(this->username));
    }

    void serialize(uint8_t* buffer)
    {
        int position = 0;

        uint32_t key_size_network = htonl(key_size);
        std::memcpy(buffer, &key_size_network, sizeof(uint32_t));
        position += sizeof(uint32_t);

        std::memcpy(buffer + position, this->ephemeral_key, EPHEMERAL_KEY_SIZE);
        position += EPHEMERAL_KEY_SIZE * sizeof(uint8_t);

        std::memcpy(buffer + position, this->username, sizeof(this->username));
    }

    static int GetSize() 
    {
        return sizeof(key_size) + sizeof(ephemeral_key) + sizeof(username);
    }

    static HandshakeM1 Deserialize(uint8_t * buffer)
    {
        HandshakeM1 m1;

        int position = 0;
        uint32_t key_size_network = 0;

        std::memcpy(&key_size_network, buffer, sizeof(uint32_t));
        m1.key_size = ntohl(key_size_network);
        position += sizeof(uint32_t);

        std::memset(m1.ephemeral_key, 0, sizeof(ephemeral_key));
        std::memcpy(m1.ephemeral_key, buffer + position, sizeof(ephemeral_key));
        position += sizeof(uint8_t) * EPHEMERAL_KEY_SIZE;

        std::memcpy(m1.username, buffer + position, sizeof(username));
        return m1;
    }

    void print() const 
    {
        std::cout << "---------- HANDSHAKE M1 ----------" << std::endl;
        std::cout << "EPHEMERAL KEY:" << std::endl;
        for (int i = 0; i < EPHEMERAL_KEY_SIZE; ++i)
            std::cout << hex << ephemeral_key[i];
        std::cout << dec << std::endl;
        //std::cout << username << std::endl;
        std::cout << "EPHEMERAL KEY SIZE: " << key_size << std::endl;
        std::cout << "------------------------------" << std::endl;
    }
};



struct HandshakeM2 
{
    uint8_t ephemeral_key[EPHEMERAL_KEY_SIZE];
    uint8_t iv[AES_BLOCK_SIZE];
    uint8_t encrypted_signature[ENCRYPTED_SIGNATURE_SIZE];
    uint8_t serialized_certificate[MAX_SERIALIZED_CERTIFICATE_SIZE];
    uint32_t ephemeral_key_size;
    uint32_t serialized_certificate_size;

    HandshakeM2() {}

    HandshakeM2(uint8_t* ephemeral_key, uint32_t ephemeral_key_size, uint8_t* iv, uint8_t* encrypted_signature, uint8_t* serialized_certificate, int serialized_certificate_size)
    {    
        std::memset(this->ephemeral_key, 0, sizeof(this->ephemeral_key));
        std::memcpy(this->ephemeral_key, ephemeral_key, ephemeral_key_size);

        std::memcpy(this->iv, iv, AES_BLOCK_SIZE * sizeof(uint8_t));

        this->ephemeral_key_size = (unsigned int)ephemeral_key_size;

        std::memcpy(this->encrypted_signature, encrypted_signature, ENCRYPTED_SIGNATURE_SIZE * sizeof(uint8_t));

        std::memcpy(this->serialized_certificate, serialized_certificate, serialized_certificate_size);
        std::memset(this->serialized_certificate + serialized_certificate_size, 0, MAX_SERIALIZED_CERTIFICATE_SIZE - serialized_certificate_size);

        this->serialized_certificate_size = (unsigned int) serialized_certificate_size;
    }

    uint8_t* serialize() const {

        uint8_t* buffer = new uint8_t[HandshakeM2::getSize()];

        size_t position = 0;
        memcpy(buffer, ephemeral_key, EPHEMERAL_KEY_SIZE * sizeof(uint8_t));
        position += EPHEMERAL_KEY_SIZE * sizeof(uint8_t);

        uint32_t ephemeral_key_size_hton = htonl(ephemeral_key_size);
        memcpy(buffer + position, &ephemeral_key_size_hton, sizeof(uint32_t));
        position += sizeof(uint32_t);

        memcpy(buffer + position, iv, AES_BLOCK_SIZE * sizeof(uint8_t));
        position += AES_BLOCK_SIZE * sizeof(uint8_t);

        memcpy(buffer + position, encrypted_signature, ENCRYPTED_SIGNATURE_SIZE * sizeof(uint8_t));
        position += ENCRYPTED_SIGNATURE_SIZE * sizeof(uint8_t);

        memcpy(buffer + position, serialized_certificate, MAX_SERIALIZED_CERTIFICATE_SIZE);
        position += MAX_SERIALIZED_CERTIFICATE_SIZE;

        uint32_t serialized_certificate_size_hton = htonl(serialized_certificate_size);
        memcpy(buffer + position, &serialized_certificate_size_hton, sizeof(uint32_t));

        return buffer;
    }

    static HandshakeM2 deserialize(uint8_t* buffer) {

        HandshakeM2 handshakeM2;

        size_t position = 0;
        memcpy(handshakeM2.ephemeral_key, buffer, EPHEMERAL_KEY_SIZE * sizeof(uint8_t));
        position += EPHEMERAL_KEY_SIZE * sizeof(uint8_t);

        uint32_t ephemeral_key_size_hton = 0;
        memcpy(&ephemeral_key_size_hton, buffer + position, sizeof(uint32_t));
        handshakeM2.ephemeral_key_size = ntohl(ephemeral_key_size_hton);
        position += sizeof(uint32_t);

        memcpy(handshakeM2.iv, buffer + position, AES_BLOCK_SIZE * sizeof(uint8_t));
        position += AES_BLOCK_SIZE * sizeof(uint8_t);

        memcpy(handshakeM2.encrypted_signature, buffer + position, ENCRYPTED_SIGNATURE_SIZE * sizeof(uint8_t));
        position += ENCRYPTED_SIGNATURE_SIZE * sizeof(uint8_t);

        memcpy(handshakeM2.serialized_certificate, buffer + position, MAX_SERIALIZED_CERTIFICATE_SIZE);
        position += MAX_SERIALIZED_CERTIFICATE_SIZE;

        uint32_t serialized_certificate_size_hton = 0;
        memcpy(&serialized_certificate_size_hton, buffer + position, sizeof(uint32_t));
        handshakeM2.serialized_certificate_size = ntohl(serialized_certificate_size_hton);

        return handshakeM2;
    }

    static int getSize() {

        int size = 0;

        size += EPHEMERAL_KEY_SIZE * sizeof(uint8_t);
        size += sizeof(uint32_t);
        size += AES_BLOCK_SIZE * sizeof(uint8_t);
        size += ENCRYPTED_SIGNATURE_SIZE * sizeof(uint8_t);
        size += MAX_SERIALIZED_CERTIFICATE_SIZE * sizeof(uint8_t);
        size += sizeof(uint32_t);

        return size;
    }

    void print() const {

        cout << "---------- HANDSHAKE M2 ----------" << endl;
        cout << "EPHEMERAL KEY:" << endl;
        for (int i = 0; i < EPHEMERAL_KEY_SIZE; ++i)
            cout << hex << ephemeral_key[i];
        cout << dec << endl;
        cout << "EPHEMERAL KEY SIZE: " << ephemeral_key_size << endl;
        cout << "IV:" << endl;
        for (int i = 0; i < AES_BLOCK_SIZE; ++i)
            cout << hex << iv[i];
        cout << dec << endl;
        cout << "ENCRYPTED SIGNATURE:" << endl;
        for (int i = 0; i < ENCRYPTED_SIGNATURE_SIZE; ++i)
            cout << hex << encrypted_signature[i];
        cout << dec << endl;
        cout << "SERIALIZED CERTIFICATE:" << endl;
        for (int i = 0; i < (int)serialized_certificate_size; ++i)
            cout << hex << serialized_certificate[i];
        cout << dec << endl;
        cout << "SERIALIZED CERTIFICATE SIZE: " << serialized_certificate_size << endl;
        cout << "------------------------------" << endl;
    }
};


struct HandshakeM3 {

    uint8_t iv[AES_BLOCK_SIZE];
    uint8_t encrypted_signature[ENCRYPTED_SIGNATURE_SIZE]; 

    HandshakeM3() {}

    HandshakeM3(uint8_t* iv, uint8_t* encrypted_signature) {
        
        memcpy(this->iv, iv, AES_BLOCK_SIZE * sizeof(uint8_t));
        memcpy(this->encrypted_signature, encrypted_signature, ENCRYPTED_SIGNATURE_SIZE * sizeof(uint8_t));
    }

    uint8_t* serialize() const {

        uint8_t* buffer = new uint8_t[HandshakeM3::getSize()];

        size_t position = 0;
        memcpy(buffer, iv, AES_BLOCK_SIZE * sizeof(uint8_t));
        position += AES_BLOCK_SIZE * sizeof(uint8_t);

        memcpy(buffer + position, encrypted_signature, ENCRYPTED_SIGNATURE_SIZE * sizeof(uint8_t));

        return buffer;
    }


    static HandshakeM3 deserialize(uint8_t* buffer) {

        HandshakeM3 handshakeM3;

        size_t position = 0;
        memcpy(handshakeM3.iv, buffer, AES_BLOCK_SIZE * sizeof(uint8_t));
        position += AES_BLOCK_SIZE * sizeof(uint8_t);

        memcpy(handshakeM3.encrypted_signature, buffer + position, ENCRYPTED_SIGNATURE_SIZE * sizeof(uint8_t));
        position += ENCRYPTED_SIGNATURE_SIZE * sizeof(uint8_t);

        return handshakeM3;
    }

    static int getSize() {

        int size = 0;

        size += AES_BLOCK_SIZE * sizeof(uint8_t);
        size += ENCRYPTED_SIGNATURE_SIZE * sizeof(uint8_t);

        return size;
    }

    void print() const {

        cout << "---------- HANDSHAKE M3 ----------" << endl;
        cout << "IV:" << endl;
        for (int i = 0; i < AES_BLOCK_SIZE; ++i)
            cout << hex << iv[i];
        cout << dec << endl;
        cout << "ENCRYPTED SIGNATURE:" << endl;
        for (int i = 0; i < ENCRYPTED_SIGNATURE_SIZE; ++i)
            cout << hex << encrypted_signature[i];
        cout << dec << endl;
        cout << "------------------------------" << endl;
    }
};


