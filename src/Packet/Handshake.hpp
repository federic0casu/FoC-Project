#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>

#include <arpa/inet.h>
#include <openssl/rand.h>

#include "../Generic/Codes.hpp"

#include "../Crypto/HMAC.hpp"
#include "../Crypto/SHA_512.hpp"
#include "../Crypto/AES_CBC.hpp"
#include "../Crypto/RSASignature.hpp"


#define ENCRYPTED_SIGNATURE_SIZE 272 
#define EPHEMERAL_KEY_SIZE       1024
#define USERNAME_SIZE            32

struct HandshakeM1
{
    uint32_t ephemeral_key_size;
    uint8_t  ephemeral_key[EPHEMERAL_KEY_SIZE];
    uint8_t  username_size;
    uint8_t  username[USERNAME_SIZE];

    HandshakeM1() : ephemeral_key_size(0), username_size(0)
    {
        std::memset(this->username, 0, USERNAME_SIZE);
        std::memset(this->ephemeral_key, 0, EPHEMERAL_KEY_SIZE);
    }

    HandshakeM1(std::vector<uint8_t>& ephemeral_key, int key_size, const unsigned char* username, size_t username_lenght)
    {   
        if (username_size > USERNAME_SIZE) 
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m Username too big!");

        this->ephemeral_key_size = (uint32_t) key_size;
        this->username_size      = (uint8_t) username_lenght;

        std::memset(this->ephemeral_key, 0, EPHEMERAL_KEY_SIZE);
        std::memcpy(this->ephemeral_key, ephemeral_key.data(), this->ephemeral_key_size);

        std::memset(this->username, 0, USERNAME_SIZE);
        std::memcpy(this->username, username, username_lenght);
    }

    void serialize(std::vector<uint8_t>& buffer)
    {
        int position = 0;
        buffer.resize(HandshakeM1::GetSize());

        uint32_t key_size_network = htonl(ephemeral_key_size);
        std::memcpy(buffer.data(), &key_size_network, sizeof(uint32_t));
        position += sizeof(uint32_t);

        std::memcpy(buffer.data() + position, this->ephemeral_key, EPHEMERAL_KEY_SIZE);
        position += EPHEMERAL_KEY_SIZE * sizeof(uint8_t);

        std::memcpy(buffer.data() + position, &(this->username_size), sizeof(uint8_t));
        position += sizeof(uint8_t);

        std::memcpy(buffer.data() + position, this->username, sizeof(this->username));
    }

    static inline int GetSize() 
    {
        return sizeof(ephemeral_key_size) + sizeof(ephemeral_key) + sizeof(username_size) + sizeof(username);
    }

    static HandshakeM1 Deserialize(std::vector<uint8_t>& buffer)
    {
        HandshakeM1 m1;

        int position = 0;
        uint32_t key_size_network = 0;

        std::memcpy(&key_size_network, reinterpret_cast<void*>(buffer.data()), sizeof(uint32_t));
        m1.ephemeral_key_size = ntohl(key_size_network);
        position += sizeof(uint32_t);

        std::memset(m1.ephemeral_key, 0, sizeof(ephemeral_key));
        std::memcpy(m1.ephemeral_key, reinterpret_cast<void*>(buffer.data() + position), sizeof(ephemeral_key));
        position += sizeof(uint8_t) * EPHEMERAL_KEY_SIZE;

        m1.username_size = buffer[position];
        position += sizeof(uint8_t);

        std::memset(m1.username, 0, sizeof(username));
        std::memcpy(m1.username, reinterpret_cast<void*>(buffer.data() + position), sizeof(username));
        return m1;
    }

    void print() const 
    {
        std::cout << "---------- HANDSHAKE M1 ----------" << std::endl;
        std::cout << "EPHEMERAL KEY:" << std::endl;
        for (int i = 0; i < EPHEMERAL_KEY_SIZE; ++i)
            std::cout << std::hex << ephemeral_key[i];
        std::cout << std::dec;
        std::cout << "USERNAME: " << username << std::endl;
        std::cout << "EPHEMERAL KEY SIZE: " << ephemeral_key_size << std::endl;
        std::cout << "------------------------------" << std::endl;
    }
};



struct HandshakeM2 
{
    uint8_t result;
    std::vector<uint8_t> ephemeral_key;
    uint32_t ephemeral_key_size;
    std::vector<uint8_t> iv;
    uint32_t iv_size;
    std::vector<uint8_t> encrypted_signature;
    uint32_t encrypted_signature_size;

    HandshakeM2() : result(1), ephemeral_key_size(0), iv_size(0), encrypted_signature_size(0) {}

    HandshakeM2(int res) : result(res), ephemeral_key_size(0), iv_size(0), encrypted_signature_size(0) {}

    HandshakeM2(std::vector<uint8_t> ephemeral_key, std::vector<uint8_t>& iv, std::vector<uint8_t>& encrypted_signature)
    {    
        this->result = 1;

        this->ephemeral_key_size = static_cast<unsigned int>(ephemeral_key.size());

        this->iv_size = static_cast<unsigned int>(iv.size());

        this->encrypted_signature_size = static_cast<unsigned int>(encrypted_signature.size());

        this->ephemeral_key.resize(this->ephemeral_key_size);
        std::memcpy(reinterpret_cast<void*>(this->ephemeral_key.data()), reinterpret_cast<const void*>(ephemeral_key.data()), this->ephemeral_key.size());

        this->iv.resize(this->iv_size);
        std::memcpy(reinterpret_cast<void*>(this->iv.data()), reinterpret_cast<const void*>(iv.data()), this->iv.size());
        
        this->encrypted_signature.resize(this->encrypted_signature_size);
        std::memcpy(reinterpret_cast<void*>(this->encrypted_signature.data()), reinterpret_cast<const void*>(encrypted_signature.data()), encrypted_signature.size());
    }

    std::vector<uint8_t> serialize() const {

        std::vector<uint8_t> buffer(HandshakeM2::GetSize());

        size_t position = 0;

        buffer[0] = this->result;
        position += sizeof(uint8_t);

        uint32_t ephemeral_key_size_hton = htonl(this->ephemeral_key_size);
        std::memcpy(reinterpret_cast<void*>(buffer.data() + position), &ephemeral_key_size_hton, sizeof(uint32_t));
        position += sizeof(uint32_t);

        std::memcpy(reinterpret_cast<void*>(buffer.data() + position), reinterpret_cast<const void*>(this->ephemeral_key.data()), this->ephemeral_key.size());
        position += ephemeral_key.size();

        uint32_t iv_size_hton = htonl(this->iv_size);
        std::memcpy(reinterpret_cast<void*>(buffer.data() + position), &iv_size_hton, sizeof(uint32_t));
        position += sizeof(uint32_t);

        std::memcpy(reinterpret_cast<void*>(buffer.data() + position), reinterpret_cast<const void*>(this->iv.data()), this->iv.size());
        position += this->iv.size();

        uint32_t encrypted_signature_size_hton = htonl(this->encrypted_signature_size);
        std::memcpy(reinterpret_cast<void*>(buffer.data() + position), &encrypted_signature_size_hton, sizeof(uint32_t));
        position += sizeof(uint32_t);

        std::memcpy(reinterpret_cast<void*>(buffer.data() + position), reinterpret_cast<const void*>(encrypted_signature.data()), encrypted_signature.size());

        return buffer;
    }

    static HandshakeM2 deserialize(std::vector<uint8_t>& buffer) {

        HandshakeM2 handshakeM2;

        size_t position = 0;

        handshakeM2.result = buffer[0];
        position += sizeof(uint8_t);

        uint32_t ephemeral_key_size_hton = 0;
        std::memcpy(&ephemeral_key_size_hton, buffer.data() + position, sizeof(uint32_t));
        handshakeM2.ephemeral_key_size = ntohl(ephemeral_key_size_hton);
        position += sizeof(uint32_t);

        handshakeM2.ephemeral_key.resize(handshakeM2.ephemeral_key_size);
        std::memcpy(reinterpret_cast<void*>(handshakeM2.ephemeral_key.data()), reinterpret_cast<const void*>(buffer.data() + position), handshakeM2.ephemeral_key_size);
        position += handshakeM2.ephemeral_key_size;

        uint32_t iv_size_hton = 0;
        std::memcpy(&iv_size_hton, buffer.data() + position, sizeof(uint32_t));
        handshakeM2.iv_size = ntohl(iv_size_hton);
        position += sizeof(uint32_t);

        handshakeM2.iv.resize(handshakeM2.iv_size);
        std::memcpy(reinterpret_cast<void*>(handshakeM2.iv.data()), reinterpret_cast<const void*>(buffer.data() + position), handshakeM2.iv_size);
        position += handshakeM2.iv_size;

        uint32_t encrypted_signature_size_hton = 0;
        std::memcpy(&encrypted_signature_size_hton, buffer.data() + position, sizeof(uint32_t));
        handshakeM2.encrypted_signature_size = ntohl(encrypted_signature_size_hton);
        position += sizeof(uint32_t);

        handshakeM2.encrypted_signature.resize(handshakeM2.encrypted_signature_size);
        std::memcpy(reinterpret_cast<void*>(handshakeM2.encrypted_signature.data()), reinterpret_cast<const void*>(buffer.data() + position), handshakeM2.encrypted_signature_size);
        
        return handshakeM2;
    }

    static int GetSize() {

        int size = 0;

        size += sizeof(uint8_t);
        size += EPHEMERAL_KEY_SIZE * sizeof(uint8_t);
        size += sizeof(uint32_t);
        size += AES_BLOCK_SIZE * sizeof(uint8_t);
        size += sizeof(uint32_t);
        size += ENCRYPTED_SIGNATURE_SIZE * sizeof(uint8_t);
        size += sizeof(uint32_t);

        return size;
    }

    void print() const {

        std::cout << "---------- HANDSHAKE M2 ----------" << std::endl;
        std::cout << "RESULT: " << result << std::endl;
        std::cout << "EPHEMERAL KEY:" << std::endl;
        for (int i = 0; i < EPHEMERAL_KEY_SIZE; ++i)
            std::cout << std::hex << ephemeral_key[i];
        std::cout << std::dec;
        std::cout << "EPHEMERAL KEY SIZE: " << ephemeral_key_size << std::endl;
        std::cout << "IV:" << std::endl;
        for (int i = 0; i < AES_BLOCK_SIZE; ++i)
            std::cout << std::hex << iv[i];
        std::cout << std::dec << std::endl;
        std::cout << "ENCRYPTED SIGNATURE:" << std::endl;
        for (int i = 0; i < ENCRYPTED_SIGNATURE_SIZE; ++i)
            std::cout << std::hex << encrypted_signature[i];
        std::cout << std::dec << std::endl;
        std::cout << "------------------------------" << std::endl;
    }
};


struct HandshakeM3 {

    uint32_t iv_size;
    std::vector<uint8_t> iv;
    uint32_t encrypted_signature_size; 
    std::vector<uint8_t> encrypted_signature;

    HandshakeM3() : iv_size(0), encrypted_signature_size(0) {}

    HandshakeM3(std::vector<uint8_t>& iv, std::vector<uint8_t>& encrypted_signature) {
        
        this->iv_size = iv.size();
        this->iv.resize(this->iv_size);
        std::memcpy(reinterpret_cast<void*>(this->iv.data()), reinterpret_cast<const void*>(iv.data()), this->iv_size);
        
        this->encrypted_signature_size = encrypted_signature.size();
        this->encrypted_signature.resize(this->encrypted_signature_size);
        std::memcpy(reinterpret_cast<void*>(this->encrypted_signature.data()), reinterpret_cast<const void*>(encrypted_signature.data()), this->encrypted_signature_size);
    }

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buffer(HandshakeM3::GetSize());
        size_t position = 0;

        uint32_t iv_size_hton = htonl(this->iv_size);
        std::memcpy(reinterpret_cast<void*>(buffer.data()), &iv_size_hton, sizeof(uint32_t));
        position += sizeof(uint32_t);

        std::memcpy(reinterpret_cast<void*>(buffer.data() + position), reinterpret_cast<const void*>(this->iv.data()), this->iv_size);
        position += this->iv_size;

        uint32_t encrypted_signature_size_hton = htonl(this->encrypted_signature_size);
        std::memcpy(reinterpret_cast<void*>(buffer.data() + position), &encrypted_signature_size_hton, sizeof(uint32_t));
        position += sizeof(uint32_t);

        std::memcpy(reinterpret_cast<void*>(buffer.data() + position), reinterpret_cast<const void*>(encrypted_signature.data()), this->encrypted_signature_size);

        return buffer;
    }


    static HandshakeM3 deserialize(std::vector<uint8_t>& buffer) {

        HandshakeM3 handshakeM3;

        size_t position = 0;

        uint32_t iv_size_hton = 0;
        std::memcpy(&iv_size_hton, buffer.data(), sizeof(uint32_t));
        handshakeM3.iv_size = ntohl(iv_size_hton);
        position += sizeof(uint32_t);

        handshakeM3.iv.resize(handshakeM3.iv_size);
        std::memcpy(reinterpret_cast<void*>(handshakeM3.iv.data()), reinterpret_cast<const void*>(buffer.data() + position), handshakeM3.iv_size);
        position += handshakeM3.iv_size;

        uint32_t encrypted_signature_size_hton = 0;
        std::memcpy(&encrypted_signature_size_hton, buffer.data() + position, sizeof(uint32_t));
        handshakeM3.encrypted_signature_size = ntohl(encrypted_signature_size_hton);
        position += sizeof(uint32_t);

        handshakeM3.encrypted_signature.resize(handshakeM3.encrypted_signature_size);
        std::memcpy(reinterpret_cast<void*>(handshakeM3.encrypted_signature.data()), reinterpret_cast<const void*>(buffer.data() + position), handshakeM3.encrypted_signature_size);

        return handshakeM3;
    }

    static int GetSize() {

        int size = 0;

        size += sizeof(uint32_t);
        size += AES_BLOCK_SIZE * sizeof(uint8_t);
        size += sizeof(uint32_t);
        size += ENCRYPTED_SIGNATURE_SIZE * sizeof(uint8_t);

        return size;
    }

    void print() const {

        std::cout << "---------- HANDSHAKE M3 ----------" << std::endl;
        std::cout << "IV:" << std::endl;
        for (int i = 0; i < AES_BLOCK_SIZE; ++i)
            std::cout << std::hex << iv[i];
        std::cout << std::dec << std::endl;
        std::cout << "ENCRYPTED SIGNATURE:" << std::endl;
        for (int i = 0; i < ENCRYPTED_SIGNATURE_SIZE; ++i)
            std::cout << std::hex << encrypted_signature[i];
        std::cout << std::dec << std::endl;
        std::cout << "------------------------------" << std::endl;
    }
};


