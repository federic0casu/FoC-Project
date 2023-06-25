#include "FileManager.hpp"

#include "../Crypto/HMAC.hpp"
#include "../Crypto/AES_CBC.hpp"
#include "../Crypto/SHA_512.hpp"

bool FileManager::FindUser(std::string path) 
{
    this->file_path = path;

    username.resize(USERNAME_DIM);
    serialized_amount.resize(AMOUNT_DIM);
    password_digest.resize(PASS_DIGEST_DIM);
    serialized_salt.resize(SERIALIZED_SALT_DIM);
    
    std::ifstream file(path, std::ios::binary);

    if (!file) {
        std::cerr << "\033[1;31m[ERROR]\033[0m FileManager::FindUser() >> Failed to open file (" << path << ")" << std::endl;
        return false;
    }

    unsigned int to_read = 0;
    try {
        file.seekg(0, std::ios::end);
        std::streampos file_size = file.tellg();
        file.seekg(0, std::ios::beg);
        to_read = file_size;
    } catch(const std::exception& ex) {
        std::cerr << "\033[1;31m[ERROR]\033[0m FileManager::FindUser() >> Failed to calculate file size (" << path << ")" << std::endl;
        return false;
    }

    username.assign(username.size(), 0);
    file.read(reinterpret_cast<char*>(this->username.data()), username.size());
    to_read -= username.size();

    serialized_salt.assign(serialized_salt.size(), 0);
    file.read(reinterpret_cast<char*>(serialized_salt.data()), serialized_salt.size());
    to_read -= serialized_salt.size();

    #ifdef DEBUG
    std::cout << "FileManager::FindUser() >> SERIALIZED SALT: "<< serialized_salt.data() << std::endl;
    #endif
    
    password_digest.assign(password_digest.size(), 0);
    file.read(reinterpret_cast<char*>(password_digest.data()), password_digest.size());
    to_read -= password_digest.size();

    #ifdef DEBUG
    std::cout << "FileManager::FindUser() >> DIGEST PASSWORD + SALT: "<< password_digest.data() << std::endl;
    #endif

    // decifra amount
    std::vector<uint8_t> ciphertext(32, 0);
    std::vector<uint8_t> session_key(256);
    std::vector<uint8_t> iv(EVP_CIPHER_iv_length(EVP_aes_256_cbc()));
    session_key.assign(session_key.size(), 2);
    file.read(reinterpret_cast<char*>(ciphertext.data()), ciphertext.size());
    file.close();

    serialized_amount.assign(serialized_amount.size(), 0);
    try {
        AES_CBC decryptor(DECRYPT, session_key, true);
        decryptor.run(ciphertext, serialized_amount, iv);
    } catch(std::runtime_error& error) {
        std::cerr << error.what() << std::endl;
        return false;
    }
    return true;
}

// ritorna lo username in formato stringa 
std::string FileManager::GetUsername() {
    std::string username;
    username = vectorToString(this->username);
    return username;
}

// ritorna il salt in formato stringa 
std::string FileManager::GetSalt() {
    std::string string_salt;
    string_salt = vectorToString(this->serialized_salt);
    return string_salt;
}

int FileManager::GetAmount() {
    std::string string_amount;
    string_amount = vectorToString(this->serialized_amount);
    return std::stoi(string_amount);
}


bool FileManager::SetAmount(int new_amount) 
{
    std::ofstream file1(this->file_path, std::ios::binary);
    
    if (!file1) {
        std::cout << "non riesco a scrivere" << std::endl;
        return false;
    }

    // scrivi username
    file1.write(reinterpret_cast<const char*>(this->username.data()), username.size());
    //scrivi salt
    file1.write(reinterpret_cast<const char*>(this->serialized_salt.data()), serialized_salt.size());

    std::vector<uint8_t> vec0;
    std::string salted_password = GetUsername() + GetSalt();
    std::cout << "PASSWORD + SALT " << salted_password << std::endl;
    vec0.resize(50);
    vec0.assign(vec0.size(), 0);
    stringToVector(salted_password, vec0, 50);

    std::vector<uint8_t> digest;
    unsigned int digest_size;
    SHA_512::generate(reinterpret_cast<unsigned char*>(vec0.data()), vec0.size(), digest, digest_size);
    file1.write(reinterpret_cast<const char*>(digest.data()), digest_size );

    std::vector<uint8_t> cleartext;
    cleartext.resize(20);
    cleartext.assign(cleartext.size(), 0);
    std::string amountstr = std::to_string(new_amount);
    stringToVector(amountstr, cleartext, 20);


    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> session_key;
    std::vector<uint8_t> iv(EVP_CIPHER_iv_length(EVP_aes_256_cbc()));
    session_key.resize(256);
    session_key.assign(session_key.size(), 2);

    try {
        AES_CBC encryptor(ENCRYPT, session_key, true);
        encryptor.run(cleartext , ciphertext, iv);
    } catch (std::runtime_error& ex) {
        std::cerr << ex.what() << std::endl;
        return false;
    }

    file1.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    file1.close();
    return true;
}
