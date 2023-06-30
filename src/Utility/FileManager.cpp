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
    
    password_digest.assign(password_digest.size(), 0);
    file.read(reinterpret_cast<char*>(password_digest.data()), password_digest.size());
    to_read -= password_digest.size();

    // decifra amount
    std::vector<uint8_t> ciphertext(32, 0);
    std::vector<uint8_t> session_key(32);
    session_key.assign(session_key.size(), 2);
    std::vector<uint8_t> iv(EVP_CIPHER_iv_length(EVP_aes_256_cbc()));
    file.read(reinterpret_cast<char*>(ciphertext.data()), ciphertext.size());
    file.close();

    serialized_amount.assign(serialized_amount.size(), 0);
    try {
        AES_CBC decryptor(DECRYPT, session_key, true);
        decryptor.run(ciphertext, serialized_amount, iv);
    } catch(const std::runtime_error& ex) {
        std::cerr << ex.what() << std::endl;
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
    std::ofstream file(this->file_path, std::ios::binary);
    
    if (!file) {
        std::cerr << "\033[1;31m[ERROR]\033[0m FileManager::SetAmount() >> Failed to open file." << std::endl;
        return false;
    }

    // scrivi username
    file.write(reinterpret_cast<const char*>(this->username.data()), username.size());
    
    // scrivi salt
    file.write(reinterpret_cast<const char*>(this->serialized_salt.data()), serialized_salt.size());

    // scrivi h(password + salt)
    file.write(reinterpret_cast<const char*>(this->password_digest.data()), this->password_digest.size());

    std::vector<uint8_t> cleartext(20, 0);
    std::string amountstr = std::to_string(new_amount);
    stringToVector(amountstr, cleartext, 20);

    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> session_key(32, 2);
    std::vector<uint8_t> iv(EVP_CIPHER_iv_length(EVP_aes_256_cbc()));

    try {
        AES_CBC encryptor(ENCRYPT, session_key, true);
        encryptor.run(cleartext , ciphertext, iv);
    } catch (std::runtime_error& ex) {
        std::cerr << ex.what() << std::endl;
        file.close();
        return false;
    }

    file.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    file.close();
    return true;
}

bool FileManager::CheckPasswordValidity(std::string password) {

    // apri il file
    std::ifstream file(this->file_path, std::ios::binary);

    if(!file) {
         std::cerr << "\033[1;31m[ERROR]\033[0m FileManager::CheckPasswordValidity() >> Failed to open file." << std::endl;
        return false;
    }

    size_t length1 = password.find_first_of('\n');
    std::string salted_password = password.substr(0, length1) + GetSalt();

    std::vector<uint8_t> vec0(50, 0);
    stringToVector(salted_password, vec0, 50);

    file.seekg(USERNAME_DIM + SERIALIZED_SALT_DIM, std::ios::beg);
    int digest_size = 64;
    std::vector<uint8_t> digest(64);
    digest.assign(digest.size(), 0);
    file.read(reinterpret_cast<char*>(digest.data()), digest.size());

    bool result =  SHA_512::verify(reinterpret_cast<unsigned char*>(vec0.data()), vec0.size(), digest.data());

    return result;
}
