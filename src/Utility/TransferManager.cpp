#include "TransferManager.hpp"

#include "../Crypto/AES_CBC.hpp"

bool TransferManager::writeTransfer(std::string file_path, int amount_to_write, std::string recipient) {
    std::ofstream file(file_path, std::ios::app);
    
    if (!file) {
        std::cerr << "\033[1;31m[ERROR]\033[0m TransferManager::writeTransfer() >> Failed to open file." << std::endl;
        return false;
    }

    // ottengo il tempo attuale
    auto now = std::time(nullptr);
    
    // stringa finale da cifrare
    std::string data = recipient + ":" + std::to_string(amount_to_write) + ":" + std::to_string(static_cast<long>(now));

    // cleartext di dimensione fissata su cui scrivo la stringa
    std::vector<uint8_t> cleartext(CLEARTEXT_DIM, 0);
    // inizializzo il cleartext con la stringa
    stringToVector(data, cleartext, CLEARTEXT_DIM);

    // cifra il cleartext
    std::vector<uint8_t> iv(EVP_CIPHER_iv_length(EVP_aes_256_cbc()));
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> session_key(256, 2);

    try {
        AES_CBC encryptor(ENCRYPT, session_key, true);
        encryptor.run(cleartext, ciphertext, iv); 
    } catch(const std::runtime_error& ex) {
        std::cerr << ex.what() << std::endl;

        return false;
    }

    // scrivi su file
    file.write(reinterpret_cast<const char *>(ciphertext.data()), ciphertext.size());
    file.close();

    return true;
}


// da modificare, deve prendere un buffer a file, decifrare 96 byte dal file e ritornare la stringa decifrata
bool TransferManager:: readTransfer(std::string file_path) {

    std::ifstream file(file_path);
    if (!file){
        std::cerr << "\033[1;31m[ERROR]\033[0m TransferManager::readTransfer() >> Failed to open file." << std::endl;
        return false;
    }

    std::vector<uint8_t> ciphertext(CIPHERTEXT_DIM);
    file.read(reinterpret_cast<char*>(ciphertext.data()), CIPHERTEXT_DIM);
    
    // dopo aver letto una transfer cifrata, decifrala
    std::vector<uint8_t> cleartext;
    std::vector<uint8_t> session_key(256, 2);
    std::vector<uint8_t> iv(EVP_CIPHER_iv_length(EVP_aes_256_cbc())); 

    try {
        AES_CBC decryptor(DECRYPT, session_key, true);
        decryptor.run(ciphertext,cleartext , iv);
    } catch(const std::runtime_error& ex) {
        std::cerr << ex.what() << std::endl;

        return false;
    }

    std::string cleartext_str(reinterpret_cast<char*>(cleartext.data()), cleartext.size());

    return true;
}

// da mettere funzione che conta quanti transfer ho in un file
int TransferManager::getTransferCount(std::string file_path) {
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);

    if (!file) {
        std::cerr << "\033[1;31m[ERROR]\033[0m TransferManager::getTransferCount() >> Failed to open file." << std::endl;
        return -1; // Errore nell'apertura del file
    }

    std::streampos size = file.tellg(); // Ottieni la posizione corrente (che è la dimensione del file)
    file.close();

    return (static_cast<int>(size) / CIPHERTEXT_DIM);
}

std::string TransferManager::readNextTransfer(int row_pos, std::string file_path) {

    std::ifstream file(file_path);

    if (!file) {
        std::cerr << "\033[1;31m[ERROR]\033[0m TransferManager::readNextTransfer() >> Failed to open file." << std::endl;
        return std::string(""); // Errore nell'apertura del file
    }

    file.seekg(row_pos * CIPHERTEXT_DIM, std::ios::beg);

    std::vector<uint8_t> ciphertext(CIPHERTEXT_DIM);
    file.read(reinterpret_cast<char*>(ciphertext.data()), CIPHERTEXT_DIM);
    
    // dopo aver letto una transfer cifrata, decifrala
    std::vector<uint8_t> cleartext;
    std::vector<uint8_t> session_key(256, 2);
    std::vector<uint8_t> iv(EVP_CIPHER_iv_length(EVP_aes_256_cbc()));

    try {
        AES_CBC decryptor(DECRYPT, session_key, true);
        decryptor.run(ciphertext,cleartext , iv);
    } catch(const std::runtime_error& ex) {
        std::cerr << ex.what() << std::endl;

        return std::string("");
    }

    std::string cleartext_str(reinterpret_cast<char*>(cleartext.data()));

    file.close();

    return cleartext_str;
}