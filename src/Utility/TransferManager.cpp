#include "TransferManager.hpp"

#include "../Crypto/AES_CBC.hpp"

bool TransferManager::writeTransfer(std::string file_path, int amount_to_write, std::string recipient) {
    std::ofstream file(file_path, std::ios::app);
    std::vector<uint8_t> timestamp;
    
    if (!file) {
        std::cout << "errore nell apertura del file " << std::endl;
        return false;
    }

    // ottengo il tempo attuale
    auto now = std::chrono::system_clock::now();
    // Calcola il timestamp in millisecondi
    time_t ts = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    // Converti il timestamp in una stringa
    std::ostringstream oss;
    oss << ts;
    std::string timestamp_str = oss.str();
    
    // stringa finale da cifrare
    std::string data = recipient + ":" + std::to_string(amount_to_write) + ":" + timestamp_str;

    // cleartext di dimensione fissata su cui scrivo la stringa
    std::vector<uint8_t> cleartext;
    cleartext.resize(CLEARTEXT_DIM);
    cleartext.assign(cleartext.size(), 0);
    // inizializzo il cleartext con la stringa
    stringToVector(data, cleartext, CLEARTEXT_DIM);

    // cifra il cleartext
    std::vector<uint8_t> iv(EVP_CIPHER_iv_length(EVP_aes_256_cbc()));
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> session_key;
    session_key.resize(256);
    session_key.assign(session_key.size(), 2);
    AES_CBC* encryptor = new AES_CBC(ENCRYPT, session_key, true);
    encryptor->run(cleartext, ciphertext, iv);
    std::cout << "TransferHandler(), dimensione del ciphertext: " <<  ciphertext.size() << std::endl; 
    

    // scrivi su file
    file.write(reinterpret_cast<const char *>(ciphertext.data()), ciphertext.size());
    file.close();
    
    std::cout << "TransferManager(): Scrittura sul file completata." << std::endl;
}


// da modificare, deve prendere un buffer a file, decifrare 96 byte dal file e ritornare la stringa decifrata
bool TransferManager:: readTransfer(std::string file_path) {

    std::ifstream file(file_path);
    if (!file){
        std::cout << "readTransfer(): non sono riuscito ad aprire il file per leggere" << std::endl;
        return false;
    }

    std::vector<uint8_t> ciphertext(CIPHERTEXT_DIM);
    file.read(reinterpret_cast<char*>(ciphertext.data()), CIPHERTEXT_DIM);
    
    // dopo aver letto una transfer cifrata, decifrala
    std::vector<uint8_t> cleartext;
    std::vector<uint8_t> session_key;
    std::vector<uint8_t> iv(EVP_CIPHER_iv_length(EVP_aes_256_cbc()));
    session_key.resize(256);
    session_key.assign(session_key.size(), 2);  
    AES_CBC* decryptor = new AES_CBC(DECRYPT, session_key, true);
    decryptor->run(ciphertext,cleartext , iv);

    std::string cleartext_str(reinterpret_cast<char*>(cleartext.data()), cleartext.size());
    std::cout << "readTransfer: " << cleartext.data() << std::endl;

}

// da mettere funzione che conta quanti transfer ho in un file
int TransferManager::getTransferCount(std::string file_path) {
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file) {
        std::cout << "Impossibile aprire il file." << std::endl;
        return -1; // Errore nell'apertura del file
    }

    std::streampos size = file.tellg(); // Ottieni la posizione corrente (che è la dimensione del file)
    file.close();

    return static_cast<int>(size)/CIPHERTEXT_DIM;
}

std::string TransferManager::readNextTransfer(int row_pos, std::string file_path) {

    std::ifstream file(file_path);
    file.seekg(row_pos * CIPHERTEXT_DIM, std::ios::beg);

    
    std::vector<uint8_t> ciphertext(CIPHERTEXT_DIM);
    file.read(reinterpret_cast<char*>(ciphertext.data()), CIPHERTEXT_DIM);
    
    // dopo aver letto una transfer cifrata, decifrala
    std::vector<uint8_t> cleartext;
    std::vector<uint8_t> session_key;
    std::vector<uint8_t> iv(EVP_CIPHER_iv_length(EVP_aes_256_cbc()));
    session_key.resize(256);
    session_key.assign(session_key.size(), 2);  
    AES_CBC* decryptor = new AES_CBC(DECRYPT, session_key, true);
    decryptor->run(ciphertext,cleartext , iv);

    std::string cleartext_str(reinterpret_cast<char*>(cleartext.data()), cleartext.size());
    std::cout << "readNextTransfer: " << cleartext.data() << std::endl;

    delete decryptor;
    file.close();

    return cleartext_str;
}