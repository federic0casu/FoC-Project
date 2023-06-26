#include <mutex>
#include <string>
#include <atomic>
#include <vector>
#include <fstream>
#include <sstream>
#include <iostream>
#include <stdexcept>
#include <algorithm>

#include <unistd.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fstream>

#define AMOUNT_DIM 32
#define USERNAME_DIM 30
#define CLEARTEXT_DIM 80
#define CIPHERTEXT_DIM 96
#define PASS_DIGEST_DIM 64
#define SERIALIZED_SALT_DIM 20


class TransferManager {
public:
    TransferManager() {}
    bool writeTransfer(std::string file_path,int amount_to_write, std::string recipient);
    bool readTransfer(std::string file_path);
    int getTransferCount(std::string file_path);
    std::string readNextTransfer(int row_position, std::string file_path);

    static void stringToVector(std::string &str, std::vector<uint8_t> &vec, long unsigned int size) {
        for (long unsigned int i = 0; i < size && i < str.length(); i++)
            vec[i] = static_cast<uint8_t>(str[i]);
    }

    static std::string vectorToString(std::vector<uint8_t> vec) {
            std::string str;
            for (const auto& elem : vec)
                str += static_cast<char>(elem);
            return str;
    }

private:
    std::string file_path; 
};
