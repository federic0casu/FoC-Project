#include <mutex>
#include <string>
#include <atomic>
#include <thread>
#include <vector>
#include <csignal>
#include <cstring>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <iostream>
#include <stdexcept>
#include <algorithm>

#include <unistd.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "../Generic/Utility.hpp"

#define AMOUNT_DIM          32
#define USERNAME_DIM        30
#define PASS_DIGEST_DIM     64
#define SERIALIZED_SALT_DIM 20

class FileManager {
    public:
    std::vector<uint8_t> username;
    std::vector<uint8_t> serialized_salt;
    std::vector<uint8_t> password_digest;
    std::vector<uint8_t> serialized_amount;
    std::string file_path;

    
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
    
    bool FindUser(std::string file_path);
    std::string GetUsername();
    std::string GetSalt();
    int GetAmount();
    bool SetAmount(int new_amount);
};
