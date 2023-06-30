#include <ctime>
#include <vector>
#include <iomanip>
#include <cstring>
#include <stdexcept>

#include <string.h>
#include <arpa/inet.h>

#include "../Generic/Codes.hpp"

struct PasswordMessage {
    uint8_t password[PASSWORD_SIZE];
    uint32_t counter;

    PasswordMessage() {}

    PasswordMessage(const char* password, uint32_t counter) 
    {
        memset(this->password, 0, PASSWORD_SIZE);
        memcpy(this->password, password, PASSWORD_SIZE);
        this->counter = counter;
    }

    void serialize(std::vector<uint8_t>& buffer) 
    {
        size_t position = 0;

        std::memcpy(reinterpret_cast<void*>(buffer.data()), this->password, PASSWORD_SIZE);
        position += PASSWORD_SIZE;

        this->counter = htonl(this->counter);
        std::memcpy(reinterpret_cast<void*>(buffer.data() + position), &this->counter, sizeof(uint32_t));
    }

    static PasswordMessage deserialize(const std::vector<uint8_t>& buffer) 
    {
        PasswordMessage passwordMessage;

        size_t position = 0;

        std::memcpy(reinterpret_cast<void*>(&passwordMessage.password), reinterpret_cast<const void*>(buffer.data()), PASSWORD_SIZE);
        position += PASSWORD_SIZE;

        std::memcpy(reinterpret_cast<void*>(&passwordMessage.counter), reinterpret_cast<const void*>(buffer.data() + position), sizeof(uint32_t));
        passwordMessage.counter = ntohl(passwordMessage.counter);

        return passwordMessage;
    }
};
