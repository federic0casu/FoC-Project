#include <ctime>
#include <vector>
#include <cstring>

#include <string.h>
#include <arpa/inet.h>

#define USER_SIZE   32 

struct List {
    uint16_t code_response;
    uint32_t amount;
    std::time_t timestamp;
    uint8_t dest[USER_SIZE];
 
    List(uint16_t code_response, uint32_t amount);
    List(uint16_t code_response, uint32_t amount, std::time_t timestamp);
    List(uint16_t code_response, uint32_t amount, uint8_t* username, size_t username_size, std::time_t timestamp);    
    void serialize(std::vector<uint8_t>& buffer);
    static List deserialize(const std::vector<uint8_t>& buffer);
};
