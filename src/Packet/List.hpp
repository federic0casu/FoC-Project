#include <ctime>
#include <string.h>
#include <arpa/inet.h>

#define USER_SIZE   32
#define BUFFER_SIZE sizeof(uint16_t) + sizeof(uint8_t[USER_SIZE]) + sizeof(uint32_t) + sizeof(std::time_t) 

struct List {
    uint16_t    code_response;
    uint8_t     dest[USER_SIZE];
    uint32_t    amount;
    std::time_t timestamp;
    
    List(int v1, uint32_t v2) : code_response(v1), amount(v2) {}
    List(int v1, uint32_t v2, std::time_t v3) : code_response(v1), amount(v2), timestamp(v3) {}
    
    void set_dest(uint8_t* username, ssize_t username_size);
    
    void serialize(uint8_t* buffer);
    void deserialize(uint8_t* buffer);
};
