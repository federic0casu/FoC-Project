#include <ctime>
#include <string.h>
#include <arpa/inet.h>

#include <iostream>

#define USER_SIZE   32
#define BUFFER_SIZE sizeof(uint16_t) + sizeof(uint8_t[USER_SIZE]) + sizeof(uint32_t) + sizeof(std::time_t) 

struct List {
    uint16_t    code_response;
    uint8_t*    dest = NULL;
    uint32_t    amount;
    std::time_t timestamp;
    
    List(uint16_t v1, uint32_t v2);
    List(uint16_t v1, uint32_t v2, std::time_t v3);
    List(uint16_t v1, uint32_t v2, uint8_t* c1, size_t c1_size, std::time_t v3);

    ~List() { if(dest != NULL) delete[] dest; };
    
    void serialize(uint8_t* buffer);
    static List deserialize(uint8_t* buffer);
};
