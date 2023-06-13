#include <ctime>
#inclide <string.h>
#include <arpa/inet.h>


#define LIST_REQUEST    0x03
#define LIST_RESPONSE_1 0x06
#define LIST_RESPONSE_2 0x07


struct plaintext {
    uint8_t buffer[sizeof(uint16_t) + sizeof(uint8_t[32]) + sizeof(uint32_t) + sizeof(std::time_t)]

    void serialize(uint16_t code);
    void serialize(uint16_t code, uint8_t dest[32], uint32_t amount, std::time_t timestamp);
    
    uint16_t deserialize_code();
    uint16_t deserialize_user(uint8_t* user);
    uint32_t deserialize_amount();
    uint32_t deserialize_timestamp();
    
};

typedef plaintext plaintext_t;

struct List_Request {
    uint16_t    code_request;
    plaintext_t buffer;
    
    List_Request();
    ~List_Request();
    void serialize();
    void deserialize();
};
