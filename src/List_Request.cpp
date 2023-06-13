#include "List_Request.hpp"

void plaintext::serialize(uint16_t code)
{
    uint16_t code_to_send = htons(code);
    memcpy(&buffer[0], &code_to_send, (size_t) sizeof(uint16_t);
}

void plaintext::serialize(uint16_t code, uint8_t dest[32], uint32_t amount, std::time_t timestamp)
{
    void* pointer = (void*) &buffer[0];

    uint16_t code_to_send = htons(code);
    memcpy(pointer, (void*) &code_to_send, (size_t) sizeof(uint16_t);
    pointer += sizeof(uint16_t);

    memcpy(pointer, (void*) &dest[0], (size_t) sizeof(uint8_t[32]);
    pointer += sizeof(uint8_t[32]);

    memcpy(pointer, (void*) &amount, (size_t) sizeof(uint32_t);
    pointer += sizeof(uint32_t);

    uint32_t timestamp_to_send = htonl(timestamp);
    memcpy(pointer, (void*) &timestamp_to_send, sizeof(uint32_t));
}

uint16_t plaintext::deserialize_code()
{
    void* pointer = (void*) &buffer[0];
    uint16_t tmp;
    memcpy((void*) &tmp, pointer, sizeof(uint16_t));
    
    return ntohs(tmp);
}

uint16_t plaintext::deserialize_user(uint8_t* user)
{
    void* pointer = (void*) (&buffer[0] + sizeof(uint16_t));
    memcpy((void*) user, pointer, (size_t) sizeof(uint8_t[32]));

    return sizeof(uint8_t[32]);
}


List_Request::List_Request() 
{
    code_request = LIST_REQUEST;
}

List_Request::~List_Request() {}

void List_Request::serialize() 
{
    buffer.serialize(code_request);
}

void List_Requeste::deserialize()
{
}
