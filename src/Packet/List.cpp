#include "List.hpp"

uint16_t deserialize_code(uint8_t* buffer)
{
    uint16_t tmp;
    memcpy((void*) &tmp, buffer, sizeof(uint16_t));
    
    return ntohs(tmp);
}

uint16_t deserialize_user(uint8_t* buffer, uint8_t* user)
{
    void* pointer = (void*) (buffer + sizeof(uint16_t));
    memcpy((void*) user, pointer, (size_t) sizeof(uint8_t[USER_SIZE]));

    return sizeof(uint8_t[USER_SIZE]);
}

uint32_t deserialize_amount(uint8_t* buffer)
{
    void* pointer = (void*) (buffer + sizeof(uint16_t) + sizeof(uint8_t[USER_SIZE]));
    uint32_t tmp;
    memcpy((void*) &tmp, pointer, sizeof(uint32_t));
    
    return ntohl(tmp);
}

uint32_t deserialize_timestamp(uint8_t* buffer)
{
    void* pointer = (void*) (buffer + sizeof(uint16_t) + sizeof(uint8_t[USER_SIZE]) + sizeof(uint32_t));
    uint32_t tmp;
    memcpy((void*) &tmp, pointer, sizeof(uint32_t));
    
    return ntohl(tmp);
}

void List::set_dest(uint8_t* username, ssize_t username_size)
{
    ssize_t bytes = (username_size < USER_SIZE) ? username_size : USER_SIZE;
    memcpy((void*) dest, (void*) username, bytes);
}

void List::serialize(uint8_t* buffer) 
{
    uint16_t code_to_send = htons(code_response);
    memcpy((void*) buffer, (void*) &code_to_send, (size_t) sizeof(uint16_t));
    buffer += sizeof(uint16_t);

    memcpy((void*) buffer, (void*) &dest[0], (size_t) sizeof(uint8_t[USER_SIZE]));
    buffer += sizeof(uint8_t[USER_SIZE]);

    memcpy((void*) buffer, (void*) &amount, (size_t) sizeof(uint32_t));
    buffer += sizeof(uint32_t);

    uint32_t timestamp_to_send = htonl(timestamp);
    memcpy((void*) buffer, (void*) &timestamp_to_send, sizeof(uint32_t));

}

void List::deserialize(uint8_t* buffer)
{
    code_response = deserialize_code(buffer);
    deserialize_user(buffer, dest);
    amount = deserialize_amount(buffer);
    timestamp = (std::time_t) deserialize_timestamp(buffer);
}
