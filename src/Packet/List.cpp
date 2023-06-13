#include "List.hpp"


void plaintext::serialize(uint16_t code, uint8_t dest[USER_SIZE], uint32_t amount, std::time_t timestamp)
{
    uint8_t* pointer = &buffer[0];

    uint16_t code_to_send = htons(code);
    memcpy((void*) pointer, (void*) &code_to_send, (size_t) sizeof(uint16_t));
    pointer += sizeof(uint16_t);

    memcpy((void*) pointer, (void*) &dest[0], (size_t) sizeof(uint8_t[USER_SIZE]));
    pointer += sizeof(uint8_t[USER_SIZE]);

    memcpy((void*) pointer, (void*) &amount, (size_t) sizeof(uint32_t));
    pointer += sizeof(uint32_t);

    uint32_t timestamp_to_send = htonl(timestamp);
    memcpy((void*) pointer, (void*) &timestamp_to_send, sizeof(uint32_t));
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
    memcpy((void*) user, pointer, (size_t) sizeof(uint8_t[USER_SIZE]));

    return sizeof(uint8_t[USER_SIZE]);
}

uint32_t plaintext::deserialize_amount()
{
    void* pointer = (void*) (&buffer[0] + sizeof(uint16_t) + sizeof(uint8_t[USER_SIZE]));
    uint32_t tmp;
    memcpy((void*) &tmp, pointer, sizeof(uint32_t));
    
    return ntohl(tmp);
}

uint32_t plaintext::deserialize_timestamp()
{
    void* pointer = (void*) (&buffer[0] + sizeof(uint16_t) + sizeof(uint8_t[USER_SIZE]) + sizeof(uint32_t));
    uint32_t tmp;
    memcpy((void*) &tmp, pointer, sizeof(uint32_t));
    
    return ntohl(tmp);
}

void List::set_dest(uint8_t* username, ssize_t username_size)
{
    ssize_t bytes = (username_size < USER_SIZE) ? username_size : USER_SIZE;
    memcpy((void*) dest, (void*) username, bytes);
}

void List::serialize() 
{
    buffer.serialize(code_response, dest, amount, timestamp);
}

void List::deserialize()
{
    code_response = buffer.deserialize_code();
    buffer.deserialize_user(dest);
    amount = buffer.deserialize_amount();
    timestamp = (std::time_t) buffer.deserialize_timestamp();
}
