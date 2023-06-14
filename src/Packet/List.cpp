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

List::List(uint16_t code_response, uint32_t amount)
{
    this->code_response = code_response;
    this->amount = amount;
    this->timestamp = std::time(NULL);
    this->dest = new uint8_t[USER_SIZE];

    if(this->dest != NULL)
    {
        uint8_t username[] = "***********************************";
        memcpy((void*) this->dest, (void*) username, USER_SIZE);
    }
}

List::List(uint16_t code_response, uint32_t amount, std::time_t timestamp)
{
    this->code_response = code_response;
    this->amount = amount;
    this->timestamp = timestamp;
    this->dest = new uint8_t[USER_SIZE];

    if(this->dest != NULL)
    {
        uint8_t username[] = "*******************************";
        memcpy((void*) this->dest, (void*) username, USER_SIZE);
    }
}

List::List(uint16_t code_response, uint32_t amount, uint8_t* username, size_t username_size, std::time_t timestamp)
{
    this->code_response = code_response;
    this->amount = amount;
    this->timestamp = timestamp;
    this->dest = new uint8_t[USER_SIZE];

    if(this->dest != NULL)
    {
        ssize_t bytes = (username_size < USER_SIZE) ? username_size : USER_SIZE;
        memcpy((void*) this->dest, (void*) username, bytes);
    }
}

void List::serialize(uint8_t* buffer) 
{
    size_t position = 0;

    uint16_t code_to_send = htons(code_response);
    memcpy((void*) buffer, (void*) &code_to_send, (size_t) sizeof(uint16_t));
    position += sizeof(uint16_t);

    memcpy((void*) (buffer + position), (void*) dest, (size_t) sizeof(uint8_t[USER_SIZE]));
    position += sizeof(uint8_t[USER_SIZE]);

    uint32_t amount_to_send = htonl(amount);
    memcpy((void*) (buffer + position), (void*) &amount_to_send, (size_t) sizeof(uint32_t));
    position += sizeof(uint32_t);

    uint32_t timestamp_to_send = htonl(timestamp);
    memcpy((void*) (buffer + position), (void*) &timestamp_to_send, sizeof(uint32_t));

}

List List::deserialize(uint8_t* buffer)
{
    auto code_response = deserialize_code(buffer);
    auto amount = deserialize_amount(buffer);
    auto timestamp = (std::time_t) deserialize_timestamp(buffer);

    List tmp(code_response, amount, timestamp);
    deserialize_user(buffer, tmp.dest);

    return tmp;
}
