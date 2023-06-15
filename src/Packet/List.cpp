#include "List.hpp"


uint16_t deserialize_code(const std::vector<uint8_t>& buffer)
{
    uint16_t tmp;
    std::memcpy(reinterpret_cast<void*>(&tmp), buffer.data(), sizeof(uint16_t));

    return ntohs(tmp);
}

uint16_t deserialize_user(const std::vector<uint8_t>& buffer, uint8_t* user)
{
    const void* pointer = buffer.data() + sizeof(uint16_t);
    std::memcpy(reinterpret_cast<void*>(user), pointer, sizeof(uint8_t) * USER_SIZE);

    return sizeof(uint8_t) * USER_SIZE;
}

uint32_t deserialize_amount(const std::vector<uint8_t>& buffer)
{
    const void* pointer = buffer.data() + sizeof(uint16_t) + sizeof(uint8_t) * USER_SIZE;
    uint32_t tmp;
    std::memcpy(reinterpret_cast<void*>(&tmp), pointer, sizeof(uint32_t));

    return ntohl(tmp);
}

uint32_t deserialize_timestamp(const std::vector<uint8_t>& buffer)
{
    const void* pointer = buffer.data() + sizeof(uint16_t) + sizeof(uint8_t) * USER_SIZE + sizeof(uint32_t);
    uint32_t tmp;
    std::memcpy(reinterpret_cast<void*>(&tmp), pointer, sizeof(uint32_t));

    return ntohl(tmp);
}

List::List(uint16_t code_response, uint32_t amount)
    : code_response(code_response), amount(amount), timestamp(std::time(nullptr))
{
    uint8_t username[] = "*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*";
    std::memcpy(reinterpret_cast<void*>(dest), reinterpret_cast<void*>(username), sizeof(uint8_t) * USER_SIZE);
}

List::List(uint16_t code_response, uint32_t amount, std::time_t timestamp)
    : code_response(code_response), amount(amount), timestamp(timestamp)
{
    uint8_t username[] = "*******************************";
    std::memcpy(reinterpret_cast<void*>(dest), reinterpret_cast<void*>(username), sizeof(uint8_t) * USER_SIZE);
}

List::List(uint16_t code_response, uint32_t amount, uint8_t* username, size_t username_size, std::time_t timestamp)
    : code_response(code_response), amount(amount), timestamp(timestamp)
{
    ssize_t bytes = (username_size < USER_SIZE) ? username_size : USER_SIZE;
    std::memcpy(reinterpret_cast<void*>(dest), reinterpret_cast<void*>(username), sizeof(uint8_t) * bytes);
}

void List::serialize(std::vector<uint8_t>& buffer)
{
    buffer.clear();

    uint16_t code_to_send = htons(code_response);
    buffer.insert(buffer.end(), reinterpret_cast<const uint8_t*>(&code_to_send), reinterpret_cast<const uint8_t*>(&code_to_send) + sizeof(uint16_t));

    buffer.insert(buffer.end(), dest, (dest + sizeof(uint8_t[USER_SIZE])));

    uint32_t amount_to_send = htonl(amount);
    buffer.insert(buffer.end(), reinterpret_cast<const uint8_t*>(&amount_to_send), reinterpret_cast<const uint8_t*>(&amount_to_send) + sizeof(uint32_t));

    uint32_t timestamp_to_send = htonl(timestamp);
    buffer.insert(buffer.end(), reinterpret_cast<const uint8_t*>(&timestamp_to_send), reinterpret_cast<const uint8_t*>(&timestamp_to_send) + sizeof(uint32_t));
}

List List::deserialize(const std::vector<uint8_t>& buffer)
{
    auto code_response = deserialize_code(buffer);
    auto amount = deserialize_amount(buffer);
    auto timestamp = static_cast<std::time_t>(deserialize_timestamp(buffer));

    List tmp(code_response, amount, timestamp);
    deserialize_user(buffer, tmp.dest);

    return tmp;
}
