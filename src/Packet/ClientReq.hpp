#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <iostream>

#include "../Generic/Codes.hpp"
#include "../Generic/Utility.hpp"


struct ClientReq {

  uint16_t  request_code;
  uint8_t   recipient[RECIPIENT_SIZE];
  uint32_t  amount;
  uint32_t  counter;

  ClientReq() {}

  ClientReq(uint16_t __request_code, uint32_t __amount, uint32_t __counter)
      : request_code(__request_code), amount(__amount), counter(__counter) {}

  ClientReq(uint16_t __request_code, uint32_t __amount, const char* recipient, uint32_t __counter)
      : request_code(__request_code), amount(__amount), counter(__counter) 
  {
    std::memcpy(reinterpret_cast<void*>(this->recipient), reinterpret_cast<const void*>(recipient), RECIPIENT_SIZE); 
  }

  void serialize(std::vector<uint8_t>& buffer)
  {
    size_t position = 0;

    request_code = htons(request_code);
    buffer.resize(position + sizeof(uint16_t));
    std::memcpy(reinterpret_cast<void*>(buffer.data() + position), reinterpret_cast<const void*>(&request_code), sizeof(uint16_t));
    position += sizeof(uint16_t);

    buffer.resize(position + sizeof(uint8_t) * RECIPIENT_SIZE);
    std::memcpy(reinterpret_cast<void*>(buffer.data() + position), reinterpret_cast<const void*>(&recipient), sizeof(uint8_t) * RECIPIENT_SIZE);
    position += sizeof(uint8_t) * RECIPIENT_SIZE;

    amount = htonl(amount);
    buffer.resize(position + sizeof(uint32_t));
    std::memcpy(reinterpret_cast<void*>(buffer.data() + position), reinterpret_cast<const void*>(&amount), sizeof(uint32_t));
    position += sizeof(uint32_t);

    counter = htonl(counter);
    buffer.resize(position + sizeof(uint32_t));
    std::memcpy(reinterpret_cast<void*>(buffer.data() + position), reinterpret_cast<const void*>(&counter), sizeof(uint32_t));
  }


  static ClientReq deserialize(const std::vector<uint8_t>& buffer)
  {
    ClientReq req;

    size_t position = 0;

    std::memcpy(reinterpret_cast<void*>(&req.request_code), reinterpret_cast<const void*>(buffer.data()), sizeof(uint16_t));
    req.request_code = ntohs(req.request_code);
    position += sizeof(uint16_t);

    std::memcpy(reinterpret_cast<void*>(&req.recipient), reinterpret_cast<const void*>(buffer.data() + position), sizeof(uint8_t) * RECIPIENT_SIZE);
    position += sizeof(uint8_t) * RECIPIENT_SIZE;

    std::memcpy(reinterpret_cast<void*>(&req.amount), reinterpret_cast<const void*>(buffer.data() + position), sizeof(uint32_t));
    req.amount = ntohl(req.amount);
    position += sizeof(uint32_t);

    std::memcpy(reinterpret_cast<void*>(&req.counter), reinterpret_cast<const void*>(buffer.data() + position), sizeof(uint32_t));
    req.counter = ntohl(req.counter);

    return req;
  }

  uint32_t get_size() 
  {
    return sizeof(request_code) + sizeof(recipient) + sizeof(amount) + sizeof(counter);
  }

};
