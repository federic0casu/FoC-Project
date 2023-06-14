#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <iostream>

#include "../Generic/Codes.hpp"
#include "../Generic/Utility.hpp"

/*------------------------- Request Message ------------------------ */

struct ClientReq {

  uint16_t  request_code;
  uint8_t   recipient[RECIPIENT_SIZE];
  uint32_t  amount;

  ClientReq() {}

  ClientReq(uint16_t request_code, uint32_t amount)
  {
    this->request_code = request_code;
    this->amount = amount;
  }

  ClientReq(uint16_t request_code, uint32_t amount, uint8_t* recipient)
  {
    this->request_code = request_code;
    memcpy((void*) this->recipient, (void*) recipient, RECIPIENT_SIZE);
    this->amount = amount;    
  }

  void serialize(std::vector<uint8_t>& buffer)
  {
    size_t position = 0;

    request_code = htons(request_code);
    buffer.resize(position + sizeof(uint16_t));
    std::memcpy(buffer.data() + position, &request_code, sizeof(uint16_t));
    position += sizeof(uint16_t);

    buffer.resize(position + sizeof(uint8_t) * RECIPIENT_SIZE);
    std::memcpy(buffer.data() + position, &recipient, sizeof(uint8_t) * RECIPIENT_SIZE);
    position += sizeof(uint8_t) * RECIPIENT_SIZE;

    amount = htonl(amount);
    buffer.resize(position + sizeof(uint32_t));
    std::memcpy(buffer.data() + position, &amount, sizeof(uint32_t));
  }


  static ClientReq deserialize(const std::vector<uint8_t>& buffer)
  {
    ClientReq req;

    size_t position = 0;

    std::memcpy(&req.request_code, buffer.data(), sizeof(uint16_t));
    req.request_code = ntohs(req.request_code);
    position += sizeof(uint16_t);

    std::memcpy(&req.recipient, buffer.data() + position, sizeof(uint8_t) * RECIPIENT_SIZE);
    position += sizeof(uint8_t) * RECIPIENT_SIZE;

    std::memcpy(&req.amount, buffer.data() + position, sizeof(uint32_t));
    req.amount = ntohl(req.amount);

    return req;
  }

  uint32_t get_size() 
  {
    return sizeof(request_code) + sizeof(recipient) + sizeof(amount);
  }

};
