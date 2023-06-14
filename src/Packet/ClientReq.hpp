#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <openssl/rand.h>

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

  void serialize(uint8_t* buffer)
  {
    size_t position = 0;
   
    request_code = htons(request_code);
    memcpy(buffer, &request_code, sizeof(uint16_t));
    position += sizeof(uint16_t);

    memcpy(buffer + position, &recipient, sizeof(uint8_t[RECIPIENT_SIZE]));
    position += sizeof(uint8_t[RECIPIENT_SIZE]);

    amount = htonl(amount);
    memcpy(buffer + position, &amount, sizeof(uint32_t));
  }

  static ClientReq deserialize(uint8_t* buffer) 
  {
    ClientReq req;
    
    size_t position = 0;

    memcpy(&req.request_code, buffer, sizeof(uint16_t));
    req.request_code = ntohs(req.request_code);
    position += sizeof(uint16_t);
    
    memcpy(&req.recipient, buffer + position, sizeof(uint8_t[RECIPIENT_SIZE]));
    position += sizeof(uint8_t[RECIPIENT_SIZE]);
    
    memcpy(&req.amount, buffer + position,sizeof(uint32_t));
    req.amount = ntohl(req.amount);

    return req;
  }

  uint32_t get_size() 
  {
    return sizeof(request_code) + sizeof(recipient) + sizeof(amount);
  }

};
