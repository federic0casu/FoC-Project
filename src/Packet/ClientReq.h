#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <openssl/rand.h>

#include "../Generic/Codes.h"


using namespace std;

#define RECIPIENT_SIZE 32
/*------------------------- Request Message ------------------------ */

struct ClientReq {

  uint8_t   request_code;
  uint8_t   recipient[RECIPIENT_SIZE];
  uint32_t  amount;

  ClientReq() {}

  ClientReq(uint32_t amount, uint8_t recipient[RECIPIENT_SIZE]) {
    this->request_code = CODE_BALANCE;
    memcpy(this->recipient,recipient,RECIPIENT_SIZE);
    this->amount = amount;    
  }

  uint8_t* serialize() const {
    uint8_t* buffer = new uint8_t[REQUEST_PACKET_SIZE];
    size_t position = 0;
    
    memcpy(buffer,&request_code, sizeof(uint8_t));
    position += sizeof(uint8_t);

    memcpy(buffer + position, &recipient, sizeof(uint8_t)*RECIPIENT_SIZE);
    position += sizeof(uint8_t) * RECIPIENT_SIZE;

    memcpy(buffer + position, &amount, sizeof(uint32_t));

    return buffer;
  }

  static ClientReq deserialize(uint8_t* buffer) {
    ClientReq req;
    
    size_t position = 0;

    memcpy(&req.request_code,buffer,sizeof(uint8_t));
    position += sizeof(uint8_t);
    
    memcpy(&req.recipient,buffer + position,sizeof(uint8_t)*RECIPIENT_SIZE);
    position += sizeof(uint8_t)*RECIPIENT_SIZE;
    
    memcpy(&req.amount,buffer + position,sizeof(uint32_t));

    return req;
  }

  uint32_t getSize() {
    return sizeof(request_code) + sizeof(recipient) + sizeof(amount);
  }

};