#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <openssl/rand.h>

#include "../Generic/Codes.h"


using namespace std;

#define RECIPIENT_SIZE 32
/*------------------------- Message 1 of Balance() ------------------------ */

struct ClientReq {

  uint8_t   request_code;
  uint8_t   recipient[RECIPIENT_SIZE];
  uint32_t  amount;

  ClientReq() {

  }

  ClientReq(uint32_t amount, uint32_t recipient[RECIPIENT_SIZE]) {
    this->request_code = CODE_BALANCE;
    memcpy(this->recipient,recipient,RECIPIENT_SIZE);
    this->amout = amount;    
  }
  
}