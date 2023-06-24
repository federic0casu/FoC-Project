#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <openssl/rand.h>

#include "../Generic/Codes.hpp"

using namespace std;

struct BalanceResponse {


  uint32_t balance;
  uint32_t counter;
  
  BalanceResponse() {}

  BalanceResponse(uint32_t counter, uint32_t balance){
    this->balance = balance;
    this->counter = counter;
  }

  void serialize(uint8_t* buffer) const {
    size_t position = 0;

    uint32_t balance_network = htonl(this->balance);
    memcpy(buffer, &balance_network, sizeof(uint32_t));
    position += sizeof(uint32_t);

    uint32_t counter_network = htonl(this->counter);
    memcpy(buffer + position, &counter_network, sizeof(uint32_t));

    return;
  }

  static BalanceResponse deserialize(uint8_t* buffer) {
    BalanceResponse response;

    size_t position = 0;

    uint32_t balance_network = 0;
    memcpy(&balance_network, buffer, sizeof(uint32_t));
    position += sizeof(uint32_t);
    response.balance = ntohl(balance_network);
    
    uint32_t counter_network = 0;
    memcpy(&counter_network, buffer + position, sizeof(uint32_t));
    response.counter = ntohl(counter_network);
    return response;
  }

  static  uint32_t getSize() {
    return sizeof(counter) + sizeof(balance);
  }

  void print() {
    std::cout << "BalanceResponse(): counter " <<this->counter << std::endl;
    std::cout << "BalanceResponse(): balance " <<this->balance << std::endl;
  }
};