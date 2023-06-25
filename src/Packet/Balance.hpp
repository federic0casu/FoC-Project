#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <openssl/rand.h>

#include "../Generic/Codes.hpp"


struct BalanceResponse {

  uint32_t balance;
  uint32_t counter;
  
  BalanceResponse() {}

  BalanceResponse(uint32_t __counter, uint32_t __balance) : counter(__counter), balance(__balance) {} 

  void serialize(std::vector<uint8_t>& buffer) const {
    size_t position = 0;

    uint32_t balance_network = htonl(this->balance);
    std::memcpy(reinterpret_cast<void*>(buffer.data()), &balance_network, sizeof(uint32_t));
    position += sizeof(uint32_t);

    uint32_t counter_network = htonl(this->counter);
    std::memcpy(reinterpret_cast<void*>(buffer.data() + position), &counter_network, sizeof(uint32_t));

    return;
  }

  static BalanceResponse deserialize(std::vector<uint8_t>& buffer) {
    BalanceResponse response;

    size_t position = 0;

    uint32_t balance_network = 0;
    std::memcpy(reinterpret_cast<void*>(&balance_network), reinterpret_cast<const void*>(buffer.data()), sizeof(uint32_t));
    position += sizeof(uint32_t);
    response.balance = ntohl(balance_network);
    
    uint32_t counter_network = 0;
    std::memcpy(reinterpret_cast<void*>(&counter_network), reinterpret_cast<const void*>(buffer.data() + position), sizeof(uint32_t));
    response.counter = ntohl(counter_network);

    return response;
  }

  static inline uint32_t getSize() {
    return sizeof(counter) + sizeof(balance);
  }

  void inline print() {
    if (balance == -1)
      std::cout << "Something went wrong. Please, try again..." << std::endl;
    else 
      std::cout << "Your balance is " << balance << "$" << std::endl;
  }
};