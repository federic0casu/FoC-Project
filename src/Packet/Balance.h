#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <openssl/rand.h>

#include "../Generic/Codes.h"

using namespace std;

struct BalanceResponse {
  uint32_t account_id;
  uint32_t balance;

  BalanceResponse() {}

  BalanceResponse(uint32_t id, uint32_t balance){
    this->account_id = id;
    this->balance = balance;
  }

  uint8_t* serialize() const {
    uint8_t* buffer = new uint8_t[BALANCE_RESPONSE_PACKET_SIZE];
    size_t position = 0;

    memcpy(buffer, &account_id, sizeof(uint32_t));
    position += sizeof(uint32_t);

    memcpy(buffer, &balace, sizeof(uint32_t));

    return buffer
  }

  static BalanceResponse deserialize() {
    BalanceResponse response;

    size_t position = 0;

    memcpy(&response.account_id, buffer, sizeof(uint32_t));
    position += sizeof(uint32_t);

    memcpy(&response.balance, buffer + position, sizeof(uint32_t));
    return response;
  }

    uint32_t getSize() {
    return sizeof(account_id) + sizeof(balance);
  }
}