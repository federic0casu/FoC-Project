#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <openssl/rand.h>

#include "../Generic/Codes.hpp"

struct TransferResponse {

    uint8_t outcome;
    uint32_t counter;

    TransferResponse() {}

    TransferResponse(char resp, uint32_t __counter) : counter(__counter){
        this->outcome = resp;
    }

    void serialize (std::vector<uint8_t>& buffer) {
        size_t position = 0;

        std::memcpy(reinterpret_cast<void*>(buffer.data()), &this->outcome, sizeof(uint8_t));
        position += sizeof(uint8_t);

        uint32_t counter_network = htonl(this->counter);
        std::memcpy(reinterpret_cast<void*>(buffer.data() + position), &counter_network, sizeof(uint32_t));
    }

    static TransferResponse deserialize(uint8_t * buffer) {
        TransferResponse transfer;
        
        size_t position = 0;
        uint32_t counter_network = 0;
        
        memcpy(&transfer.outcome, buffer, sizeof(uint8_t));
        position += sizeof(uint8_t);

        memcpy(&counter_network, buffer + position, sizeof(uint32_t));
        transfer.counter = ntohl(counter_network);

        return transfer;
    }

      void print() const {
        std::cout << "--------- TRANSFER RESPONSE --------" << std::endl;
        std::cout << "RESPONSE: " << this->outcome << std::endl;
        std::cout << "COUNTER:" << counter << std::endl;
        std::cout << "------- END REQUEST MESSAGGE ----------" << std::endl;
    }
};