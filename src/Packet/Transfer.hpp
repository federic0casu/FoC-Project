#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <openssl/rand.h>

#include "../Generic/Codes.hpp"

struct TransferResponse {

    uint8_t outcome;
    uint32_t counter;


    TransferResponse(){}
    TransferResponse(char resp, uint32_t counter){
        this->counter = counter;
        this->outcome = resp;
    }


    void serialize (uint8_t *buffer) {
        size_t position = 0;

        memcpy(buffer, &this->outcome, sizeof(uint8_t));
        position += sizeof(uint8_t);

        uint32_t counter_network = htonl(this->counter);
        memcpy(buffer + position, &counter_network, sizeof(uint32_t));
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
        cout << "--------- TRANSFER RESPONSE --------" << endl;
        cout << "RESPONSE: " << this->outcome << endl;
        cout << "COUNTER:" << counter << endl;
        cout << "------- END REQUEST MESSAGGE ----------" << endl;
    }
};