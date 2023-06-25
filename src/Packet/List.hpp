#include <ctime>
#include <vector>
#include <cstring>

#include <string.h>
#include <arpa/inet.h>

#define USER_SIZE   32 

#define HTONLL(x) ((1==htonl(1)) ? (x) : (((uint64_t)htonl((x) & 0xFFFFFFFFUL)) << 32) | htonl((uint32_t)((x) >> 32)))
#define NTOHLL(x) ((1==ntohl(1)) ? (x) : (((uint64_t)ntohl((x) & 0xFFFFFFFFUL)) << 32) | ntohl((uint32_t)((x) >> 32)))

struct ListM1 {
    uint32_t transaction_num;
    uint32_t counter;

    ListM1 () {}

    ListM1 (uint32_t counter, uint32_t transaction_num) {
        this->counter = counter;
        this->transaction_num = transaction_num;
    }

    void serialize(uint8_t * buffer) {
        size_t position = 0;

        uint32_t transaction_num_network = htonl(this->transaction_num);
        memcpy(buffer, &transaction_num_network, sizeof(uint32_t));
        position += sizeof(uint32_t);

        uint32_t counter_network = htonl(this->counter);
        memcpy(buffer + position, &counter_network, sizeof(uint32_t));

        return;
    }

    static ListM1 deserialize(uint8_t * buffer) {
        ListM1 listm1;

        size_t position = 0;
        uint32_t transaction_num_network = 0;
        memcpy(&transaction_num_network, buffer, sizeof(uint32_t));
        listm1.transaction_num = ntohl(transaction_num_network);

        position += sizeof(uint32_t);

        uint32_t counter_network = 0;
        memcpy(&counter_network, buffer, sizeof(uint32_t));
        listm1.counter = ntohl(counter_network);

        return listm1;
        }

    static uint32_t getSize() {
        return sizeof(uint32_t) + sizeof(uint32_t);
    }

    void print() {
        std::cout << "--------- LIST M1 MESSAGE -----------" << std::endl;
        std::cout << "TRANSATIONS: " << this->transaction_num << "  -----------" << std::endl;
    }
};


struct ListM2 {
    uint32_t counter; 
    uint64_t timestamp;
    uint32_t amount;
    uint8_t recipient[USER_SIZE];

    ListM2(){}

    ListM2(uint32_t counter, uint64_t timestamp, uint32_t amount, uint8_t * recipient) {
        this->counter = counter;
        this->timestamp = timestamp;
        this->amount = amount;
        memset(this->recipient, 0, sizeof(this->recipient));
        memcpy(this->recipient, recipient, sizeof(this->recipient));
    }

    void serialize(uint8_t * buffer) {
        size_t position = 0;

        uint32_t counter_network = htonl(this->counter);
        memcpy(buffer, &counter_network, sizeof(uint32_t));
        position += sizeof(uint32_t);

        uint64_t timestamp_network = HTONLL(this->timestamp);
        memcpy(buffer + position, &timestamp_network, sizeof(this->timestamp));
        position += sizeof(uint64_t);

        uint32_t amount_network = htonl(this->amount);
        memcpy(buffer + position, &amount_network, sizeof(this->amount));
        position += sizeof(uint32_t);

        memcpy(buffer + position, this->recipient, sizeof(this->recipient));
    }

    static ListM2 deserialize(uint8_t * buffer) {
        ListM2 listm2;

        size_t position = 0;

        uint32_t counter_network = 0;
        memcpy(&counter_network, buffer, sizeof(uint32_t));
        listm2.counter = ntohl(counter_network);
        position += sizeof(uint32_t);
    

        uint64_t timestamp_network = 0;
        memcpy(&timestamp_network, buffer + position, sizeof(uint64_t));
        listm2.timestamp = NTOHLL(timestamp_network);
        position += sizeof(uint64_t);
    

        uint32_t amount_network = 0;
        memcpy(&amount_network, buffer + position, sizeof(uint32_t));
        listm2.amount = ntohl(amount_network);
        position += sizeof(uint32_t);

        memcpy(listm2.recipient, buffer + position, sizeof(listm2.recipient));

        return listm2;
    }
    

    void print() {
        std::cout << "--------- LIST M2 MESSAGE -----------" << std::endl;
        std::cout << "COUNTER: " <<  this->counter << "  -----------" << std::endl;
        std::cout << "TIMESTAMP: " <<  this->timestamp << "  -----------" << std::endl;
        std::cout << "AMOUNT" <<  this->amount << "  -----------" << std::endl;
        std::cout << "RECIPIENT" <<  this->recipient << "  -----------" << std::endl;
        std::cout << "--------- END LIST M2 MESSAGE -----------" << std::endl;
    
    }

};