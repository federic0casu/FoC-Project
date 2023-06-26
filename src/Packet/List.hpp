#include <ctime>
#include <vector>
#include <iomanip>
#include <cstring>

#include <string.h>
#include <arpa/inet.h>

#define USER_SIZE   32 

struct ListM1 {
    uint32_t transaction_num;
    uint32_t counter;

    ListM1 () {}

    ListM1 (uint32_t __counter, uint32_t __transaction_num) : transaction_num(__transaction_num), counter(__counter) {}

    void serialize(std::vector<uint8_t>& buffer) {
        size_t position = 0;

        uint32_t transaction_num_network = htonl(this->transaction_num);
        std::memcpy(reinterpret_cast<void*>(buffer.data()), &transaction_num_network, sizeof(uint32_t));
        position += sizeof(uint32_t);

        uint32_t counter_network = htonl(this->counter);
        std::memcpy(reinterpret_cast<void*>(buffer.data() + position), &counter_network, sizeof(uint32_t));

        return;
    }

    static ListM1 deserialize(std::vector<uint8_t>& buffer) {
        ListM1 listM1;

        size_t position = 0;
        uint32_t transaction_num_network = 0;
        std::memcpy(reinterpret_cast<void*>(&transaction_num_network), reinterpret_cast<const void*>(buffer.data()), sizeof(uint32_t));
        listM1.transaction_num = ntohl(transaction_num_network);

        position += sizeof(uint32_t);

        uint32_t counter_network = 0;
        std::memcpy(reinterpret_cast<void*>(&counter_network), reinterpret_cast<const void*>(buffer.data() + position), sizeof(uint32_t));
        listM1.counter = ntohl(counter_network);

        return listM1;
        }

    static uint32_t getSize() { return sizeof(uint32_t) + sizeof(uint32_t); }

    void print() {
        std::cout << "--------- LIST M1 MESSAGE -----------" << std::endl;
        std::cout << "TRANSATIONS: " << this->transaction_num << std::endl;
        std::cout << "-------------------------------------" << std::endl;
    }
};


struct ListM2 {
    uint32_t counter; 
    uint32_t timestamp;
    uint32_t amount;
    uint8_t  recipient[USER_SIZE];

    ListM2() : counter(0), timestamp(0), amount(0) {
        std::memset(reinterpret_cast<void*>(recipient), 0, sizeof(recipient));
    }

    ListM2(uint32_t __counter, uint64_t __timestamp, uint32_t __amount, std::vector<uint8_t>& recipient) : counter(__counter), timestamp(__timestamp), amount(__amount) {
        std::memset(reinterpret_cast<void*>(this->recipient), 0, sizeof(this->recipient));
        std::memcpy(reinterpret_cast<void*>(this->recipient), reinterpret_cast<const void*>(recipient.data()), sizeof(this->recipient));
    }

    void serialize(std::vector<uint8_t>& buffer) {
        buffer.resize(sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(this->recipient));

        size_t position = 0;

        uint32_t counter_network = htonl(this->counter);
        std::memcpy(reinterpret_cast<void*>(buffer.data()), reinterpret_cast<const void*>(&counter_network), sizeof(uint32_t));
        position += sizeof(uint32_t);

        uint32_t timestamp_net = htonl(static_cast<uint32_t>(this->timestamp));
        std::memcpy(reinterpret_cast<void*>(buffer.data() + position), reinterpret_cast<const void*>(&timestamp_net), sizeof(uint32_t));
        position += sizeof(uint32_t);

        uint32_t amount_network = htonl(this->amount);
        std::memcpy(reinterpret_cast<void*>(buffer.data() + position), reinterpret_cast<const void*>(&amount_network), sizeof(this->amount));
        position += sizeof(uint32_t);

        std::memcpy(reinterpret_cast<void*>(buffer.data() + position), reinterpret_cast<const void*>(this->recipient), sizeof(this->recipient));
    }

    static ListM2 deserialize(std::vector<uint8_t>& buffer) {
        ListM2 listM2;

        size_t position = 0;

        uint32_t counter_network = 0;
        std::memcpy(reinterpret_cast<void*>(&counter_network), reinterpret_cast<const void*>(buffer.data()), sizeof(listM2.counter));
        listM2.counter = ntohl(counter_network);
        position += sizeof(uint32_t);

        uint32_t timestamp_net = 0;
        std::memcpy(reinterpret_cast<void*>(&timestamp_net), reinterpret_cast<const void*>(buffer.data() + position), sizeof(listM2.timestamp));
        listM2.timestamp = ntohl(timestamp_net);
        position += sizeof(uint32_t);

        uint32_t amount_network = 0;
        std::memcpy(reinterpret_cast<void*>(&amount_network), reinterpret_cast<void*>(buffer.data() + position), sizeof(listM2.amount));
        listM2.amount = ntohl(amount_network);
        position += sizeof(uint32_t);

        std::memcpy(reinterpret_cast<void*>(listM2.recipient), reinterpret_cast<const void*>(buffer.data() + position), sizeof(listM2.recipient));

        return listM2;
    }

    void print_formatted_date(std::time_t timestamp) {
        std::tm* timeinfo = std::localtime(&timestamp);
        if (timeinfo != nullptr) {
            char buffer[20];
            std::strftime(buffer, sizeof(buffer), "%d:%m:%Y %H:%M", timeinfo);
            std::cout << buffer << std::endl;
        }
    }

    void print() {
        std::cout << "PAYEE: "   << this->recipient << ",\t"
                  << "AMOUT: " << this->amount    << ",\t"
                  << "DATE: ";
        print_formatted_date(this->timestamp);
    }

};