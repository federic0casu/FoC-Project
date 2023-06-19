#include <mutex>
#include <string>
#include <atomic>
#include <thread>
#include <vector>
#include <string>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <fstream>
#include <sstream>
#include <iostream>
#include <stdexcept>
#include <algorithm>
#include <condition_variable>

#include <unistd.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "../Crypto/DiffieHellman.hpp"

#include "../Packet/List.hpp"
#include "../Packet/ClientReq.hpp"
#include "../Packet/Handshake.hpp"
#include "../Packet/SessionMessage.hpp"

#include "../Generic/Codes.hpp"
#include "../Generic/Utility.hpp"

#define SESSION_KEY_LENGHT 256

struct jobs {
    std::vector<int> socket_queue;
    std::atomic_bool stop;
    std::mutex socket_mutex;
    std::condition_variable socket_cv;
};
typedef struct jobs jobs_t;

struct row_data {
    std::string dest;
    int amount;
    long timestamp;

    row_data() {}

    row_data(const std::string& destination, int amt, long ts) 
        : dest(destination), amount(amt), timestamp(ts) {}
};
typedef struct row_data row_data_t;

class Worker {

public:
    Worker(jobs_t* jobs);

    // Thread logic
    void Run();
    
private:
    std::vector<uint8_t> iv;
    std::vector<uint8_t> hmac_key;
    std::vector<uint8_t> session_key;
    uint8_t username[USERNAME_SIZE];
    
    int client_socket;
    jobs_t* jobs;

    // Communication methods
    ssize_t Receive(std::vector<uint8_t>& buffer, ssize_t buffer_size);
    ssize_t Send(const std::vector<uint8_t>& buffer);
    
    // Key exchange protocol
    void Handshake();

    // Worker Logic
    ClientReq RequestHandler();
    void ListHandler();
    void TransferHandler();
    void BalanceHandler();

    std::vector<row_data_t> ListByUsername(const std::string& filename);
    void AppendTransactionByUsername(const std::string& filename, const row_data_t& row);
};
