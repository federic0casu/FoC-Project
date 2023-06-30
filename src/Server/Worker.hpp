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

#include "../Packet/List.hpp"
#include "../Packet/Balance.hpp"
#include "../Packet/Transfer.hpp"
#include "../Packet/Handshake.hpp"
#include "../Packet/ClientReq.hpp"
#include "../Packet/SessionMessage.hpp"
#include "../Packet/PasswordMessage.hpp"

#include "../Generic/Codes.hpp"
#include "../Generic/Utility.hpp"
#include "../Utility/FileManager.hpp"
#include "../Utility/TransferManager.hpp"

#include "../Crypto/DiffieHellman.hpp"


struct jobs {
    std::vector<int> socket_queue;
    std::atomic_bool stop;
    std::mutex socket_mutex;
    std::condition_variable socket_cv;
};
typedef struct jobs jobs_t;

class Worker {

public:
    Worker(jobs_t* jobs);
    ~Worker();

    // Thread logic
    void Run();
    
private:
    std::vector<uint8_t> iv;
    std::vector<uint8_t> hmac_key;
    std::vector<uint8_t> session_key;
    std::string username;
    uint8_t counter;
    uint32_t max_list_transfers;
    const std::string server_private_key_path = "../res/private_keys/server_privkey.pem";
    
    int client_socket;
    jobs_t* jobs;

    // Communication methods
    ssize_t Receive(std::vector<uint8_t>& buffer, ssize_t buffer_size);
    ssize_t Send(const std::vector<uint8_t>& buffer);
    
    // Key exchange protocol
    void Handshake();
    bool ClientExists(uint8_t* username, ssize_t username_size);

    // Worker Logic
    ClientReq RequestHandler();
    void ListHandler();
    void TransferHandler(uint8_t* recipient, uint32_t msg_amount);
    void BalanceHandler();

    // Utility
    void IncrementCounter();
    void CheckCounter(uint32_t received_counter);
    void SendResponse(bool outcome);
};
