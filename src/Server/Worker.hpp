#include <mutex>
#include <atomic>
#include <thread>
#include <vector>
#include <string>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <algorithm>
#include <condition_variable>

#include <unistd.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "../Packet/List.hpp"
#include "../Packet/ClientReq.hpp"
#include "../Generic/Codes.hpp"
#include "../Generic/Utility.hpp"

struct jobs {
    std::vector<int> socket_queue;
    std::atomic_bool stop;
    std::mutex socket_mutex;
    std::condition_variable socket_cv;
};
typedef struct jobs jobs_t;

#define SESSION_KEY_LENGHT 256

class Worker {

public:
    Worker(int n_workers, jobs_t* jobs);

    // Thread logic
    void Run();
    
    // Communication methods
    ssize_t Receive(std::vector<uint8_t>& buffer, ssize_t buffer_size);
    ssize_t Send(const std::vector<uint8_t>& buffer);
    
    // Worker Logic
    ClientReq HandleRequest();
    void List();
    void Transfer();
    void Balance();
private:
    uint8_t hmac_key[SESSION_KEY_LENGHT];
    uint8_t session_key[SESSION_KEY_LENGHT];
    
    int n_workers;
    int thread_id;
    int client_socket;
    jobs_t* jobs;
};
