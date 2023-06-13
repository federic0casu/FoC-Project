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

#include "../Generic/Utility.hpp"
#include "../Packet/List.hpp"


struct jobs {
    std::vector<int> socket_queue;
    std::atomic_bool stop;
    std::mutex socket_mutex;
    std::condition_variable socket_cv;
};
typedef struct jobs jobs_t;


class Server {

public:
    Server(int port, int n_workers, int backlog, volatile sig_atomic_t* g_signal_flag);
    ~Server();
    void accept_connections();
    void set_signal_flag(int flag);

private:
    int port;               // Port used to listen client's requests.
    int sock_fd;            // TCP socket used to listen the incoming requests.
    int backlog;            // Parameter used to decide how big the backlog will be.
    int n_workers;          // Number of workers (threads).
    sockaddr_in address;    // Server's address.
    jobs_t jobs;            // Shared structure used to share task among the workers. 
    std::vector<std::thread> threads;

    volatile sig_atomic_t* g_signal_flag;

    int  create_socket();   // To create the listener socket.
    void bind_socket();     // To bind the listener socket.   
    void listen_socket();   // To listen the incoming connection (using listener socket).
    void worker(int);       // Method called by workers.
    
    ssize_t send_to_client(int, uint8_t*, ssize_t);
    ssize_t recv_from_client(int, uint8_t*, ssize_t);
};
