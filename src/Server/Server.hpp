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

#include "Worker.hpp"


class Server {

public:
    Server(int port, int n_workers, int backlog, volatile sig_atomic_t* g_signal_flag);
    ~Server();
    void accept_connections();

private:
    int port;               // Port used to listen client's requests.
    int sock_fd;            // TCP socket used to listen the incoming requests.
    int backlog;            // Parameter used to decide how big the backlog will be.
    int n_workers;          // Number of workers (threads).
    sockaddr_in address;    // Server's address.
    jobs_t jobs;            // Shared structure used to share task among the workers. 
    
    std::vector<std::thread> threads;
    std::vector<Worker*>     workers;

    volatile sig_atomic_t* g_signal_flag;

    int  create_socket();   // To create the listener socket.
    void bind_socket();     // To bind the listener socket.   
    void listen_socket();   // To listen the incoming connection (using listener socket).
    
    //void worker(int);       // Method called by workers.
   
    //ClientReq handle_request(int);

    //void balance(int, int);
    //void transfer(int, int);
    //void list(int, int);
    
    //void send_to_client(int, uint8_t*, ssize_t);
    //void recv_from_client(int, uint8_t*, ssize_t);
};
