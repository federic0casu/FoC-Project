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

#define GREEN_BOLD "\033[1;32m"
#define BLUE_BOLD  "\033[1;34m"
#define RED_BOLD   "\033[1;31m"
#define RESET      "\033[0m"

#define DEBUG 0

struct jobs {
    std::vector<int> socket_queue;
    std::atomic_bool stop;
    std::mutex socket_mutex;
    std::condition_variable socket_cv;
};

class Server {
    int port;       // Port used to listen client's requests.
    int sock_fd;    // TCP socket used to listen the incoming requests.
    int backlog;    // Parameter used to decide how big the backlog will be.
    int n_workers;

    struct sockaddr_in address;
    
    std::vector<std::thread> threads;
    struct jobs __jobs;

    volatile sig_atomic_t* g_signal_flag;

    int  create_socket();
    void bind_socket();
    void set_reuse();
    void listen_socket();
    void worker(int);
public:
    Server(int port, int n_workers, int backlog, volatile sig_atomic_t* g_signal_flag);
    ~Server();
    void accept_connections();
    void set_signal_flag(int flag);
};
