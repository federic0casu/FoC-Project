#include "Server.hpp"


Server::Server(int port, int n_workers, int backlog, volatile sig_atomic_t* g_signal_flag)
{
    // Backlog must be validated before instatianting the socket.
    if (backlog < 0)
        throw std::invalid_argument("\033[1;31m[ERROR]\033[0m Couldn't start the server: backlog must be a non-negative number.");

    // n_workers must be a non-negative number.
    if (n_workers < 0)
        throw std::invalid_argument("\033[1;31m[ERROR]\033[0m Couldn't start the server: n_workers must be a non-negative number.");

    // Port number must be validated before instatianting the socket.
    if (port < 1024 || port > 65535)
        throw std::invalid_argument("\033[1;31m[ERROR]\033[0m Couldn't start the server: port number must be 1024 < port <= 65535.");

    this->port = port;
    this->n_workers = n_workers;
    this->backlog = backlog;
    this->g_signal_flag = g_signal_flag;

    // Instantiating a TCP socket (listen socket).
    sock_fd = create_socket();

    set_reuse();

    // Binding the socket to the server address and port
    bind_socket();  

    // Enabling the socket to listen incoming requests
    listen_socket();

#ifdef DEBUG    
    std::cout << "###########################" << std::endl;
    std::cout << "#    " << GREEN_BOLD << "SERVER IS RUNNING" << RESET << "   #" << std::endl;
    std::cout << "###########################" << std::endl;
#endif
}


Server::~Server() 
{
    __jobs.stop = true;

    // Awaking threads to notify that they should stop.
    __jobs.socket_cv.notify_all();

    for (auto& thread : threads)
        thread.join();

    for (int client_socket : __jobs.socket_queue)
        close(client_socket);

    if (sock_fd != -1) close(sock_fd);

#ifdef DEBUG
    std::cout << "###########################" << std::endl;
    std::cout << "# " << RED_BOLD << "SERVER IS SHUTTING DOWN" << RESET << " #" << std::endl;
    std::cout << "###########################" << std::endl;
#endif
}


void Server::accept_connections()
{
    __jobs.stop = false;

    // Reserves space in the 'threads' vector to hold the worker threads.
    threads.reserve(n_workers);

    for (int i = 0; i < n_workers; i++) {
        threads.emplace_back([this,i]() { worker(i); });
    }

    struct sockaddr_in client_address;
    socklen_t addrlen = sizeof(struct sockaddr_in);
    int client_socket = -1;

    while (!(*g_signal_flag)) {

        // Set up the file descriptor set for select()
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(sock_fd, &read_fds);

        // Set up the timeout value for select()
        struct timeval timeout;
        timeout.tv_sec  = 1;
        timeout.tv_usec = 0;

        // Use select() to wait for incoming connections with a timeout
        int select_result = select(sock_fd + 1, &read_fds, nullptr, nullptr, &timeout);

        if (select_result == -1)
        {
            if(errno != EINTR) 
            {
                std::string error_message = strerror(errno);
                throw std::runtime_error("\033[1;31m[ERROR]\033[0m Failed to select(): " + error_message);
            }
            continue;
        }

        if (select_result == 0) 
        {
            // Timeout occurred, no incoming connections
            continue;
        }

        client_socket = accept(sock_fd, (struct sockaddr*)&client_address, &addrlen);

        if (client_socket == -1) 
        {
            std::cerr << "[RUNTIME EVENT] Failed to accept an incoming connection: " << strerror(errno) << std::endl;;
            continue;
        }

        {
            // This lock ensures that 'socket_queue' is accessed safely 
            // by preventing concurrent access from multiple threads.
            std::lock_guard<std::mutex> lock(__jobs.socket_mutex);

            __jobs.socket_queue.push_back(client_socket);
        }

        // This notifies one waiting worker thread that a new connection is available in the queue.
        __jobs.socket_cv.notify_one();
    }
}


inline int Server::create_socket() 
{
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (socket_fd == -1) 
    {
        std::string error_message = strerror(errno);
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Failed to create socket: " + error_message);
    }
    return socket_fd;
}


inline void Server::bind_socket() 
{
    // Served address and server port
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(sock_fd, (struct sockaddr*) &address, sizeof(address)) == -1) 
    {
        std::string error_message = strerror(errno);
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Failed to bind socket: " + error_message);
    }
}

inline void Server::set_reuse() 
{
    int reuse = 1;    
    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == -1) {
        std::string error_message = strerror(errno);
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Failed to set 'reuse' option " + error_message);
    }
}


inline void Server::listen_socket()
{
    if (listen(sock_fd, backlog) == -1) 
    {
        std::string error_message = strerror(errno);
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Failed to listen on socket: " + error_message);
    }
}


void Server::worker(int id) 
{
    while (true) {
        int client_socket;

        {
            std::unique_lock<std::mutex> lock(__jobs.socket_mutex);
            __jobs.socket_cv.wait(lock, [&]() { return !__jobs.socket_queue.empty() || __jobs.stop; });

            if (__jobs.stop) 
            {
                #ifdef DEBUG
                std::cout << BLUE_BOLD << "THREAD[" << id << "]" << RESET << " >> stop" << std::endl;
                #endif
                return;
            }

            client_socket = __jobs.socket_queue.front();
            __jobs.socket_queue.erase(__jobs.socket_queue.begin());
        }

        #ifdef DEBUG
        std::cout << BLUE_BOLD << "THREAD[" << id << "]" << RESET << " >> Client connected (socket: " << client_socket << ")." << std::endl;
        #endif

        char buffer[4096] = { 0 };
        ssize_t bytes_read = recv(client_socket, buffer, sizeof(buffer) - 1, 0);

        if (bytes_read == -1) 
        {
            close(client_socket);
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m recv error");
        }

        if (bytes_read == 0) 
        {
            #ifdef DEBUG
            std::cout << BLUE_BOLD << "THREAD[" << id << "]" << RESET << " >> Client disconnected (socket: " << client_socket << ")." << std::endl;
            #endif
            close(client_socket);
        }

        std::cout << BLUE_BOLD << "THREAD[" << id << "]" << RESET << " >> ";
        std::cout << "Client " << client_socket << ": " << buffer << std::endl;
        close(client_socket);

        #ifdef DEBUG
        std::cout << BLUE_BOLD << "THREAD[" << id << "]" << RESET << " >> Client disconnected (socket: " << client_socket << ")." << std::endl;
        #endif
    }
}