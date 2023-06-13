#include "Server.hpp"
#include "../Packet/ClientReq.h"


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
    jobs.stop = true;

    // Awaking threads to notify that they should stop.
    jobs.socket_cv.notify_all();

    for (auto& thread : threads)
        thread.join();

    for (int client_socket : jobs.socket_queue)
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
    jobs.stop = false;

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
            std::lock_guard<std::mutex> lock(jobs.socket_mutex);

            jobs.socket_queue.push_back(client_socket);
        }

        // This notifies one waiting worker thread that a new connection is available in the queue.
        jobs.socket_cv.notify_one();
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
            std::unique_lock<std::mutex> lock(jobs.socket_mutex);
            jobs.socket_cv.wait(lock, [&]() { return !jobs.socket_queue.empty() || jobs.stop; });

            if (jobs.stop) 
            {
                #ifdef DEBUG
                std::cout << BLUE_BOLD << "THREAD[" << id << "]" << RESET << " >> stop" << std::endl;
                #endif
                return;
            }

            client_socket = jobs.socket_queue.front();
            jobs.socket_queue.erase(jobs.socket_queue.begin());
        }

        #ifdef DEBUG
        std::cout << BLUE_BOLD << "THREAD[" << id << "]" << RESET << " >> Client connected (socket: " << client_socket << ")." << std::endl;
        #endif

<<<<<<< HEAD
        try {
            unsigned char buffer[4096] = { 0 };
            recv_from_client(client_socket, buffer, sizeof(buffer) - 1);
=======
        uint8_t  buffer[4096] = { 0 };
        ssize_t bytes_read = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
>>>>>>> cd06b724b398af0c0293ededdcb4b9a5e0e0582f

            std::cout << BLUE_BOLD << "THREAD[" << id << "]" << RESET << " >> ";
            std::cout << "Client " << client_socket << ": " << buffer << std::endl;
        }
        catch(std::runtime_error& e) {
            #ifdef DEBUG
            std::cout << BLUE_BOLD << "THREAD[" << id << "]" << RESET << " >> ";
            #endif
            std::cerr << e.what() << std::endl;
            close(client_socket);

            // Something went wrong: we need to clear the session (session key and HMAC key).

            continue;
        }

<<<<<<< HEAD
        try {
            List list_response_1(CODE_LIST_RESPONSE_1, 1);
            list_response_1.serialize();
            ssize_t buffer_size = sizeof(list_response_1.get_buffer()); 
            
            send_to_client(client_socket, list_response_1.get_buffer(), buffer_size);
        }
        catch(std::runtime_error& e) {
            #ifdef DEBUG
            std::cout << BLUE_BOLD << "THREAD[" << id << "]" << RESET << " >> ";
            #endif

            std::cerr << e.what() << std::endl;
            close(client_socket);

            // Something went wrong: we need to clear the session (session key and HMAC key).

            continue;
        }


=======
        std::cout << BLUE_BOLD << "THREAD[" << id << "]" << RESET << " >> ";


        // test 
        ClientReq request;
        request = request.deserialize(buffer);
        std::cout << "Client" << client_socket << ": " 
                  << (char)request.request_code << ":" 
                  << request.recipient << ":" 
                  << (int)request.amount <<  std::endl;
>>>>>>> cd06b724b398af0c0293ededdcb4b9a5e0e0582f
        close(client_socket);

        #ifdef DEBUG
        std::cout << BLUE_BOLD << "THREAD[" << id << "]" << RESET << " >> Client disconnected (socket: " << client_socket << ")." << std::endl;
        #endif
    }
}


<<<<<<< HEAD
void Server::send_to_client(int sock_fd, uint8_t* buffer, ssize_t buffer_size)
=======


ssize_t Server::send_to_client(int sock_fd, uint8_t* buffer, ssize_t buffer_size)
>>>>>>> cd06b724b398af0c0293ededdcb4b9a5e0e0582f
{
    ssize_t total_bytes_sent = 0;

    while (total_bytes_sent < buffer_size) 
    {
        ssize_t bytes_sent = send(sock_fd, (void*) (buffer + total_bytes_sent), buffer_size - total_bytes_sent, 0);
        
        if (bytes_sent == -1 && (errno == EPIPE || errno == ECONNRESET))
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m Client disconnected");

        if (bytes_sent == -1)
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m failed to send data");

        total_bytes_sent += bytes_sent;
    }
}

void Server::recv_from_client(int sock_fd, uint8_t* buffer, ssize_t buffer_size)
{
    ssize_t total_bytes_received = 0;

    while (total_bytes_received < buffer_size) 
    {
        ssize_t bytes_received = recv(sock_fd, (void*) (buffer + total_bytes_received), buffer_size - total_bytes_received, 0);
        if (bytes_received == -1)
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m failed to receive data");

        if (bytes_received == 0)
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m Client disconnected");

        total_bytes_received += bytes_received;
    }
<<<<<<< HEAD
}
=======

    return total_bytes_received;

>>>>>>> cd06b724b398af0c0293ededdcb4b9a5e0e0582f