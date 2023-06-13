#include "Client.hpp"

Client::Client(const std::string& server_ip, int server_port)
{
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (sock_fd == -1)
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Failed to create socket.");

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(server_port);

    if (inet_pton(AF_INET, server_ip.c_str(), &(server_address.sin_addr)) <= 0) 
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Invalid server IP address.");
}

Client::~Client()
{
    close(sock_fd);
}

void Client::connect_to_server()
{
    if (connect(sock_fd, (struct sockaddr*)&server_address, sizeof(server_address)) == -1)
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Failed to connect to the server.");

    std::cout << "Connected to the server." << std::endl;
}

<<<<<<< HEAD
bool Client::list()
{
    try {
=======
void Client::send_request(const uint8_t* message, uint32_t len)
{
    if (send(sock_fd, message, len, 0) == -1)
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Failed to send the request.");
>>>>>>> cd06b724b398af0c0293ededdcb4b9a5e0e0582f

    }
    catch(std::runtime_error& e) {
        std::cerr << e.what() << std::endl;
        return false;
    }
    return true;
}

void Client::send_to_server(int sock_fd, uint8_t* buffer, ssize_t buffer_size)
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

void Client::recv_from_server(int sock_fd, uint8_t* buffer, ssize_t buffer_size)
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
}
