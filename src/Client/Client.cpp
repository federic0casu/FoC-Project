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

void Client::balance()
{
    try {
        uint8_t buffer[RECIPIENT_SIZE] = "PADDiNG_PADDiNG_PADDiNG_PADDiNG";
        ClientReq balance_request(CODE_BALANCE_REQUEST, 0, &buffer[0]);

        #ifdef DEBUG
        std::cout << "[1] balance: " << buffer << std::endl;
        #endif

        uint8_t to_send[REQUEST_PACKET_SIZE];
        balance_request.serialize(to_send);

        #ifdef DEBUG
        std::cout << "[2] balance.serialize: " << to_send << std::endl;
        #endif

        send_to_server(to_send, balance_request.get_size());
    }
    catch(std::runtime_error& e) {
        std::cerr << e.what() << std::endl;
    }
}

void Client::transfer()
{
    try {
        uint8_t buffer[RECIPIENT_SIZE] = "PaDDING_PaDDING_PaDDING_PaDDING";
        ClientReq transfer_request(CODE_TRANSFER_REQUEST, 0, &buffer[0]);

        #ifdef DEBUG
        std::cout << "[1] transfer: " << buffer << std::endl;
        #endif

        uint8_t to_send[REQUEST_PACKET_SIZE];
        transfer_request.serialize(to_send);

        #ifdef DEBUG
        std::cout << "[2] transfer.serialize: " << to_send << std::endl;
        #endif

        send_to_server(to_send, transfer_request.get_size());
    }
    catch(std::runtime_error& e) {
        std::cerr << e.what() << std::endl;
    }
}


void Client::list()
{
    try {
        uint8_t buffer[RECIPIENT_SIZE] = "PADDING_PADDING_PADDING_PADDING";
        ClientReq list_request(CODE_LIST_REQUEST, 0, &buffer[0]);

        #ifdef DEBUG
        std::cout << "[1] list: " << buffer << std::endl;
        #endif

        uint8_t to_send[REQUEST_PACKET_SIZE];
        list_request.serialize(to_send);

        #ifdef DEBUG
        std::cout << "[2] list.serialize: " << to_send << std::endl;
        #endif

        send_to_server(to_send, list_request.get_size());
    }
    catch(std::runtime_error& e) {
        std::cerr << e.what() << std::endl;
    }
}

void Client::send_to_server(uint8_t* buffer, ssize_t buffer_size)
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

void Client::recv_from_server(uint8_t* buffer, ssize_t buffer_size)
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
