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
        unsigned char buffer[] = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        ClientReq balance_request(CODE_BALANCE_REQUEST, 0, buffer);

        #ifdef DEBUG
        std::cout << "[1] balance ->\t" << balance_request.request_code << ":" << balance_request.recipient << ":" << balance_request.amount << std::endl;
        #endif

        std::vector<uint8_t> to_send;
        to_send.resize(REQUEST_PACKET_SIZE);  // Resize the vector to the desired buffer size
        balance_request.serialize(to_send);
        send_to_server(to_send);
    }
    catch(std::runtime_error& e) {
        std::cerr << e.what() << std::endl;
    }
}

void Client::transfer()
{
    try {
        unsigned char buffer[] = "TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT";
        ClientReq transfer_request(CODE_TRANSFER_REQUEST, 0, buffer);

        #ifdef DEBUG
        std::cout << "[1] transfer ->\t" << transfer_request.request_code << ":" << transfer_request.recipient << ":" << transfer_request.amount << std::endl;
        #endif

        std::vector<uint8_t> to_send;
        to_send.resize(REQUEST_PACKET_SIZE);  // Resize the vector to the desired buffer size
        transfer_request.serialize(to_send);
        send_to_server(to_send);
    }
    catch(std::runtime_error& e) {
        std::cerr << e.what() << std::endl;
    }
}


void Client::list()
{
    try {
        /*--------------- STEP 1: send a list request (request_code: 0x03) ---------------*/
        unsigned char buffer[] = "LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL";
        ClientReq list_request(CODE_LIST_REQUEST, 0, buffer);

        #ifdef DEBUG
        std::cout << "[1] list ->\t" << list_request.request_code << ":" << list_request.recipient << ":" << list_request.amount << std::endl;
        #endif

        std::vector<uint8_t> to_send;
        to_send.resize(REQUEST_PACKET_SIZE);  // Resize the vector to the desired buffer size
        list_request.serialize(to_send);
        send_to_server(to_send);
        /*--------------------------------------------------------------------------------*/

        /*---------- STEP 2: receive number of transactions (response_code 0x06) ---------*/
        std::vector<uint8_t> to_recv(LIST_RESPONSE_1_SIZE, 0);
        recv_from_server(to_recv);
        List response_1 = List::deserialize(to_recv);

        #ifdef DEBUG
        std::cout << "[2] list ->\t" << response_1.code_response << ":" 
                << response_1.dest << ":" 
                << response_1.amount << ":";
        print_formatted_date(response_1.timestamp);
        #endif
        /*--------------------------------------------------------------------------------*/

        /*---------- STEP 3: receive lisy of transactions (response_code 0x06) -----------*/
        auto n = response_1.amount;
        
        for (uint32_t i = 0; i < n; i++)
        {
            to_recv.clear();
            to_recv.resize(LIST_RESPONSE_2_SIZE);

            recv_from_server(to_recv);
            List response_2 = List::deserialize(to_recv);

            std::cout << "\t" << response_2.amount << " -> " << response_2.dest << "\t";
            print_formatted_date(response_2.timestamp);
        }
        /*--------------------------------------------------------------------------------*/

    }
    catch(std::runtime_error& e) {
        std::cerr << e.what() << std::endl;
    }
}

void Client::send_to_server(const std::vector<uint8_t>& buffer)
{
    ssize_t total_bytes_sent = 0;
    ssize_t buffer_size = buffer.size();

    while (total_bytes_sent < buffer_size)
    {
        ssize_t bytes_sent = send(sock_fd, (void*)(buffer.data() + total_bytes_sent), buffer_size - total_bytes_sent, 0);

        if (bytes_sent == -1 && (errno == EPIPE || errno == ECONNRESET))
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m Server disconnected");

        if (bytes_sent == -1)
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m failed to send data");

        total_bytes_sent += bytes_sent;
    }
}

void Client::recv_from_server(std::vector<uint8_t>& buffer)
{
    ssize_t total_bytes_received = 0;
    ssize_t buffer_size = buffer.size();

    while (total_bytes_received < buffer_size)
    {
        ssize_t bytes_received = recv(sock_fd, (void*)(buffer.data() + total_bytes_received), buffer_size - total_bytes_received, 0);
        
        if (bytes_received == -1)
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m failed to receive data");

        if (bytes_received == 0)
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m Server disconnected");

        total_bytes_received += bytes_received;
    }
}

void Client::print_formatted_date(std::time_t timestamp)
{
    std::tm* timeinfo = std::localtime(&timestamp);
    if (timeinfo != nullptr) {
        std::cout << std::setfill('0') << std::setw(2) << timeinfo->tm_mday << ":" // Day
                  << std::setfill('0') << std::setw(2) << (timeinfo->tm_mon + 1) << ":" // Month (+1 because months are zero-based)
                  << (timeinfo->tm_year + 1900) << " " // Year (+1900 because years are counted from 1900)
                  << std::setfill('0') << std::setw(2) << timeinfo->tm_hour << ":" // Hour
                  << std::setfill('0') << std::setw(2) << timeinfo->tm_min << std::endl; // Minute
    }
}
