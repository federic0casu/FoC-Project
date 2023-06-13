#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <stdexcept>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define GREEN_BOLD "\033[1;32m"
#define RED_BOLD   "\033[1;31m"
#define RESET      "\033[0m"

class Client {
    int sock_fd;
    struct sockaddr_in server_address;

public:
    Client(const std::string& server_ip, int server_port);
    ~Client();
    void connect_to_server();
    void send_request(const uint8_t* message,uint32_t len);
};