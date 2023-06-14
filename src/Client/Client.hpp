#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <stdexcept>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "../Packet/List.hpp"
#include "../Packet/ClientReq.hpp"

#include "../Generic/Codes.hpp"
#include "../Generic/Utility.hpp"

class Client {
public:
    Client(const std::string& server_ip, int server_port);
    ~Client();
    void connect_to_server();
    void send_to_server(uint8_t* buffer, ssize_t buffer_size);
    void recv_from_server(uint8_t* buffer, ssize_t buffer_size);
    
    void balance();
    void transfer();
    void list();        // To get list of transactions.

private:
    int sock_fd;
    struct sockaddr_in server_address;
};
