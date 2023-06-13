#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <stdexcept>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "../Packet/List.hpp"
#include "../Generic/Codes.hpp"
#include "../Generic/Utility.hpp"

class Client {
    int sock_fd;
    struct sockaddr_in server_address;

public:
    Client(const std::string& server_ip, int server_port);
    ~Client();
    void connect_to_server();
<<<<<<< HEAD
    void send_to_server(int sock_fd, uint8_t* buffer, ssize_t buffer_size);
    void recv_from_server(int sock_fd, uint8_t* buffer, ssize_t buffer_size);
    
    bool list();        // To get list of transactions.
};
=======
    void send_request(const uint8_t* message,uint32_t len);
};
>>>>>>> cd06b724b398af0c0293ededdcb4b9a5e0e0582f
