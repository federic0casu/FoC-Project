#include <iostream>
#include <string>
#include <iomanip>
#include <ctime>
#include <cstring>
#include <unistd.h>
#include <stdexcept>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "../Packet/List.hpp"
#include "../Packet/ClientReq.hpp"
#include "../Packet/SessionMessage.hpp"

#include "../Generic/Codes.hpp"
#include "../Generic/Utility.hpp"

class Client {
public:
    Client(const std::string& server_ip, int server_port);
    ~Client();
    void connect_to_server();
    void send_to_server(const std::vector<uint8_t>& buffer);
    void recv_from_server(std::vector<uint8_t>& buffer);
    
    void balance();
    void transfer();
    void list();

private:
    int sock_fd;
    struct sockaddr_in server_address;

    void print_formatted_date(std::time_t timestamp);
};
