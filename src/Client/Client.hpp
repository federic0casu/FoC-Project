#include <ctime>
#include <string>
#include <iomanip>
#include <cstring>
#include <iostream>
#include <stdexcept>

#include <unistd.h>
#include <termios.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "../Packet/List.hpp"
#include "../Packet/Balance.hpp"
#include "../Packet/Transfer.hpp"
#include "../Packet/ClientReq.hpp"
#include "../Packet/Handshake.hpp"
#include "../Packet/SessionMessage.hpp"
#include "../Packet/PasswordMessage.hpp"

#include "../Generic/Codes.hpp"
#include "../Generic/Utility.hpp"

#include "../Crypto/DiffieHellman.hpp"

class Client {
public:
    Client(const std::string& server_ip, int server_port);
    ~Client();
    void connect_to_server();
    void send_to_server(const std::vector<uint8_t>& buffer);
    void recv_from_server(std::vector<uint8_t>& buffer);
    
    void handshake();
    void SendPassword(std::string password);

    void balance();
    void transfer();
    void list();

private:
    int sock_fd;
    struct sockaddr_in server_address;

    uint32_t counter; 
    std::vector<uint8_t> hmac_key;
    std::vector<uint8_t> session_key;

    std::string m_username;

    void turnOnEcho();
    void turnOffEcho();
    void CheckCounter(uint32_t received_counter);
    void IncrementCounter();
};
