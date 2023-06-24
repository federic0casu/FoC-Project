#include "Client.hpp"

int main(int argc, char* argv[])
{
    if(argc != 2) {
	    std::cerr << "Correct usage: ./serv SERVER_PORT" << std::endl;
        return -1;
    }

    try {
        OpenSSL_add_all_algorithms();

        std::string server_ip = "127.0.0.1";
        Client client(server_ip, atoi(argv[1]));
        client.connect_to_server();

        client.handshake();

        // test
        client.balance();
        //client.transfer();
        //client.list();
    } 
    catch (const std::runtime_error& e) {
        std::cerr << e.what() << std::endl;
        return -1;
    }
    return 0;
}
