#include "Client.hpp"

int main(int argc, char* argv[])
{
    if(argc != 2) {
	    std::cerr << "Correct usage: ./serv SERVER_PORT" << std::endl;
        std::exit(-1);
    }
    
    std::string server_ip = "127.0.0.1";

    try {
        Client client(server_ip, atoi(argv[1]));
        client.connect_to_server();

        std::string message = "HELLO";

        client.send_request(message);
    } 
    catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        exit(-1);
    }

    exit(0);
}