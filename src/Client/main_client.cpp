#include "Client.hpp"
#include "../Packet/ClientReq.h"

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

        // KEY EXCHANGE and AUTHENTICATION

        // test
        uint8_t recipient[32] = "berlusca";
        ClientReq req(5,recipient);
        std::cout << "Codice della richiesta: "<< (char)req.request_code << "amount:" << req.amount <<  std::endl; 
        uint8_t* message = req.serialize();
        std::cout << "Dimesione del pacchetto di richiesta" << req.getSize() << std::endl;
        client.send_request(message,req.getSize());
    } 
    catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        exit(-1);
    }

    exit(0);
}
