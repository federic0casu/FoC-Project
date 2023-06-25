#include "Client.hpp"

static uint32_t menu() {
    uint32_t cmd;
    std::cout << "========== MENU ==========" << std::endl;
    std::cout << "0 - Logout" << std::endl;
    std::cout << "1 - Check Balance" << std::endl;
    std::cout << "2 - Make a Transfer" << std::endl;
    std::cout << "3 - List of Transfers" << std::endl;
    std::cout << "==========================" << std::endl;
    std::cout << "Please enter the desired option: ";
    std::cin >> cmd;
    
    return cmd;
}

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

        uint32_t cmd = 0;

        do {
            cmd = menu();
            switch(cmd) {
                case 0  : break;
                case 1  : client.balance(); break;
                case 2  : client.transfer(); break;
                case 3  : client.list(); break;
                default : std::cout << "Operation not known. Please, try again..." << std::endl;
            }
        } while (cmd != 0);
    } catch (const std::runtime_error& e) {
        std::cerr << e.what() << std::endl;
        return -1;
    }
    std::cout << std::endl << "Bye Bye..." << std::endl;
    return 0;
}
