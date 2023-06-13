#include "Server.hpp"

// Global flag variable to indicate if Ctrl+C was pressed.
volatile sig_atomic_t g_signal_flag = 0;

// Signal handler function for Ctrl+C
void handle_signal(int signal)
{
    if (signal == SIGINT)
        // Set the flag to indicate that Ctrl+C was pressed
        g_signal_flag = 1;
}

int main(int argc, char* argv[])
{
    int port;
    int n_workers;
    int backlog;

    if(argc != 4) {
	    std::cerr << "Correct usage: ./serv PORT THREADS BACKLOG" << std::endl;
        std::exit(-1);
    }

    try {
	port      = atoi(argv[1]);
        n_workers = atoi(argv[2]);
        backlog   = atoi(argv[3]);

	Server server(port, n_workers, backlog, &g_signal_flag);

        // Set up the signal handler for Ctrl+C (SIGINT)
        std::signal(SIGINT, handle_signal);

        server.accept_connections();
    } 
    catch(std::invalid_argument& e) {
	    std::cerr << e.what() << std::endl;
	    std::exit(-1);
    }
    catch(std::runtime_error& e) {
	    std::cerr << e.what() << std::endl;
	    std::exit(-1);
    }
    catch(std::exception& e) {
        std::cerr << e.what() << std::endl;
    }

    std::cout << std::endl << "Bye Bye..." << std::endl;

    std::exit(0);
}
