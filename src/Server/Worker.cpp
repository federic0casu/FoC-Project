#include "Worker.hpp"

Worker::Worker(int n_workers, jobs_t* jobs) 
{
    this->n_workers = n_workers;
    this->jobs = jobs;
}

void Worker::Run() 
{
    while (true) {
        std::hash<std::thread::id> hasher;
        thread_id = static_cast<int>(hasher(std::this_thread::get_id())) % n_workers;
        
        {
            std::unique_lock<std::mutex> lock(jobs->socket_mutex);
            jobs->socket_cv.wait(lock, [&]() { return !jobs->socket_queue.empty() || jobs->stop; });

            if (jobs->stop) 
            {
                #ifdef DEBUG
                std::cout << BLUE_BOLD << "THREAD[" << thread_id << "]" << RESET << " >> stop" << std::endl;
                #endif
                return;
            }

            client_socket = jobs->socket_queue.front();
            jobs->socket_queue.erase(jobs->socket_queue.begin());
        }

        #ifdef DEBUG
        std::cout << BLUE_BOLD << "THREAD[" << thread_id << "]" << RESET 
                  << " >> Client connected (socket: "
                  << client_socket << ")." << std::endl;
        #endif

        try {
            ClientReq request;
            while(true) 
            {
                request = HandleRequest();

                #ifdef DEBUG
                std::cout << BLUE_BOLD << "THREAD[" << thread_id << "]" << RESET << " >> ";
                std::cout << "Client " << client_socket << " -> " 
                        << request.request_code << ":" 
                        << request.recipient << ":" 
                        << request.amount << std::endl;
                #endif 

                switch(request.request_code) 
                {
                    case CODE_BALANCE_REQUEST: {
                        Balance();
                        break;
                    }
                    case CODE_TRANSFER_REQUEST: {
                        Transfer();
                        break;
                    }
                    case CODE_LIST_REQUEST: {
                        List();
                        break;
                    }
                    default: throw std::runtime_error("\033[1;31m[ERROR]\033[0m Bad format message (on request)");
                }
            }
        }
        catch(std::runtime_error& e) {
            #ifdef DEBUG
            std::cout << BLUE_BOLD << "THREAD[" << thread_id << "]" << RESET << " >> ";
            #endif
            std::cerr << e.what() << std::endl;
            close(client_socket);

            // Something went wrong: we need to clear the session (session key and HMAC key).

            continue;
        }

        #ifdef DEBUG
        std::cout << BLUE_BOLD << "THREAD[" << thread_id << "]" << RESET << " >> Client disconnected (socket: " << client_socket << ")." << std::endl;
        #endif
    }

}

ClientReq Worker::HandleRequest()
{
    std::vector<uint8_t> buffer;
    buffer.resize(REQUEST_PACKET_SIZE);  // Resize the vector to the desired buffer size

    Receive(buffer, REQUEST_PACKET_SIZE);

    return ClientReq::deserialize(buffer);
}

void Worker::Balance()
{
    #ifdef DEBUG
    std::cout << BLUE_BOLD << "THREAD[" << thread_id << "]" << RESET << " >> balance (socket: " << client_socket << ")." << std::endl;
    #endif

}

void Worker::Transfer()
{
    #ifdef DEBUG
    std::cout << BLUE_BOLD << "THREAD[" << thread_id << "]" << RESET << " >> transfer (socket: " << client_socket << ")." << std::endl;
    #endif

}

void Worker::List()
{
    #ifdef DEBUG
    std::cout << BLUE_BOLD << "THREAD[" << thread_id << "]" << RESET << " >> list (socket: " << client_socket << ")." << std::endl;
    #endif
}

ssize_t Worker::Receive(std::vector<uint8_t>& buffer, ssize_t buffer_size) {
    ssize_t total_bytes_received = 0;

    while (total_bytes_received < buffer_size) {
        ssize_t bytes_received = recv(client_socket, (void*)(buffer.data() + total_bytes_received), buffer_size - total_bytes_received, 0);

        if (bytes_received == -1)
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m failed to receive data");

        if (bytes_received == 0) 
        {
            char message[sizeof("Client disconnected (socket: )") + sizeof(int)] = {0};
            sprintf(message, "Client disconnected (socket: %d)", client_socket);
            throw std::runtime_error(message);
        }

        total_bytes_received += bytes_received;
    }
    return total_bytes_received;
}

ssize_t Worker::Send(const std::vector<uint8_t>& buffer) {
    ssize_t total_bytes_sent = 0;
    ssize_t buffer_size = buffer.size();

    while (total_bytes_sent < buffer_size) {
        ssize_t bytes_sent = send(client_socket, (void*)(buffer.data() + total_bytes_sent), buffer_size - total_bytes_sent, 0);

        if (bytes_sent == -1 && (errno == EPIPE || errno == ECONNRESET)) {
            char message[sizeof("Client disconnected (socket: )") + sizeof(int)] = { 0 };
            sprintf(message, "Client disconnected (socket: %d)", client_socket);
            throw std::runtime_error(message);
        }

        if (bytes_sent == -1)
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m failed to send data");

        total_bytes_sent += bytes_sent;
    }

    return total_bytes_sent;
}