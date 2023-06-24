#include "Client.hpp"


Client::Client(const std::string& server_ip, int server_port)
{
    m_long_term_key = nullptr;
    
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (sock_fd == -1)
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Failed to create socket.");

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(server_port);

    if (inet_pton(AF_INET, server_ip.c_str(), &(server_address.sin_addr)) <= 0) 
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Invalid server IP address.");

    hmac_key.resize(SESSION_KEY_LENGHT);
    session_key.resize(SESSION_KEY_LENGHT);
}

Client::~Client()
{
    close(sock_fd);

    m_username.erase(m_username.begin(), m_username.end());
    
    hmac_key.clear();
    session_key.clear();
}

void Client::connect_to_server()
{
    if (connect(sock_fd, (struct sockaddr*)&server_address, sizeof(server_address)) == -1) {
        char error_message[] = "\033[1;31m[ERROR]\033[0m Failed to connect to the server.";
        throw std::runtime_error(error_message);
    }

    std::cout << "Connected to the server." << std::endl;
}

void Client::balance()
{
    try {
        unsigned char padding[] = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        ClientReq balance_request(CODE_BALANCE_REQUEST, 0, padding);

        #ifdef DEBUG
        std::cout << "[1] balance ->\t" 
                  << balance_request.request_code << ":" 
                  << balance_request.recipient << ":" 
                  << balance_request.amount << std::endl;
        #endif 

        std::vector<uint8_t> plaintext(REQUEST_PACKET_SIZE);
        balance_request.serialize(plaintext);

        SessionMessage encrypted_request(this->session_key, this->hmac_key, plaintext);

        #ifdef DEBUG
        std::cout << "Sending encrypted message..." << std::endl;
        encrypted_request.print();
        #endif

        std::vector<uint8_t> to_send = encrypted_request.serialize();
        send_to_server(to_send);
/*
        std::vector<uint8_t> buffer(SessionMessage::get_size(BALANCE_RESPONSE_SIZE));
        recv_from_server(buffer);

        SessionMessage encrypted_response = SessionMessage::deserialize(buffer, BALANCE_RESPONSE_SIZE);

        #ifdef DEBUG
        std::cout << "Incoming encrypted message..." << std::endl;
        encrypted_response.print();
        #endif

        plaintext.resize(BALANCE_RESPONSE_SIZE);
        plaintext.assign(plaintext.size(), 0);
        encrypted_response.decrypt(this->session_key, plaintext);

        BalanceResponse response = BalanceResponse::deserialize(plaintext.data());
        response.print();
*/
    }
    catch(std::runtime_error& e) {
        throw e;
    }
}

void Client::transfer()
{
    try {
        unsigned char padding[] = "TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT";
        ClientReq transfer_request(CODE_TRANSFER_REQUEST, 0, padding);

        #ifdef DEBUG
        std::cout << "[1] transfer ->\t" << transfer_request.request_code << ":" << transfer_request.recipient << ":" << transfer_request.amount << std::endl;
        #endif

        std::vector<uint8_t> plaintext(REQUEST_PACKET_SIZE);
        transfer_request.serialize(plaintext);

        SessionMessage encrypted_request(this->session_key, this->hmac_key, plaintext);
        
        #ifdef DEBUG
        std::cout << "Sending encrypted message..." << std::endl;
        encrypted_request.print();
        #endif

        std::vector<uint8_t> to_send = encrypted_request.serialize();
        send_to_server(to_send);
    }
    catch(std::runtime_error& e) {
        throw e;
    }
}


void Client::list()
{
    try {
        /*--------------- STEP 1: send a list request (request_code: 0x03) ---------------*/
        unsigned char padding[] = "LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL";
        ClientReq list_request(CODE_LIST_REQUEST, 0, padding);

        #ifdef DEBUG
        std::cout << "[1] list ->\t" << list_request.request_code << ":" << list_request.recipient << ":" << list_request.amount << std::endl;
        #endif

        std::vector<uint8_t> plaintext(REQUEST_PACKET_SIZE);
        list_request.serialize(plaintext);
        
        SessionMessage encrypted_request(this->session_key, this->hmac_key, plaintext);
        
        #ifdef DEBUG
        std::cout << "Sending encrypted message..." << std::endl;
        encrypted_request.print();
        #endif

        std::vector<uint8_t> to_send = encrypted_request.serialize();
        send_to_server(to_send);

        /*--------------------------------------------------------------------------------*/

        /*---------- STEP 2: receive number of transactions (response_code 0x06) ---------*/
        std::vector<uint8_t> to_recv(SessionMessage::get_size(LIST_RESPONSE_1_SIZE), 0);
        recv_from_server(to_recv);

        SessionMessage encrypted_response_1 = SessionMessage::deserialize(to_recv, LIST_RESPONSE_1_SIZE);

        #ifdef DEBUG
        std::cout << "Incoming encrypted message..." << std::endl;
        encrypted_response_1.print();
        #endif 

        if(!encrypted_response_1.verify_HMAC(hmac_key.data()))
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m HMAC verification: FAILED.");

        plaintext.resize(LIST_RESPONSE_1_SIZE);
        encrypted_response_1.decrypt(this->session_key, plaintext);

        List response_1 = List::deserialize(plaintext);

        #ifdef DEBUG
        std::cout << "[2] list ->\t" << response_1.code_response << ":" 
                << response_1.dest << ":" 
                << response_1.amount << ":";
        print_formatted_date(response_1.timestamp);
        #endif
        /*--------------------------------------------------------------------------------*/

        /*---------- STEP 3: receive lisy of transactions (response_code 0x06) -----------*/
        auto n = response_1.amount;
        
        for (uint32_t i = 0; i < n; i++)
        {
            to_recv.clear();
            to_recv.resize(SessionMessage::get_size(LIST_RESPONSE_2_SIZE));

            recv_from_server(to_recv);

            SessionMessage encrypted_response_2 = SessionMessage::deserialize(to_recv, LIST_RESPONSE_2_SIZE);

            #ifdef DEBUG
            std::cout << "Incoming encrypted message..." << std::endl;
            encrypted_response_2.print();
            #endif 

            if(!encrypted_response_2.verify_HMAC(hmac_key.data()))
                throw std::runtime_error("\033[1;31m[ERROR]\033[0m HMAC verification: FAILED.");

            plaintext.resize(LIST_RESPONSE_2_SIZE);
            encrypted_response_2.decrypt(this->session_key, plaintext);

            List response_2 = List::deserialize(plaintext);

            std::cout << "\t" << response_2.amount << " -> " << response_2.dest << "\t";
            print_formatted_date(response_2.timestamp);
        }
        /*--------------------------------------------------------------------------------*/

    }
    catch(std::runtime_error& e) {
        throw e;
    }
}

void Client::handshake() 
{
    unsigned char password[20];
    std::cout << ">> Insert username: ";
    std::cin >> m_username;
    std::cout << ">> Insert password: ";
    std::cin >> password;


    DiffieHellman dh;
    EVP_PKEY* ephemeral_key = nullptr;
    try {
        // Generate ephemeral key
        ephemeral_key = dh.generateEphemeralKey();
    } catch(const std::runtime_error& error) {
        std::cerr << error.what() << std::endl;

        if (ephemeral_key != nullptr) 
            EVP_PKEY_free(ephemeral_key); 
        
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Handshake() >> Failed to generate ephemeral key.");
    }

    // Serialize ephemeral key
    std::vector<uint8_t> serialized_ephemeral_key;
    try {
        serialized_ephemeral_key = DiffieHellman::serializeKey(ephemeral_key);
    } catch(const std::runtime_error& error) {
        std::cerr << error.what() << std::endl;

        EVP_PKEY_free(ephemeral_key);
        
        if (!serialized_ephemeral_key.empty()) {
            std::memset(reinterpret_cast<void*>(serialized_ephemeral_key.data()), 0, serialized_ephemeral_key.size());
            serialized_ephemeral_key.clear();
        }

        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Handshake() >> Failed to serialize ephemeral key.");
    }

    HandshakeM1 m1(serialized_ephemeral_key, serialized_ephemeral_key.size(), reinterpret_cast<const unsigned char*>(m_username.c_str()));

    std::vector<uint8_t> serialized_m1;
    m1.serialize(serialized_m1);

    try {
        send_to_server(serialized_m1);
    } catch(const std::runtime_error& error) {
        std::cerr << error.what() << std::endl;

        std::memset(reinterpret_cast<void*>(serialized_ephemeral_key.data()), 0, serialized_ephemeral_key.size());
        serialized_ephemeral_key.clear();

        EVP_PKEY_free(ephemeral_key);

        throw std::runtime_error("\033[1;31m[ERROR]\033[0m handshake() >> Failed to send M1.");
    }


    // Receive the result of existence of the user
    std::vector<uint8_t> serialized_m2(HandshakeM2::GetSize());
    try {
        recv_from_server(serialized_m2);
    } catch(const std::runtime_error& error) {
        std::cerr << error.what() << std::endl;
        
        std::memset(reinterpret_cast<void*>(serialized_ephemeral_key.data()), 0, serialized_ephemeral_key.size());
        serialized_ephemeral_key.clear();

        EVP_PKEY_free(ephemeral_key);

        throw std::runtime_error("\033[1;31m[ERROR]\033[0m handshake() >> Failed to receive M2.");
    }

    HandshakeM2 m2 = HandshakeM2::deserialize(serialized_m2);
    serialized_m2.clear();

    if (m2.result == 0) {
        std::memset(reinterpret_cast<void*>(serialized_ephemeral_key.data()), 0, serialized_ephemeral_key.size());
        serialized_ephemeral_key.clear();

        EVP_PKEY_free(ephemeral_key);

        throw std::runtime_error("\033[1;31m[ERROR]\033[0m handshake() >> Failed authentication.");
        return;
    }

    EVP_PKEY* peer_ephemeral_key = nullptr;
    std::vector<uint8_t> shared_secret;
    size_t shared_secret_size;  
    try {  
        // retrieve the peer ephemeral key from the M2 packet
        peer_ephemeral_key = DiffieHellman::deserializeKey(m2.ephemeral_key.data(), m2.ephemeral_key_size);
        
        // Generate shared secret
        dh.generateSharedSecret(ephemeral_key, peer_ephemeral_key, shared_secret, shared_secret_size);
    } catch(std::runtime_error& e) {
        std::cerr << e.what() << std::endl;
        
        std::memset(reinterpret_cast<void*>(serialized_ephemeral_key.data()), 0, serialized_ephemeral_key.size());
        serialized_ephemeral_key.clear();

        std::memset(reinterpret_cast<void*>(shared_secret.data()), 0, shared_secret.size());
        shared_secret.clear();

        EVP_PKEY_free(ephemeral_key);

        if (peer_ephemeral_key != nullptr)
            EVP_PKEY_free(peer_ephemeral_key);

        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Handshake() >> Failed to generate shared secret.");
    }
    EVP_PKEY_free(ephemeral_key);
    EVP_PKEY_free(peer_ephemeral_key);

    // generate the session and the hmac keys from the shared secret
    std::vector<uint8_t> keys;
    uint32_t keys_size;
    try {
        SHA_512::generate(shared_secret.data(), shared_secret_size, keys, keys_size);
        std::memset(reinterpret_cast<void*>(shared_secret.data()), 0, shared_secret.size());
        shared_secret.clear();
    } catch(std::runtime_error& error) {
        std::cerr << error.what() << std::endl;

        std::memset(reinterpret_cast<void*>(serialized_ephemeral_key.data()), 0, serialized_ephemeral_key.size());
        serialized_ephemeral_key.clear();

        std::memset(reinterpret_cast<void*>(keys.data()), 0, keys.size());
        keys.clear();

        std::memset(reinterpret_cast<void*>(shared_secret.data()), 0, shared_secret.size());
        shared_secret.clear();

        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Handshake() >> Failed to hash shared secret.");
    }

    std::memcpy(this->session_key.data(), keys.data(), (keys.size()/2) * sizeof(uint8_t));
    std::memcpy(this->hmac_key.data(), keys.data() + ((keys.size()/2) * sizeof(uint8_t)), HMAC_DIGEST_SIZE * sizeof(uint8_t));
    
    std::memset(reinterpret_cast<void*>(keys.data()), 0, keys.size());
    keys.clear();

    // prepare <g^a,g^b>
    int ephemeral_keys_buffer_size = m2.ephemeral_key_size + serialized_ephemeral_key.size();
    std::vector<uint8_t> ephemeral_keys_buffer(ephemeral_keys_buffer_size);
    std::memcpy(ephemeral_keys_buffer.data(), serialized_ephemeral_key.data(), serialized_ephemeral_key.size());
    std::memcpy(ephemeral_keys_buffer.data() + serialized_ephemeral_key.size(), m2.ephemeral_key.data(), m2.ephemeral_key_size);
    
    std::memset(reinterpret_cast<void*>(serialized_ephemeral_key.data()), 0, serialized_ephemeral_key.size());
    serialized_ephemeral_key.clear();

    // calculate <g^a,g^b>_privKc
    std::vector<unsigned char> signature;
    try {
        char private_key_path[sizeof("../res/keys/") + sizeof(m_username.c_str()) + sizeof("_privkey.pem")];
        sprintf(private_key_path, "../res/keys/%s_privkey.pem", m_username.c_str());

        // Create an instance of RSASignature with the private key file
        RSASignature rsa(private_key_path, "");

        // Sign the buffer
        signature = rsa.sign(ephemeral_keys_buffer);
    } catch(const std::runtime_error& error) {
        throw error;
    }

    // calculate {<g^a,g^b>_privKc}_Ksess
    std::vector<uint8_t> iv(EVP_CIPHER_iv_length(EVP_aes_256_cbc()));
    std::vector<uint8_t> ciphertext;
    AES_CBC* encryptor = nullptr;
    try {
        encryptor = new AES_CBC(ENCRYPT, this->session_key);
        encryptor->run(signature, ciphertext, iv);
        delete encryptor;

        std::memset(reinterpret_cast<void*>(signature.data()), 0, signature.size());
        signature.clear();
    } catch(...) {
        if (encryptor != nullptr)
            delete encryptor;

        std::memset(reinterpret_cast<void*>(signature.data()), 0, signature.size());
        signature.clear();

        std::memset(reinterpret_cast<void*>(ephemeral_keys_buffer.data()), 0, ephemeral_keys_buffer.size());
        ephemeral_keys_buffer.clear();
        
        throw;
    }

    // decrypt the encrypted digital signature
    std::vector<uint8_t> decrypted_signature;
    AES_CBC* decryptor = nullptr;
    try {
        decryptor = new AES_CBC(DECRYPT, this->session_key);
        decryptor->run(m2.encrypted_signature, decrypted_signature, m2.iv);
        delete decryptor;
        decrypted_signature.resize(DECRYPTED_SIGNATURE_SIZE);
    } catch (const std::runtime_error& error) {
        if (decryptor != nullptr)
            delete decryptor;
        
        std::memset(reinterpret_cast<void*>(decrypted_signature.data()), 0, decrypted_signature.size());
        decrypted_signature.clear();
        
        throw error;
    }

    // verify the signature
    RSASignature* rsa = nullptr;
    bool signature_verification = true;
    try {
        char public_key_path[] = "../res/public_keys/server_pubkey.pem";

        rsa = new RSASignature("", public_key_path);
        signature_verification = rsa->verify(ephemeral_keys_buffer, decrypted_signature);
        delete rsa;
        
        std::memset(reinterpret_cast<void*>(ephemeral_keys_buffer.data()), 0, ephemeral_keys_buffer.size());
        ephemeral_keys_buffer.clear();

        std::memset(reinterpret_cast<void*>(decrypted_signature.data()), 0, decrypted_signature.size());
        decrypted_signature.clear();
    } catch(std::runtime_error& e) {
        std::cerr << e.what() << std::endl;

        if (rsa != nullptr)
            delete rsa;
        
        std::memset(reinterpret_cast<void*>(ephemeral_keys_buffer.data()), 0, ephemeral_keys_buffer.size());
        ephemeral_keys_buffer.clear();

        std::memset(reinterpret_cast<void*>(decrypted_signature.data()), 0, decrypted_signature.size());
        decrypted_signature.clear();

        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Handshake() >> Failed to verify digital signature.");
    }

    if (!signature_verification)
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Handshake() >> Server not authenticated.");


    HandshakeM3 m3(iv, ciphertext);

    std::vector<uint8_t> serialized_m3 = m3.serialize();

    try {
        send_to_server(serialized_m3);

        std::memset(reinterpret_cast<void*>(ciphertext.data()), 0, ciphertext.size());
        ciphertext.clear();

        std::memset(reinterpret_cast<void*>(iv.data()), 0, iv.size());
        iv.clear();
    } catch(...) {
        std::memset(reinterpret_cast<void*>(ciphertext.data()), 0, ciphertext.size());
        ciphertext.clear();

        std::memset(reinterpret_cast<void*>(iv.data()), 0, iv.size());
        iv.clear();
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Handshake() >> Failed to send M3.");
    }

    // reset the counter
    m_counter = 0;
}

void Client::send_to_server(const std::vector<uint8_t>& buffer)
{
    ssize_t bytes_sent = 0;
    ssize_t total_bytes_sent = 0;
    ssize_t buffer_size = buffer.size();

    while (total_bytes_sent < buffer_size)
    {
        bytes_sent = send(sock_fd, reinterpret_cast<const void*>(buffer.data() + total_bytes_sent), buffer_size - total_bytes_sent, 0);

        if (bytes_sent != -1) {
            total_bytes_sent += bytes_sent;
            continue;
        }

        if (bytes_sent == -1 && (errno == EPIPE || errno == ECONNRESET))
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m Server disconnected");

        if (bytes_sent == -1)
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m Failed to send data");

    }
}

void Client::recv_from_server(std::vector<uint8_t>& buffer)
{
    ssize_t bytes_received = 0;
    ssize_t total_bytes_received = 0;
    ssize_t buffer_size = buffer.size();

    while (total_bytes_received < buffer_size)
    {
        bytes_received = recv(sock_fd, reinterpret_cast<void*>(buffer.data() + total_bytes_received), buffer_size - total_bytes_received, 0);
        
        if (bytes_received != -1 && bytes_received != 0) {
            total_bytes_received += bytes_received;
            continue;
        }

        if (bytes_received == -1)
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m Failed to receive data");

        if (bytes_received == 0)
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m Server disconnected");

    }
}

void Client::print_formatted_date(std::time_t timestamp)
{
    std::tm* timeinfo = std::localtime(&timestamp);
    if (timeinfo != nullptr) {
        std::cout << std::setfill('0') << std::setw(2) << timeinfo->tm_mday << ":" // Day
                  << std::setfill('0') << std::setw(2) << (timeinfo->tm_mon + 1) << ":" // Month (+1 because months are zero-based)
                  << (timeinfo->tm_year + 1900) << " " // Year (+1900 because years are counted from 1900)
                  << std::setfill('0') << std::setw(2) << timeinfo->tm_hour << ":" // Hour
                  << std::setfill('0') << std::setw(2) << timeinfo->tm_min << std::endl; // Minute
    }
}
