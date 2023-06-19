#include "Client.hpp"

Client::Client(const std::string& server_ip, int server_port)
{
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
}

void Client::connect_to_server()
{
    if (connect(sock_fd, (struct sockaddr*)&server_address, sizeof(server_address)) == -1)
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Failed to connect to the server.");

    std::cout << "Connected to the server." << std::endl;
}

void Client::balance()
{
    try {
        unsigned char padding[] = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        ClientReq balance_request(CODE_BALANCE_REQUEST, 0, padding);

        #ifdef DEBUG
        std::cout << "[1] balance ->\t" << balance_request.request_code << ":" << balance_request.recipient << ":" << balance_request.amount << std::endl;
        #endif 

        std::vector<uint8_t> plaintext(REQUEST_PACKET_SIZE);
        balance_request.serialize(plaintext);

        SessionMessage encrypted_request(session_key, hmac_key, plaintext);

        #ifdef DEBUG
        std::cout << "Sending encrypted message..." << std::endl;
        encrypted_request.print();
        #endif

        std::vector<uint8_t> to_send = encrypted_request.serialize();
        send_to_server(to_send);
    }
    catch(std::runtime_error& e) {
        std::cerr << e.what() << std::endl;
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

        SessionMessage encrypted_request(session_key, hmac_key, plaintext);
        
        #ifdef DEBUG
        std::cout << "Sending encrypted message..." << std::endl;
        encrypted_request.print();
        #endif

        std::vector<uint8_t> to_send = encrypted_request.serialize();
        send_to_server(to_send);
    }
    catch(std::runtime_error& e) {
        std::cerr << e.what() << std::endl;
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
        
        SessionMessage encrypted_request(session_key, hmac_key, plaintext);
        
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
        encrypted_response_1.decrypt(session_key, plaintext);

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
            encrypted_response_2.decrypt(session_key, plaintext);

            List response_2 = List::deserialize(plaintext);

            std::cout << "\t" << response_2.amount << " -> " << response_2.dest << "\t";
            print_formatted_date(response_2.timestamp);
        }
        /*--------------------------------------------------------------------------------*/

    }
    catch(std::runtime_error& e) {
        std::cerr << e.what() << std::endl;
    }
}

int Client::handshake() {

    #ifdef DEBUG
    std::cout << "START HANDSHAKE" << std::endl;
    #endif 

    unsigned char password[20];
    std::cout << "Insert username: ";
    std::cin >> m_username;
    std::cout << "Insert password: ";
    std::cin >> password;


    DiffieHellman dh;
    EVP_PKEY* ephemeral_key = dh.generateEphemeralKey();

    // Generate ephemeral key
    uint8_t* serialized_ephemeral_key = nullptr;
    int serialized_ephemeral_key_size;
    
    if (DiffieHellman::serializeKey(ephemeral_key, serialized_ephemeral_key, serialized_ephemeral_key_size) < 0) 
    {
        EVP_PKEY_free(ephemeral_key);
        std::memset(reinterpret_cast<void*>(serialized_ephemeral_key), 0, serialized_ephemeral_key_size);
        delete[] serialized_ephemeral_key;
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m handshake() >> Failed to create/serialize DH ephemeral key.");
    }

    HandshakeM1 m1(serialized_ephemeral_key, serialized_ephemeral_key_size, reinterpret_cast<const unsigned char*>(m_username.c_str()));
    #ifdef DEBUG
    m1.print();
    #endif

    std::vector<uint8_t> serialized_m1(HandshakeM1::GetSize());
    m1.serialize(serialized_m1.data());

    try {
        send_to_server(serialized_m1);
    } catch(...) {
        std::memset(reinterpret_cast<void*>(serialized_ephemeral_key), 0, serialized_ephemeral_key_size);
        delete[] serialized_ephemeral_key;
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m handshake() >> Failed to send M1.");
    }

    // aspetto m2 dal server
    std::vector<uint8_t> serialized_packet(HandshakeM2::getSize());
    
    try {
        recv_from_server(serialized_packet);
    } catch(...) {
        EVP_PKEY_free(ephemeral_key);
        std::memset(reinterpret_cast<void*>(serialized_ephemeral_key), 0, serialized_ephemeral_key_size);
        delete[] serialized_ephemeral_key;
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m handshake() >> Failed to receive M2.");
    }

    // open the private key PEM file
    string private_key_file = "../res/keys/daniel_key.pem";
    BIO *bio = BIO_new_file(private_key_file.c_str(), "r");
    if (!bio)
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Handshake() >> Failed to open private key file.");
    
    // encrypt and save the long term private key
    m_long_term_key = PEM_read_bio_PrivateKey(bio, 0, 0, 0);
    BIO_free(bio);

    // check if the password is correct
    if (!m_long_term_key) 
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Handshake() >> Failed to read private key.");

    HandshakeM2 m2 = HandshakeM2::deserialize(serialized_packet.data());
    serialized_packet.clear();

    // retrieve the peer ephemeral key from the M3 packet
    EVP_PKEY* peer_ephemeral_key = DiffieHellman::deserializeKey(m2.ephemeral_key, m2.ephemeral_key_size);

    // generate the shared secret
    uint8_t* shared_secret = nullptr;
    size_t shared_secret_size;    
    int res = dh.generateSharedSecret(ephemeral_key, peer_ephemeral_key, shared_secret, shared_secret_size);
    EVP_PKEY_free(ephemeral_key);
    EVP_PKEY_free(peer_ephemeral_key);
    if (res < 0) {
        std::memset(reinterpret_cast<void*>(shared_secret), 0, shared_secret_size);
        delete[] shared_secret;
        std::memset(reinterpret_cast<void*>(serialized_ephemeral_key), 0, serialized_ephemeral_key_size);
        delete[] serialized_ephemeral_key;
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Handshake() >> Failed to generate shared secret.");
    }
    
    // generate the session key and hmac key
    unsigned char* keys = nullptr;
    unsigned int keys_size;
    SHA_512::generate(shared_secret, shared_secret_size, keys, keys_size);
    std::memcpy(session_key.data(), keys, (keys_size/2) * sizeof(unsigned char));
    std::memcpy(hmac_key.data(), keys + ((keys_size/2) * sizeof(unsigned char)), HMAC_DIGEST_SIZE * sizeof(unsigned char));
    std::memset(reinterpret_cast<void*>(shared_secret), 0, shared_secret_size);
    delete[] shared_secret;
    std::memset(reinterpret_cast<void*>(keys), 0, keys_size);
    delete[] keys;

    // prepare <g^a,g^b>
    int ephemeral_keys_buffer_size = m2.ephemeral_key_size + serialized_ephemeral_key_size;
    uint8_t* ephemeral_keys_buffer = new uint8_t[ephemeral_keys_buffer_size];
    std::memcpy(ephemeral_keys_buffer, serialized_ephemeral_key, serialized_ephemeral_key_size);
    std::memcpy(ephemeral_keys_buffer + serialized_ephemeral_key_size, m2.ephemeral_key, m2.ephemeral_key_size);
    std::memset(reinterpret_cast<void*>(serialized_ephemeral_key), 0, serialized_ephemeral_key_size);
    delete[] serialized_ephemeral_key;

    // questa parte va modificata mettendo la password 
    // calculate <pass>_c
    unsigned char* signature = nullptr;
    unsigned int signature_size;
    DigitalSignature::generate(ephemeral_keys_buffer, ephemeral_keys_buffer_size, signature, signature_size, m_long_term_key);
    std::vector<uint8_t> signature_vector(signature_size);
    std::memcpy(signature_vector.data(), signature, signature_size);

    // calculate {<g^a,g^b>_s}_Ksess
    std::vector<uint8_t> iv(EVP_CIPHER_iv_length(EVP_aes_256_cbc()));
    std::vector<uint8_t> ciphertext;
    AES_CBC* encryptor = new AES_CBC(ENCRYPT, session_key);
    encryptor->run(signature_vector, ciphertext, iv);
    std::memset(reinterpret_cast<void*>(signature), 0, signature_size);
    delete[] signature;
    signature_vector.clear();
    delete encryptor;

    // retrieve and verify the certificate
    X509* server_certificate = CertificateStore::deserializeCertificate(m2.serialized_certificate, m2.serialized_certificate_size);
    CertificateStore* certificate_store = CertificateStore::getStore();
    if (!certificate_store->verify(server_certificate)) {
        X509_free(server_certificate);
        std::memset(reinterpret_cast<void*>(ephemeral_keys_buffer), 0, ephemeral_keys_buffer_size);
        delete[] ephemeral_keys_buffer;
        ciphertext.clear();
        iv.clear();
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Handshake() >> Failed to generate shared secret.");
    }

    // retrieve the server public key 
    EVP_PKEY* server_public_key = certificate_store->getPublicKey(server_certificate); 
    X509_free(server_certificate);

    // decrypt the encrypted digital signature
    std::vector<uint8_t> decrypted_signature;
    std::vector<uint8_t> encrypted_signature(144 * sizeof(uint8_t));
    std::memcpy(encrypted_signature.data(), m2.encrypted_signature, 144 * sizeof(uint8_t));
    std::vector<uint8_t> signature_iv(sizeof(uint8_t) * AES_BLOCK_SIZE);
    std::memcpy(signature_iv.data(), m2.iv, sizeof(uint8_t) * AES_BLOCK_SIZE);
    AES_CBC* decryptor = new AES_CBC(DECRYPT, session_key);
    decryptor->run(encrypted_signature, decrypted_signature, signature_iv);
    delete decryptor;

    // verify the signature
    bool signature_verification = DigitalSignature::verify(ephemeral_keys_buffer, ephemeral_keys_buffer_size, decrypted_signature.data(), decrypted_signature.size(), server_public_key);
    delete[] ephemeral_keys_buffer;
    decrypted_signature.clear();
    EVP_PKEY_free(server_public_key);
    if (signature_verification) 
    {
        ciphertext.clear();
        iv.clear();
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Handshake() >> Failed to verify digital signature.");
    }

    HandshakeM3 m3(iv.data(), ciphertext.data());
    uint8_t* serialized_packet_tmp = m3.serialize();
    serialized_packet.resize(HandshakeM3::getSize());
    std::memcpy(serialized_packet.data(), serialized_packet_tmp, HandshakeM3::getSize());
    try {
        send_to_server(serialized_packet);
    } catch(...) {
        std::memset(reinterpret_cast<void*>(serialized_packet_tmp), 0, HandshakeM3::getSize());
        delete[] serialized_packet_tmp;
        ciphertext.clear();
        iv.clear();
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Handshake() >> Failed to send M3.");
    }

    // reset the counter
    m_counter = 0;

    std::memset(reinterpret_cast<void*>(serialized_packet_tmp), 0, HandshakeM3::getSize());
    delete[] serialized_packet_tmp;
    ciphertext.clear();
    iv.clear();

    #ifdef DEBUG
    std::cout << "END HANDSHAKE" << std::endl;
    #endif 
}

void Client::send_to_server(const std::vector<uint8_t>& buffer)
{
    ssize_t total_bytes_sent = 0;
    ssize_t buffer_size = buffer.size();

    while (total_bytes_sent < buffer_size)
    {
        ssize_t bytes_sent = send(sock_fd, (void*)(buffer.data() + total_bytes_sent), buffer_size - total_bytes_sent, 0);

        if (bytes_sent == -1 && (errno == EPIPE || errno == ECONNRESET))
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m Server disconnected");

        if (bytes_sent == -1)
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m Failed to send data");

        total_bytes_sent += bytes_sent;
    }
}

void Client::recv_from_server(std::vector<uint8_t>& buffer)
{
    ssize_t total_bytes_received = 0;
    ssize_t buffer_size = buffer.size();

    while (total_bytes_received < buffer_size)
    {
        ssize_t bytes_received = recv(sock_fd, (void*)(buffer.data() + total_bytes_received), buffer_size - total_bytes_received, 0);
        
        if (bytes_received == -1)
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m Failed to receive data");

        if (bytes_received == 0)
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m Server disconnected");

        total_bytes_received += bytes_received;
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
