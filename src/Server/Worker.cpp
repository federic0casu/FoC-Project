#include "Worker.hpp"

Worker::Worker(jobs_t* jobs) 
{
    this->jobs = jobs;
    this->iv.resize(AES_BLOCK_SIZE);
    this->hmac_key.resize(SESSION_KEY_LENGHT);
    this->session_key.resize(SESSION_KEY_LENGHT);
}

void Worker::Run() 
{
    while (true) {
        {
            std::unique_lock<std::mutex> lock(jobs->socket_mutex);
            jobs->socket_cv.wait(lock, [&]() { return !jobs->socket_queue.empty() || jobs->stop; });

            if (jobs->stop) 
            {
                #ifdef DEBUG
                std::cout << BLUE_BOLD << "[WORKER]" << RESET << " >> stop" << std::endl;
                #endif
                return;
            }

            client_socket = jobs->socket_queue.front();
            jobs->socket_queue.erase(jobs->socket_queue.begin());
        }

        #ifdef DEBUG
        std::cout << BLUE_BOLD << "[WORKER]" << RESET 
                  << " >> Client connected (socket: "
                  << client_socket << ")." << std::endl;
        #endif

        try {
            Handshake();

            ClientReq request;
            while(true) 
            {
                request = RequestHandler();

                #ifdef DEBUG
                std::cout << BLUE_BOLD << "[WORKER]" << RESET << " >> ";
                std::cout << "Client " << client_socket << " -> " 
                        << request.request_code << ":" 
                        << request.recipient << ":" 
                        << request.amount << std::endl;
                #endif 

                switch(request.request_code) 
                {
                    case CODE_BALANCE_REQUEST: {
                        BalanceHandler();
                        break;
                    }
                    case CODE_TRANSFER_REQUEST: {
                        TransferHandler();
                        break;
                    }
                    case CODE_LIST_REQUEST: {
                        ListHandler();
                        break;
                    }
                    default: throw std::runtime_error("\033[1;31m[ERROR]\033[0m Bad format message (request_code not known)");
                }
            }
        }
        catch(std::runtime_error& e) {
            #ifdef DEBUG
            std::cout << BLUE_BOLD << "[WORKER]" << RESET << " >> ";
            #endif
            std::cerr << e.what() << std::endl;
            close(client_socket);

            // Something went wrong: we need to clear the session (session key and HMAC key).

            continue;
        }

        #ifdef DEBUG
        std::cout << BLUE_BOLD << "[WORKER]" << RESET << " >> " 
                << "Client disconnected (socket: " 
                << client_socket << ")." << std::endl;
        #endif
    }

}

ClientReq Worker::RequestHandler()
{
    std::vector<uint8_t> buffer(SessionMessage::get_size(REQUEST_PACKET_SIZE));

    Receive(buffer, SessionMessage::get_size(REQUEST_PACKET_SIZE));

    SessionMessage encrypted_request = SessionMessage::deserialize(buffer, REQUEST_PACKET_SIZE);
    buffer.clear();

    #ifdef DEBUG
    std::cout << BLUE_BOLD << "[WORKER]" << RESET << " >> "
              << "Incoming encrypted message..." << std::endl;
    encrypted_request.print();
    #endif 

    if(!encrypted_request.verify_HMAC(this->hmac_key.data()))
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m HMAC verification: FAILED.");

    std::vector<uint8_t> plaintext(REQUEST_PACKET_SIZE);
    encrypted_request.decrypt(this->session_key, plaintext);

    return ClientReq::deserialize(plaintext);
}

void Worker::BalanceHandler()
{
    #ifdef DEBUG
    std::cout << BLUE_BOLD << "[WORKER]" << RESET << " >> "
            << "balance (socket: " 
            << client_socket << ")." << std::endl;
    #endif
}

void Worker::TransferHandler()
{
    #ifdef DEBUG
    std::cout << BLUE_BOLD << "[WORKER]" << RESET << " >> "
            << "transfer (socket: " 
            << client_socket << ")." << std::endl;
    #endif
}

void Worker::ListHandler()
{
    std::vector<row_data_t> list = ListByUsername("transactions/Alice.txt");
    unsigned int n = list.size(); 
    
    List response(CODE_LIST_RESPONSE_1, n);
    std::vector<uint8_t> plaintext(LIST_RESPONSE_1_SIZE);
    response.serialize(plaintext);

    SessionMessage encrypted_response(this->session_key, this->hmac_key, plaintext);
    
    #ifdef DEBUG
    std::cout << BLUE_BOLD << "[WORKER]" << RESET << " >> "
              << "Sending encrypted message..." << std::endl;
    encrypted_response.print();
    #endif

    std::vector<uint8_t> to_send = encrypted_response.serialize();
    Send(to_send);

    plaintext.clear();
    plaintext.resize(LIST_RESPONSE_2_SIZE);
 
    for (row_data_t& transaction : list)
    {
        List response(CODE_LIST_RESPONSE_2, 
                    transaction.amount, 
                    reinterpret_cast<uint8_t*>(const_cast<char*>(transaction.dest.data())), 
                    sizeof(uint8_t[USER_SIZE]), 
                    reinterpret_cast<std::time_t>(transaction.timestamp));
        response.serialize(plaintext);

        SessionMessage encrypted_response(this->session_key, this->hmac_key, plaintext);
    
        #ifdef DEBUG
        std::cout << BLUE_BOLD << "[WORKER]" << RESET << " >> "
                    << "Sending encrypted message..." << std::endl;
        encrypted_response.print();
        #endif

        std::vector<uint8_t> to_send = encrypted_response.serialize();
        Send(to_send);

        plaintext.clear();
        plaintext.resize(LIST_RESPONSE_2_SIZE);
    }
}

void Worker::Handshake() {

    /* ---------------------- RECEIVING M1 ----------------------*/
    
    // Allocate a buffer to receive M1 message.
    std::vector<uint8_t> handshake_m1(HandshakeM1::GetSize());

    try {
        Receive(handshake_m1, HandshakeM1::GetSize());
    } catch(...) {
        handshake_m1.clear();
        throw;
    }

    // Deserialize M1
    HandshakeM1 m1 = HandshakeM1::Deserialize(handshake_m1.data());

    #ifdef DEBUG
    std::cout << BLUE_BOLD << "[WORKER]" << RESET << " >> "
              << "Incoming encrypted message..." << std::endl;
    m1.print();
    #endif

    std::string server_pkey_path = "../res/private_keys/server_privkey.pem";
    
    // extract the server private key
    BIO * bp = nullptr;
    bp = BIO_new_file(server_pkey_path.c_str(), "r");
    if (!bp) 
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Worker::Handshake() >> Failed to open private key file.");

    EVP_PKEY* private_key = PEM_read_bio_PrivateKey(bp, NULL, NULL, NULL);
    BIO_free(bp); 
    if (!private_key) 
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Worker::Handshake() >> Failed to read private key.");

    DiffieHellman* dh = nullptr;
    EVP_PKEY* ephemeral_key = nullptr;
    EVP_PKEY* peer_ephemeral_key = nullptr;

    try {
        dh = new DiffieHellman();
        ephemeral_key = dh->generateEphemeralKey();
        peer_ephemeral_key = DiffieHellman::deserializeKey(m1.ephemeral_key, m1.key_size);
    } catch(...) {
        if (peer_ephemeral_key != nullptr) 
            EVP_PKEY_free(peer_ephemeral_key);
        if (ephemeral_key != nullptr)  
            EVP_PKEY_free(ephemeral_key);
        if (dh != nullptr) 
            delete dh;
        throw;
    }

    /* ---------------------- SESSION KEYS GENERATION ----------------------*/

    // generate the shared secret
    uint8_t* secret = nullptr;
    size_t secret_size = 0;
    int res = dh->generateSharedSecret(ephemeral_key, peer_ephemeral_key, secret, secret_size);
    EVP_PKEY_free(peer_ephemeral_key);
    delete dh;
    if (res < 0) 
    {
        if(secret != nullptr) 
        {
            std::memset(reinterpret_cast<void*>(secret), 0, secret_size);
            delete[] secret;
        }
        EVP_PKEY_free(ephemeral_key);
        EVP_PKEY_free(private_key);
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Worker::Handshake() >> Failed to generate shared secret.");
    }
    
    // generate the session and the hmac keys from the shared secret
    uint8_t* keys = nullptr;
    uint32_t keys_size;

    try {
        SHA_512::generate(secret, secret_size, keys, keys_size);
    } catch(...) {
        std::memset(reinterpret_cast<void*>(secret), 0, secret_size);
        delete[] secret;
        if (keys != nullptr) {
            std::memset(reinterpret_cast<void*>(keys), 0, keys_size);
            delete[] keys;
        }
        EVP_PKEY_free(ephemeral_key);
        EVP_PKEY_free(private_key);
        throw;
    }

    std::memset(reinterpret_cast<void*>(secret), 0, secret_size);
    delete[] secret;

    std::memcpy(this->session_key.data(), keys, (keys_size/2) * sizeof(uint8_t));
    std::memcpy(this->hmac_key.data(), keys + ((keys_size/2) * sizeof(uint8_t)), HMAC_DIGEST_SIZE * sizeof(uint8_t));
    std::memset(reinterpret_cast<void*>(keys), 0, keys_size);
    delete[] keys;

    /* ----------------------SERVER  CERTIFICATE----------------------*/

    string certificate_filename = "../res/cert/server_certificate.pem";
    CertificateStore* certificate_store = CertificateStore::getStore();
    X509* certificate = certificate_store->load(certificate_filename);

    uint8_t *serialized_certificate = nullptr;
    int serialized_certificate_size = 0;
    CertificateStore::serializeCertificate(certificate, serialized_certificate, serialized_certificate_size);
    X509_free(certificate);
    
    /* ---------------------- SERIALIZE OWN EPHEMERAL KEY ----------------------*/
    
    uint8_t* serialized_ephemeral_key = nullptr;
    int serialized_ephemeral_key_size;
    res = DiffieHellman::serializeKey(ephemeral_key, serialized_ephemeral_key, serialized_ephemeral_key_size);
    EVP_PKEY_free(ephemeral_key);
    if (res < 0) 
    {
        EVP_PKEY_free(private_key);
        if (serialized_certificate != nullptr) {
            std::memset(reinterpret_cast<void*>(serialized_certificate), 0, serialized_certificate_size);
            delete[] serialized_certificate;
        }
        if (serialized_ephemeral_key != nullptr) {
            std::memset(reinterpret_cast<void*>(serialized_ephemeral_key), 0, serialized_ephemeral_key_size);
            delete[] serialized_ephemeral_key;
        }
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Worker::Handshake() >> Failed to serialize ephemeral key.");
    }

    // prepare <g^a,g^b>
    int ephemeral_keys_buffer_size = m1.key_size + serialized_ephemeral_key_size;
    uint8_t* ephemeral_keys_buffer = new uint8_t[ephemeral_keys_buffer_size];
    std::memcpy(ephemeral_keys_buffer, m1.ephemeral_key, m1.key_size * sizeof(uint8_t));
    std::memcpy(ephemeral_keys_buffer + m1.key_size * sizeof(uint8_t), serialized_ephemeral_key, serialized_ephemeral_key_size);

    // calculate digest(<g^a,g^b>)_s
    unsigned char *_signature;
    unsigned int signature_size;
    DigitalSignature::generate(ephemeral_keys_buffer, ephemeral_keys_buffer_size, _signature, signature_size, private_key);
    EVP_PKEY_free(private_key);

    // calculate {<g^a,g^b>_s}_Ksess
    std::vector<uint8_t> iv(EVP_CIPHER_iv_length(EVP_aes_256_cbc()));
    std::vector<uint8_t> signature(signature_size);
    std::vector<uint8_t> ciphertext;
    std::memcpy(signature.data(), _signature, signature_size);
    AES_CBC* encryptor = new AES_CBC(ENCRYPT, session_key);
    encryptor->run(signature, ciphertext, iv);
    std::memset(reinterpret_cast<void*>(_signature), 0, signature_size * sizeof(uint8_t));
    signature.clear();
    delete[] _signature;

    HandshakeM2 m2(serialized_ephemeral_key, serialized_ephemeral_key_size, iv.data(), ciphertext.data(), serialized_certificate, serialized_certificate_size);
    uint8_t *_serialized_packet = new uint8_t[HandshakeM2::getSize()];
    _serialized_packet = m2.serialize();
    std::vector<uint8_t> serialized_packet(_serialized_packet, _serialized_packet + HandshakeM2::getSize() * sizeof(uint8_t));
    Send(serialized_packet);
    delete[] _serialized_packet;
    delete[] serialized_certificate;
    delete[] serialized_ephemeral_key;
    if (res < 0) {
        delete[] ephemeral_keys_buffer;
        return ;
    }

    serialized_packet.clear();
    serialized_packet.resize(HandshakeM3::getSize());
    
    try {
        Receive(serialized_packet, HandshakeM3::getSize());
    } catch(...) {
        throw;
    }

    HandshakeM3 m3 = HandshakeM3::deserialize(serialized_packet.data());

    // decrypt the encrypted digital signature
    std::vector<uint8_t> decrypted_signature;
    AES_CBC* decryptor = new AES_CBC(DECRYPT, session_key);
    iv.clear();
    iv.resize(AES_BLOCK_SIZE * sizeof(uint8_t));
    std::memcpy(iv.data(), m3.iv, AES_BLOCK_SIZE * sizeof(uint8_t));
    std::vector<uint8_t> encrypted_signature(ENCRYPTED_SIGNATURE_SIZE * sizeof(uint8_t));
    std::memcpy(encrypted_signature.data(), m3.encrypted_signature, ENCRYPTED_SIGNATURE_SIZE * sizeof(uint8_t));
    decryptor->run(encrypted_signature, decrypted_signature, iv);
    delete decryptor;

    char file_name[sizeof("../res/public_keys/") + sizeof(m1.username) + sizeof("_pubkey.pem")];
    std::sprintf(file_name, "../res/public_keys/%s_pubkey.pem", m1.username);
    bp = BIO_new_file(reinterpret_cast<const char*>(file_name), "r");
    EVP_PKEY* user_public_key = nullptr;
    if (!bp) 
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Worker::Handshake() >> Failed to open client's public key."); 
    else {
        std::sprintf(reinterpret_cast<char*>(this->username), "%s", m1.username);
        user_public_key = PEM_read_bio_PUBKEY(bp, NULL, NULL, NULL);
    }
    BIO_free(bp);

    // qua invece che controllare la signature con le ephemeral devo controllare con la password cifrata che ho preso dall'archivio dell'utente
    bool signature_verification = DigitalSignature::verify(ephemeral_keys_buffer, ephemeral_keys_buffer_size, decrypted_signature.data(), decrypted_signature.size(), user_public_key);
    EVP_PKEY_free(user_public_key);
    delete[] ephemeral_keys_buffer;
    if (signature_verification)
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Worker::Handshake() >> Invalid signature.");
}

ssize_t Worker::Receive(std::vector<uint8_t>& buffer, ssize_t buffer_size) {
    ssize_t total_bytes_received = 0;

    while (total_bytes_received < buffer_size) {
        ssize_t bytes_received = recv(client_socket, (void*)(buffer.data() + total_bytes_received), buffer_size - total_bytes_received, 0);

        if (bytes_received == -1)
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m Worker::Receive() >> Failed to receive data");

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
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m Worker::Receive() >> Failed to send data");

        total_bytes_sent += bytes_sent;
    }

    return total_bytes_sent;
}

std::vector<row_data_t> Worker::ListByUsername(const std::string& filename)
{
    std::vector<row_data_t> rows;
    std::ifstream file(filename);

    if (!file.is_open())
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Worker::ListByUsername() >> Failed to open the file");

    std::string line;
    while (std::getline(file, line)) 
    {
        row_data_t row;
        row.dest = "";
        std::istringstream iss(line);
        if (iss >> row.dest >> row.amount >> row.timestamp)
            rows.push_back(row);
        else
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m Worker::ListByUsername() >> Failed to parse a line in the file");
    }

    file.close();
    return rows;
}


void Worker::AppendTransactionByUsername(const std::string& filename, const row_data_t& row)
{
    std::ofstream file(filename, std::ios::app);

    if (!file.is_open())
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Worker::AppendTransactionByUsername() >> Failed to open the file for appending");

    file << row.dest << " " << row.amount << " " << row.timestamp << "\n";

    file.close();
}
