#include "Worker.hpp"


Worker::Worker(jobs_t* jobs) : max_list_transfers(4)
{
    this->jobs = jobs;
    this->iv.resize(AES_BLOCK_SIZE);
    this->username.resize(USERNAME_SIZE);
    this->hmac_key.resize(SESSION_KEY_LENGHT);
    this->session_key.resize(SESSION_KEY_LENGHT);
}

Worker::~Worker()
{
    iv.clear();
    username.clear();
    hmac_key.clear();
    session_key.clear();
}

void Worker::Run() 
{
    while (true) 
    {
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

            while(true) {
                ClientReq request = RequestHandler();

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
                        TransferHandler(request.recipient, request.amount);
                        break;
                    }
                    case CODE_LIST_REQUEST: {
                        ListHandler();
                        break;
                    }
                    default: throw std::runtime_error("\033[1;31m[ERROR]\033[0m Bad format message (request_code not known).");
                }

                std::memset(reinterpret_cast<void*>(&request), 0, sizeof(ClientReq));
            }
        } catch(std::runtime_error& ex) {
            std::cerr << BLUE_BOLD << "[WORKER]" << RESET << " >> "
                      << ex.what() << std::endl;
            
            close(client_socket);

            // Something went wrong: we need to clear the session (session key and HMAC key).
            std::memset(reinterpret_cast<void*>(hmac_key.data()), 0, hmac_key.size());
            hmac_key.clear();
            std::memset(reinterpret_cast<void*>(session_key.data()), 0, session_key.size());
            session_key.clear(); 

            continue;
        }
    }
}

ClientReq Worker::RequestHandler()
{
    std::vector<uint8_t> buffer(SessionMessage::get_size(REQUEST_PACKET_SIZE));

    Receive(buffer, SessionMessage::get_size(REQUEST_PACKET_SIZE));

    SessionMessage encrypted_request = SessionMessage::deserialize(buffer, REQUEST_PACKET_SIZE);
    
    std::memset(reinterpret_cast<void*>(buffer.data()), 0, buffer.size());
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
    // Get user's balance
    int amount = -1;
    FileManager* manager = nullptr;

    char file_path[sizeof("../res/archive/account/") + this->username.length() + sizeof(".txt") + 1];
    std::sprintf(file_path, "../res/archive/account/%s.txt", this->username.c_str());

    try {
        manager = new FileManager();
        manager->FindUser(file_path);
        amount = manager->GetAmount();
        delete manager;
    } catch (const std::runtime_error& ex) {
        std::cerr << ex.what() << std::endl;

        if (manager != nullptr)
            delete manager;
    }

    #ifdef DEBUG
    std::cout << BLUE_BOLD << "[WORKER]" << RESET 
              << " >> Balance(): user: " << this->username.c_str()
              << " | amount: " << amount << std::endl;
    #endif 

    BalanceResponse balance_resp(this->counter, amount);

    std::vector<uint8_t> plaintext(BALANCE_RESPONSE_SIZE, 0);
    balance_resp.serialize(plaintext);

    SessionMessage encrypted_response(this->session_key, this->hmac_key, plaintext);
    try {
        std::vector<uint8_t> to_send = encrypted_response.serialize();
        Send(to_send); 
    } catch (const std::runtime_error& ex) {
        throw ex;
    }

    return;
}

void Worker::TransferHandler(uint8_t* recipient, uint32_t msg_amount)
{    
    #ifdef DEBUG
    std::cout << BLUE_BOLD << "[WORKER]" << RESET << " >> "
              << "TransferHandler(): payee is: " << recipient << "." << std::endl;
    #endif

    // Check if destination user exists
    std::string dest_usr(reinterpret_cast<const char *>(recipient));
    std::string account_file_path = "../res/archive/account/" + dest_usr + ".txt";
    
    FileManager dest_user_file;
    if (!dest_user_file.FindUser(account_file_path)) 
    {
        std::cerr << BLUE_BOLD << "[WORKER]" << RESET << " >> "
                  << "TransferHandler(): payee not exists: " << dest_usr << "." << std::endl;
        SendTransferResponse(false);
        return;
    }

    uint8_t buffer[sizeof("../res/archive/account/") + this->username.length() + sizeof(".txt")];
    sprintf(reinterpret_cast<char*>(buffer), "../res/archive/account/%s.txt", this->username.c_str());

    FileManager src_user_file;
    std::string path(reinterpret_cast<const char*>(buffer), sizeof(buffer));
    if (!src_user_file.FindUser(path))
    {
        std::cerr << BLUE_BOLD << "[WORKER]" << RESET << " >> "
                  << "TransferHandler(): Could not load payer (" << this->username.c_str() << ") informations."<< std::endl;
        SendTransferResponse(false);
        return;
    }

    int src_amount = src_user_file.GetAmount();
    if (src_amount < msg_amount) 
    {
        std::cerr << BLUE_BOLD << "[WORKER]" << RESET << " >> "
                  << "TransferHandler(): payer (" << this->username.c_str() << ") does not have enough money."<< std::endl;
        SendTransferResponse(false);
        return;
    }

    int new_src_amount = src_amount - msg_amount;
    int new_dest_amount = dest_user_file.GetAmount() + msg_amount;

    if (!src_user_file.SetAmount(new_src_amount)) 
    {
        std::cerr << BLUE_BOLD << "[WORKER]" << RESET << " >> "
                  << "TransferHandler(): Could not update payer's (" << this->username.c_str() << ") balance."<< std::endl;
        SendTransferResponse(false);
        return;
    }

    if (!dest_user_file.SetAmount(new_dest_amount)) 
    {
        std::cerr << BLUE_BOLD << "[WORKER]" << RESET << " >> "
                  << "TransferHandler(): Could not update payee's (" << dest_usr << ") balance." << std::endl;
        SendTransferResponse(false);
        return;
    }

    std::string transfer_file_path = "../res/archive/transfers/" + this->username + ".txt";
    TransferManager transfer;
    transfer.writeTransfer(transfer_file_path, msg_amount, dest_usr);

    SendTransferResponse(true);
}


void Worker::ListHandler()
{
    /*-------- PARTE 1 : MANDA IL NUMERO DI TRANSAZIONI CHE SPEDIRAI --------*/

    // prendi il nome dell'utente e calcola la path
    std::string src_username(reinterpret_cast<const char *>(username.c_str()));
    std::string file_path = "../res/archive/transfers/" + src_username + ".txt";

    // calcola il numero di trasferimenti e mandalo 
    TransferManager transfer;
    int transaction_num = transfer.getTransferCount(file_path);

    if (transaction_num >= this->max_list_transfers)
        transaction_num = this->max_list_transfers;

    ListM1 listm1(this->counter, transaction_num);

    std::vector<uint8_t> plaintext(LIST_RESPONSE_1_SIZE);
    listm1.serialize(plaintext.data());

    SessionMessage encrypted_response(this->session_key, this->hmac_key, plaintext);
    std::vector<uint8_t> to_send = encrypted_response.serialize();
    Send(to_send);

    to_send.clear();
    /*------------------- PARTE 2 : MANDA LE TRANSAZIONI -----------------*/

    for (int i = 0; i < transaction_num; i++) {

        std::string row_to_deserialize = transfer.readNextTransfer(i,file_path);

        // deserializza e manda il messaggio

        std::stringstream ss(row_to_deserialize);
        std::string field;

        ListM2 listm2;

        // DESERIALIZZA LA STRINGA 

        std::getline(ss, field, ':');
        std::memcpy(listm2.recipient, field.c_str(), sizeof(listm2.recipient));

        std::getline(ss, field, ':');
        listm2.amount = std::stol(field); 

        std::getline(ss, field, ':');
        listm2.timestamp = std::stoll(field);

        listm2.counter = counter;

        std::cout << "Worker(): " << std::endl;
        listm2.print();
        // SPEDISCI
        std::vector<uint8_t> plaintext(LIST_RESPONSE_2_SIZE);
        listm2.serialize(plaintext.data());

        SessionMessage encrypted_response(this->session_key, this->hmac_key, plaintext);
        std::vector<uint8_t> to_send = encrypted_response.serialize();
        Send(to_send);

    }
}

void Worker::Handshake() 
{    
    // Allocate a buffer to receive M1 message.
    std::vector<uint8_t> serialized_m1(HandshakeM1::GetSize());
    try {
        // Receive M1 message.
        Receive(serialized_m1, HandshakeM1::GetSize());
    } catch(const std::runtime_error& ex) {
        std::cerr << ex.what() << std::endl;
        return;
    }

    // Deserialize M1
    HandshakeM1 m1 = HandshakeM1::Deserialize(serialized_m1);

    if (!ClientExists(m1.username, m1.username_size))
        return;
    
    DiffieHellman* dh = nullptr;
    EVP_PKEY* ephemeral_key = nullptr;
    EVP_PKEY* peer_ephemeral_key = nullptr;    
    try {
        dh = new DiffieHellman();

        // generate the ephemeral_key (that contains private and public keys)
        ephemeral_key = dh->generateEphemeralKey();

        // retrieve the peer ephemeral key from the M1 packet
        peer_ephemeral_key = DiffieHellman::deserializeKey(m1.ephemeral_key, m1.ephemeral_key_size);
    } catch(const std::runtime_error& ex) {

        if (dh != nullptr) 
            delete dh;
        if (ephemeral_key != nullptr) 
            EVP_PKEY_free(ephemeral_key); 
        if (peer_ephemeral_key != nullptr) 
            EVP_PKEY_free(peer_ephemeral_key);
        
        throw ex;
    }

    // generate the shared secret
    std::vector<uint8_t> shared_secret;
    size_t shared_secret_size;
    try {
        dh->generateSharedSecret(ephemeral_key, peer_ephemeral_key, shared_secret, shared_secret_size);

        EVP_PKEY_free(peer_ephemeral_key);

        delete dh;
        dh = nullptr;
    } catch(const std::runtime_error& ex) {
        
        std::memset(reinterpret_cast<void*>(shared_secret.data()), 0, shared_secret.size());
        shared_secret.clear();

        if (dh != nullptr)
            delete dh;

        EVP_PKEY_free(ephemeral_key);
        EVP_PKEY_free(peer_ephemeral_key);
    
        throw ex;
    }
        
    // generate the session and the hmac keys from the shared secret
    std::vector<uint8_t> keys;
    uint32_t keys_size;
    try {
        SHA_512::generate(shared_secret.data(), shared_secret_size, keys, keys_size);

        std::memset(reinterpret_cast<void*>(shared_secret.data()), 0, shared_secret.size());
        shared_secret.clear();
    } catch(...) {
        std::memset(reinterpret_cast<void*>(keys.data()), 0, keys.size());
        keys.clear();

        std::memset(reinterpret_cast<void*>(shared_secret.data()), 0, shared_secret.size());
        shared_secret.clear();
        
        EVP_PKEY_free(ephemeral_key);
        throw;
    }

    std::memcpy(this->session_key.data(), keys.data(), (keys.size()/2) * sizeof(uint8_t));
    std::memcpy(this->hmac_key.data(), keys.data() + ((keys.size()/2) * sizeof(uint8_t)), HMAC_DIGEST_SIZE * sizeof(uint8_t));
    
    std::memset(reinterpret_cast<void*>(keys.data()), 0, keys.size());
    keys.clear();
    
    std::vector<uint8_t> serialized_ephemeral_key;
    try {
        serialized_ephemeral_key = DiffieHellman::serializeKey(ephemeral_key);
    } catch(...) {
        EVP_PKEY_free(ephemeral_key);

        std::memset(reinterpret_cast<void*>(serialized_ephemeral_key.data()), 0, serialized_ephemeral_key.size());
        serialized_ephemeral_key.clear();

        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Handshake() >> Failed to serialize ephemeral key.");
    }
    EVP_PKEY_free(ephemeral_key);

    // prepare <g^a,g^b>
    auto ephemeral_keys_buffer_size = m1.ephemeral_key_size + serialized_ephemeral_key.size();
    std::vector<uint8_t> ephemeral_keys_buffer(ephemeral_keys_buffer_size);
    std::memcpy(ephemeral_keys_buffer.data(), m1.ephemeral_key, m1.ephemeral_key_size);
    std::memcpy(ephemeral_keys_buffer.data() + m1.ephemeral_key_size, serialized_ephemeral_key.data(), serialized_ephemeral_key.size());
        
    // calculate <g^a,g^b>_privKs
    std::vector<unsigned char> signature;
    RSASignature* rsa = nullptr;
    try {
        // Create an instance of RSASignature with the private key file
        rsa = new RSASignature(server_private_key_path.c_str(), "");

        // Sign the buffer
        signature = rsa->sign(ephemeral_keys_buffer);

        delete rsa;
        rsa = nullptr;
    } catch(const std::runtime_error& ex) {
        std::memset(reinterpret_cast<void*>(ephemeral_keys_buffer.data()), 0, ephemeral_keys_buffer.size());
        ephemeral_keys_buffer.clear();
        
        std::memset(reinterpret_cast<void*>(ephemeral_keys_buffer.data()), 0, ephemeral_keys_buffer.size());
        ephemeral_keys_buffer.clear();

        std::memset(reinterpret_cast<void*>(serialized_ephemeral_key.data()), 0, serialized_ephemeral_key.size());
        serialized_ephemeral_key.clear();

        if (rsa != nullptr)
            delete rsa;

        throw ex;
    }

    // calculate {<g^a,g^b>_privKs}_Ksess
    std::vector<uint8_t> iv(EVP_CIPHER_iv_length(EVP_aes_256_cbc()));
    std::vector<uint8_t> ciphertext;
    AES_CBC* encryptor = nullptr;
    try {
        encryptor = new AES_CBC(ENCRYPT, session_key);
        encryptor->run(signature, ciphertext, iv);

        delete encryptor;
        encryptor = nullptr;

        std::memset(reinterpret_cast<void*>(signature.data()), 0, signature.size());
        signature.clear();
    } catch(...) {
        if (encryptor != nullptr)
            delete encryptor;

        std::memset(reinterpret_cast<void*>(iv.data()), 0, iv.size());
        iv.clear();

        std::memset(reinterpret_cast<void*>(signature.data()), 0, signature.size());
        signature.clear();

        std::memset(reinterpret_cast<void*>(ciphertext.data()), 0, ciphertext.size());
        ciphertext.clear();
        
        std::memset(reinterpret_cast<void*>(ephemeral_keys_buffer.data()), 0, ephemeral_keys_buffer.size());
        ephemeral_keys_buffer.clear();

        std::memset(reinterpret_cast<void*>(serialized_ephemeral_key.data()), 0, serialized_ephemeral_key.size());
        serialized_ephemeral_key.clear();

        throw;
    }

    try {
        HandshakeM2 m2(serialized_ephemeral_key, iv, ciphertext);
        std::vector<uint8_t> serialized_m2 = m2.serialize();

        Send(serialized_m2);
        
        std::memset(reinterpret_cast<void*>(iv.data()), 0, iv.size());
        iv.clear();

        std::memset(reinterpret_cast<void*>(ciphertext.data()), 0, ciphertext.size());
        ciphertext.clear();

        std::memset(reinterpret_cast<void*>(serialized_ephemeral_key.data()), 0, serialized_ephemeral_key.size());
        serialized_ephemeral_key.clear();
    } catch(const std::runtime_error& ex) {
        
        std::memset(reinterpret_cast<void*>(iv.data()), 0, iv.size());
        iv.clear();

        std::memset(reinterpret_cast<void*>(ciphertext.data()), 0, ciphertext.size());
        ciphertext.clear();

        std::memset(reinterpret_cast<void*>(ephemeral_keys_buffer.data()), 0, ephemeral_keys_buffer.size());
        ephemeral_keys_buffer.clear();

        std::memset(reinterpret_cast<void*>(serialized_ephemeral_key.data()), 0, serialized_ephemeral_key.size());
        serialized_ephemeral_key.clear();

        throw ex;
    }

    std::vector<uint8_t> serialized_m3(HandshakeM3::GetSize());
    try {
        Receive(serialized_m3, HandshakeM3::GetSize());
    } catch(const std::runtime_error& ex) {    
        std::memset(reinterpret_cast<void*>(ephemeral_keys_buffer.data()), 0, ephemeral_keys_buffer.size());
        ephemeral_keys_buffer.clear();

        throw ex;
    }

    HandshakeM3 m3 = HandshakeM3::deserialize(serialized_m3);

    // decrypt the encrypted digital signature
    std::vector<uint8_t> decrypted_signature;
    AES_CBC* decryptor = nullptr;
    try {
        decryptor = new AES_CBC(DECRYPT, session_key);
        decryptor->run(m3.encrypted_signature, decrypted_signature, m3.iv);
        decrypted_signature.resize(DECRYPTED_SIGNATURE_SIZE);

        delete decryptor;
        decryptor = nullptr;

    } catch(const std::exception& ex) {
        if (decryptor != nullptr)
            delete decryptor;

        std::memset(reinterpret_cast<void*>(decrypted_signature.data()), 0, decrypted_signature.size());
        decrypted_signature.clear();
        
        std::memset(reinterpret_cast<void*>(ephemeral_keys_buffer.data()), 0, ephemeral_keys_buffer.size());
        ephemeral_keys_buffer.clear();
        
        throw ex;
    }

    bool signature_verification = false;
    try {
        char* client_public_key_path = new char[sizeof("../res/public_keys/") + username.size() + sizeof("_pubkey.pem")];
        std::sprintf(client_public_key_path, "../res/public_keys/%s_pubkey.pem", username.data());

        RSASignature rsa("", client_public_key_path);
        delete[] client_public_key_path;

        signature_verification = rsa.verify(ephemeral_keys_buffer, decrypted_signature);

        std::memset(reinterpret_cast<void*>(decrypted_signature.data()), 0, decrypted_signature.size());
        decrypted_signature.clear();

        std::memset(reinterpret_cast<void*>(ephemeral_keys_buffer.data()), 0, ephemeral_keys_buffer.size());
        ephemeral_keys_buffer.clear();
    } catch(const std::runtime_error& ex) {
        std::memset(reinterpret_cast<void*>(decrypted_signature.data()), 0, decrypted_signature.size());
        decrypted_signature.clear();

        std::memset(reinterpret_cast<void*>(ephemeral_keys_buffer.data()), 0, ephemeral_keys_buffer.size());
        ephemeral_keys_buffer.clear();

        throw ex;
    }

    if (!signature_verification)
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Handshake() >> Failed Client authentication.");

    // reset the counter
    counter = 0;
}

ssize_t Worker::Receive(std::vector<uint8_t>& buffer, ssize_t buffer_size) {
    ssize_t total_bytes_received = 0;

    while (total_bytes_received < buffer_size) 
    {
        ssize_t bytes_received = recv(client_socket, (void*)(buffer.data() + total_bytes_received), buffer_size - total_bytes_received, 0);

        if (bytes_received == -1)
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m Failed to receive data.");

        if (bytes_received == 0) 
        {
            char message[sizeof("Client disconnected (socket: , on recv).") + sizeof(int)] = {0};
            std::sprintf(message, "Client disconnected (socket: %d, on recv).", client_socket);
            throw std::runtime_error(message);
        }

        total_bytes_received += bytes_received;
    }
    return total_bytes_received;
}

ssize_t Worker::Send(const std::vector<uint8_t>& buffer) {
    ssize_t total_bytes_sent = 0;
    ssize_t buffer_size = buffer.size();

    while (total_bytes_sent < buffer_size) 
    {
        ssize_t bytes_sent = send(client_socket, (void*)(buffer.data() + total_bytes_sent), buffer_size - total_bytes_sent, 0);

        if (bytes_sent == -1 && (errno == EPIPE || errno == ECONNRESET)) {
            char message[sizeof("Client disconnected (socket: , on send).") + sizeof(int)] = { 0 };
            sprintf(message, "Client disconnected (socket: %d, on send).", client_socket);
            throw std::runtime_error(message);
        }

        if (bytes_sent == -1)
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m Failed to send data.");

        total_bytes_sent += bytes_sent;
    }

    return total_bytes_sent;
}

bool Worker::ClientExists(uint8_t* username, ssize_t username_size)
{

    // check if username exists (the server must have a file called username), and retrieve the user's public key
    char* client_public_key_path = new char[sizeof("../res/public_keys/") + username_size + sizeof("_pubkey.pem")];
    std::sprintf(client_public_key_path, "../res/public_keys/%s_pubkey.pem", username);

    EVP_PKEY* user_public_key  = nullptr;
    try {
        BIO *bp = BIO_new_file(client_public_key_path, "r");
        delete[] client_public_key_path;
        if (!bp)
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m Handshake() >> Failed to open client public key file (Client does not exist?).");
        
        user_public_key = PEM_read_bio_PUBKEY(bp, NULL, NULL, NULL);
        BIO_free(bp);
        if (!user_public_key)
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m Handshake() >> Failed to read client public key (Client does not exist?).");

        this->username = std::string(reinterpret_cast<const char*>(username), username_size);
    } catch(const std::runtime_error& ex) {
        // Client does not exist
        std::cerr << ex.what() << std::endl;
        
        if (client_public_key_path != nullptr)
            delete[] client_public_key_path;

        if (user_public_key != nullptr) 
            EVP_PKEY_free(user_public_key);
 
        try {
            HandshakeM2 m2(0);
            std::vector<uint8_t> serialized_m2 = m2.serialize();

            // Send to Client the negative result
            Send(serialized_m2);
        } catch(const std::runtime_error& __ex) {
            std::cerr << __ex.what() << std::endl;
            return false;
        }
        return false;
    }
    EVP_PKEY_free(user_public_key);
    return true;
}

void Worker::SendTransferResponse(bool outcome) {

    // Transfer response = S - Success, D - Denied
    std::string transfer_outcome = (outcome) ? "S" : "D";

    TransferResponse transfer_response(reinterpret_cast<char>(transfer_outcome[0]), this->counter);

    #ifdef DEBUG
    std::cout << BLUE_BOLD << "[WORKER]" << RESET << " >> "
              << "TransferHandler() >> outcome: " << transfer_response.outcome  << std::endl;
    #endif

    std::vector<uint8_t> plaintext(TRANSFER_RESPONSE_SIZE, 0);
    transfer_response.serialize(plaintext);

    try {
        SessionMessage encrypted_response(this->session_key, this->hmac_key, plaintext);
        std::vector<uint8_t> to_send = encrypted_response.serialize();
        Send(to_send);
    } catch(const std::runtime_error& ex) {
        throw ex;
    }
}
