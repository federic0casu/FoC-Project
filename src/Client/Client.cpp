#include "Client.hpp"

Client::Client(const std::string &server_ip, int server_port)
{
    m_long_term_key = nullptr;

    sock_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (sock_fd == -1)
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Failed to create socket!");

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(server_port);

    if (inet_pton(AF_INET, server_ip.c_str(), &(server_address.sin_addr)) <= 0)
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Invalid server IP address!");

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
    if (connect(sock_fd, (struct sockaddr *)&server_address, sizeof(server_address)) == -1)
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Failed to connect to the server!");

    std::cout << "Connected to the server." << std::endl;
}

void Client::balance() 
{
    try {
        const char padding[] = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        ClientReq balance_request(CODE_BALANCE_REQUEST, 0, padding);

        std::vector<uint8_t> plaintext(REQUEST_PACKET_SIZE);
        balance_request.serialize(plaintext);

        SessionMessage encrypted_request(this->session_key, this->hmac_key, plaintext);

        std::memset(reinterpret_cast<void *>(plaintext.data()), 0, plaintext.size());
        plaintext.clear();

        std::vector<uint8_t> to_send = encrypted_request.serialize();
        send_to_server(to_send);

        std::memset(reinterpret_cast<void *>(to_send.data()), 0, to_send.size());
        to_send.clear();

        std::vector<uint8_t> buffer(SessionMessage::get_size(BALANCE_RESPONSE_SIZE));
        recv_from_server(buffer); 

        SessionMessage encrypted_response = SessionMessage::deserialize(buffer, BALANCE_RESPONSE_SIZE);

        plaintext.resize(BALANCE_RESPONSE_SIZE);
        plaintext.assign(plaintext.size(), 0);
        encrypted_response.decrypt(this->session_key, plaintext);

        BalanceResponse response = BalanceResponse::deserialize(plaintext);
        response.print();
    } catch (const std::runtime_error &ex) {
        #ifdef DEBUG
        std::cerr << ex.what() << std::endl;
        #endif // DEBUG

        std::cerr << "Something went wrong. Please try again..." << std::endl;
    }
}

void Client::transfer()
{
    try {
        std::string dest;
        uint32_t amount;

        std::cout << ">> Insert payee: ";
        std::cin >> dest;
        std::cout << ">> Insert amount [$]: ";
        std::cin >> amount;

        ClientReq transfer_request(CODE_TRANSFER_REQUEST, amount, dest.c_str());

        std::vector<uint8_t> plaintext(REQUEST_PACKET_SIZE);
        transfer_request.serialize(plaintext);

        SessionMessage encrypted_request(session_key, hmac_key, plaintext);

        std::vector<uint8_t> to_send = encrypted_request.serialize();
        send_to_server(to_send);

        // aspetta la risposta
        std::vector<uint8_t> buffer(SessionMessage::get_size(TRANSFER_RESPONSE_SIZE));

        recv_from_server(buffer);
        // decifra
        SessionMessage encrypted_response = SessionMessage::deserialize(buffer, TRANSFER_RESPONSE_SIZE);

        plaintext.resize(TRANSFER_RESPONSE_SIZE);
        plaintext.assign(plaintext.size(), 0);
        encrypted_response.decrypt(this->session_key, plaintext);

        TransferResponse response = TransferResponse::deserialize(plaintext.data());
        response.print();
    } catch (const std::runtime_error &ex) {
        #ifdef DEBUG
        std::cerr << ex.what() << std::endl;
        #endif // DEBUG

        std::cerr << "Something went wrong. Please try again..." << std::endl;
    }
}

void Client::list()
{
    try {
        const char padding[] = "LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL";
        ClientReq list_request(CODE_LIST_REQUEST, 0, padding);

        std::vector<uint8_t> plaintext(REQUEST_PACKET_SIZE);
        list_request.serialize(plaintext);
        
        SessionMessage encrypted_request(this->session_key, this->hmac_key, plaintext);
        std::vector<uint8_t> to_send = encrypted_request.serialize();
        send_to_server(to_send);


        // ---------------- RICEVI NUMERO DI TRANSAZIONI ----------------

        // aspetta la risposta
        std::vector<uint8_t> buffer(SessionMessage::get_size(LIST_RESPONSE_1_SIZE));

        recv_from_server(buffer);
        // decifra
        SessionMessage encrypted_response = SessionMessage::deserialize(buffer, LIST_RESPONSE_1_SIZE);

        plaintext.resize(LIST_RESPONSE_1_SIZE);
        plaintext.assign(plaintext.size(), 0);
        encrypted_response.decrypt(this->session_key, plaintext);

        ListM1 listm1 = ListM1::deserialize(plaintext);

        // ---------------- RICEVI LE TRANSAZIONI ---------------------

        for (int i = 0; i < listm1.transaction_num; i++) {
            
            buffer.resize(SessionMessage::get_size(LIST_RESPONSE_2_SIZE));
            recv_from_server(buffer);
            // decifra
            SessionMessage encrypted_response = SessionMessage::deserialize(buffer, LIST_RESPONSE_2_SIZE);

            plaintext.resize(LIST_RESPONSE_2_SIZE);
            plaintext.assign(plaintext.size(), 0);
            encrypted_response.decrypt(this->session_key, plaintext);

            ListM2 listm2 = ListM2::deserialize(plaintext);
            listm2.print();
        }
    } catch(const std::runtime_error& ex) {
        #ifdef DEBUG
        std::cerr << ex.what() << std::endl;
        #endif // DEBUF

        std::cerr << "Something went wrong. Please try again..." << std::endl;
    }
}

void Client::handshake() 
{
    std::string password;
    std::cout << ">> Insert username: ";
    std::cin >> m_username;
    getchar(); // To delete the '\n' character
    std::cout << ">> Insert password: ";

    // Read password with asterisks
    char ch;
    turnOffEcho();
    do {
        ch = getchar();
        if (ch == 127) {  // Handle backspace. A legit password cannot contain backspaces.
            if (!password.empty()) {
                password.pop_back();
                std::cout << "\b \b";  // Move cursor back, erase character, move cursor back again
            }
        } else {
            password += ch;
            std::cout << "*";
        }
    } while(ch != '\n' && ch != '\r');
    turnOnEcho();

    DiffieHellman dh;
    EVP_PKEY *ephemeral_key = nullptr;
    try {
        // Generate ephemeral key
        ephemeral_key = dh.generateEphemeralKey();
    } catch (const std::runtime_error &ex) {
        #ifdef DEBUG    
        std::cerr << ex.what() << std::endl;
        #endif // DEBUG
        
        if (ephemeral_key != nullptr)
            EVP_PKEY_free(ephemeral_key);

        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Please, try to attempt the login procedure again...");
    }

    // Serialize ephemeral key
    std::vector<uint8_t> serialized_ephemeral_key;
    try {
        serialized_ephemeral_key = DiffieHellman::serializeKey(ephemeral_key);
    } catch (const std::runtime_error &ex) {
        #ifdef DEBUG
        std::cerr << ex.what() << std::endl;
        #endif // DEBUG

        EVP_PKEY_free(ephemeral_key);

        if (!serialized_ephemeral_key.empty()) {
            std::memset(reinterpret_cast<void *>(serialized_ephemeral_key.data()), 0, serialized_ephemeral_key.size());
            serialized_ephemeral_key.clear();
        }

        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Please, try to attempt the login procedure again...");
    }

    HandshakeM1 m1(serialized_ephemeral_key, serialized_ephemeral_key.size(), reinterpret_cast<const unsigned char *>(m_username.c_str()), std::strlen(m_username.c_str()));

    std::vector<uint8_t> serialized_m1;
    m1.serialize(serialized_m1);

    try {
        send_to_server(serialized_m1);
    } catch (const std::runtime_error &ex) {
        #ifdef DEBUG
        std::cerr << ex.what() << std::endl;
        #endif // DEBUG

        std::memset(reinterpret_cast<void *>(serialized_ephemeral_key.data()), 0, serialized_ephemeral_key.size());
        serialized_ephemeral_key.clear();

        EVP_PKEY_free(ephemeral_key);

        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Please, try to attempt the login procedure again...");
    }

    // Receive the result of existence of the user
    std::vector<uint8_t> serialized_m2(HandshakeM2::GetSize());
    try {
        recv_from_server(serialized_m2);
    } catch (const std::runtime_error &ex) {
        #ifdef DEBUG
        std::cerr << ex.what() << std::endl;
        #endif // DEBUG

        std::memset(reinterpret_cast<void *>(serialized_ephemeral_key.data()), 0, serialized_ephemeral_key.size());
        serialized_ephemeral_key.clear();

        EVP_PKEY_free(ephemeral_key);

        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Please, try to attempt the login procedure again...");
    }

    HandshakeM2 m2 = HandshakeM2::deserialize(serialized_m2);
    serialized_m2.clear();

    if (m2.result == 0) {
        std::memset(reinterpret_cast<void *>(serialized_ephemeral_key.data()), 0, serialized_ephemeral_key.size());
        serialized_ephemeral_key.clear();

        EVP_PKEY_free(ephemeral_key);

        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Please, try to attempt the login procedure again...");
        return;
    }

    EVP_PKEY *peer_ephemeral_key = nullptr;
    std::vector<uint8_t> shared_secret;
    size_t shared_secret_size;
    try {
        // retrieve the peer ephemeral key from the M2 packet
        peer_ephemeral_key = DiffieHellman::deserializeKey(m2.ephemeral_key.data(), m2.ephemeral_key_size);

        // Generate shared secret
        dh.generateSharedSecret(ephemeral_key, peer_ephemeral_key, shared_secret, shared_secret_size);
    } catch (const std::runtime_error &ex) {
        #ifdef DEBUG
        std::cerr << ex.what() << std::endl;
        #endif // DEBUG

        std::memset(reinterpret_cast<void *>(serialized_ephemeral_key.data()), 0, serialized_ephemeral_key.size());
        serialized_ephemeral_key.clear();

        std::memset(reinterpret_cast<void *>(shared_secret.data()), 0, shared_secret.size());
        shared_secret.clear();

        EVP_PKEY_free(ephemeral_key);

        if (peer_ephemeral_key != nullptr)
            EVP_PKEY_free(peer_ephemeral_key);

        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Please, try to attempt the login procedure again...");
    }
    EVP_PKEY_free(ephemeral_key);
    EVP_PKEY_free(peer_ephemeral_key);

    // generate the session and the hmac keys from the shared secret
    std::vector<uint8_t> keys;
    uint32_t keys_size;
    try {
        SHA_512::generate(shared_secret.data(), shared_secret_size, keys, keys_size);
        std::memset(reinterpret_cast<void *>(shared_secret.data()), 0, shared_secret.size());
        shared_secret.clear();
    } catch (std::runtime_error &ex) {
        #ifdef DEBUG
        std::cerr << ex.what() << std::endl;
        #endif

        std::memset(reinterpret_cast<void *>(serialized_ephemeral_key.data()), 0, serialized_ephemeral_key.size());
        serialized_ephemeral_key.clear();

        std::memset(reinterpret_cast<void *>(keys.data()), 0, keys.size());
        keys.clear();

        std::memset(reinterpret_cast<void *>(shared_secret.data()), 0, shared_secret.size());
        shared_secret.clear();

        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Please, try to attempt the login procedure again...");
    }

    std::memcpy(this->session_key.data(), keys.data(), (keys.size() / 2) * sizeof(uint8_t));
    std::memcpy(this->hmac_key.data(), keys.data() + ((keys.size() / 2) * sizeof(uint8_t)), HMAC_DIGEST_SIZE * sizeof(uint8_t));

    std::memset(reinterpret_cast<void *>(keys.data()), 0, keys.size());
    keys.clear();

    // prepare <g^a,g^b>
    int ephemeral_keys_buffer_size = m2.ephemeral_key_size + serialized_ephemeral_key.size();
    std::vector<uint8_t> ephemeral_keys_buffer(ephemeral_keys_buffer_size);
    std::memcpy(ephemeral_keys_buffer.data(), serialized_ephemeral_key.data(), serialized_ephemeral_key.size());
    std::memcpy(ephemeral_keys_buffer.data() + serialized_ephemeral_key.size(), m2.ephemeral_key.data(), m2.ephemeral_key_size);

    std::memset(reinterpret_cast<void *>(serialized_ephemeral_key.data()), 0, serialized_ephemeral_key.size());
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
    } catch (const std::runtime_error &ex) {
        #ifdef DEBUG
        std::cerr << ex.what() << std::endl;
        #endif // DEBUG

        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Please, try to attempt the login procedure again...");
    }

    // calculate {<g^a,g^b>_privKc}_Ksess
    std::vector<uint8_t> iv(EVP_CIPHER_iv_length(EVP_aes_256_cbc()));
    std::vector<uint8_t> ciphertext;
    AES_CBC *encryptor = nullptr;
    try {
        encryptor = new AES_CBC(ENCRYPT, this->session_key);
        encryptor->run(signature, ciphertext, iv);
        delete encryptor;

        std::memset(reinterpret_cast<void *>(signature.data()), 0, signature.size());
        signature.clear();
    } catch (const std::exception &ex) {
        #ifdef DEBUG
        std::cerr << ex.what() << std::endl;
        #endif // DEBUG

        if (encryptor != nullptr)
            delete encryptor;

        std::memset(reinterpret_cast<void *>(signature.data()), 0, signature.size());
        signature.clear();

        std::memset(reinterpret_cast<void *>(ephemeral_keys_buffer.data()), 0, ephemeral_keys_buffer.size());
        ephemeral_keys_buffer.clear();

        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Please, try to attempt the login procedure again...");
    }

    // decrypt the encrypted digital signature
    std::vector<uint8_t> decrypted_signature;
    AES_CBC *decryptor = nullptr;
    try {
        decryptor = new AES_CBC(DECRYPT, this->session_key);
        decryptor->run(m2.encrypted_signature, decrypted_signature, m2.iv);
        delete decryptor;
        decrypted_signature.resize(DECRYPTED_SIGNATURE_SIZE);
    } catch (const std::runtime_error &ex) {
        #ifdef DEBUG
        std::cerr << ex.what() << std::endl;
        #endif // DEBUG

        if (decryptor != nullptr)
            delete decryptor;

        std::memset(reinterpret_cast<void *>(decrypted_signature.data()), 0, decrypted_signature.size());
        decrypted_signature.clear();

        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Please, try to attempt the login procedure again...");
    }

    // verify the signature
    RSASignature *rsa = nullptr;
    bool signature_verification = true;
    try {
        char public_key_path[] = "../res/public_keys/server_pubkey.pem";

        rsa = new RSASignature("", public_key_path);
        signature_verification = rsa->verify(ephemeral_keys_buffer, decrypted_signature);
        delete rsa;

        std::memset(reinterpret_cast<void *>(ephemeral_keys_buffer.data()), 0, ephemeral_keys_buffer.size());
        ephemeral_keys_buffer.clear();

        std::memset(reinterpret_cast<void *>(decrypted_signature.data()), 0, decrypted_signature.size());
        decrypted_signature.clear();
    } catch (const std::runtime_error &ex) {
        #ifdef DEBUG
        std::cerr << ex.what() << std::endl;
        #endif // DEBUG

        if (rsa != nullptr)
            delete rsa;

        std::memset(reinterpret_cast<void *>(ephemeral_keys_buffer.data()), 0, ephemeral_keys_buffer.size());
        ephemeral_keys_buffer.clear();

        std::memset(reinterpret_cast<void *>(decrypted_signature.data()), 0, decrypted_signature.size());
        decrypted_signature.clear();

        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Please, try to attempt the login procedure again...");
    }

    if (!signature_verification)
        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Please, try to attempt the login procedure again...");

    HandshakeM3 m3(iv, ciphertext);

    std::vector<uint8_t> serialized_m3 = m3.serialize();

    try {
        send_to_server(serialized_m3);

        std::memset(reinterpret_cast<void *>(ciphertext.data()), 0, ciphertext.size());
        ciphertext.clear();

        std::memset(reinterpret_cast<void *>(iv.data()), 0, iv.size());
        iv.clear();
    } catch (const std::exception& ex) {
        #ifdef DEBUG
        std::cerr << ex.what() << std::endl;
        #endif

        std::memset(reinterpret_cast<void *>(ciphertext.data()), 0, ciphertext.size());
        ciphertext.clear();

        std::memset(reinterpret_cast<void *>(iv.data()), 0, iv.size());
        iv.clear();

        throw std::runtime_error("\033[1;31m[ERROR]\033[0m Please, try to attempt the login procedure again...");
    }

    // reset the counter
    m_counter = 0;

    std::cout << "Session established." << std::endl;
}

void Client::send_to_server(const std::vector<uint8_t> &buffer)
{
    ssize_t bytes_sent = 0;
    ssize_t total_bytes_sent = 0;
    ssize_t buffer_size = buffer.size();

    while (total_bytes_sent < buffer_size)
    {
        bytes_sent = send(sock_fd, reinterpret_cast<const void *>(buffer.data() + total_bytes_sent), buffer_size - total_bytes_sent, 0);

        if (bytes_sent != -1)
        {
            total_bytes_sent += bytes_sent;
            continue;
        }

        if (bytes_sent == -1 && (errno == EPIPE || errno == ECONNRESET))
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m Server disconnected");

        if (bytes_sent == -1)
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m Failed to send data");
    }
}

void Client::recv_from_server(std::vector<uint8_t> &buffer)
{
    ssize_t bytes_received = 0;
    ssize_t total_bytes_received = 0;
    ssize_t buffer_size = buffer.size();

    while (total_bytes_received < buffer_size)
    {
        bytes_received = recv(sock_fd, reinterpret_cast<void *>(buffer.data() + total_bytes_received), buffer_size - total_bytes_received, 0);

        if (bytes_received != -1 && bytes_received != 0)
        {
            total_bytes_received += bytes_received;
            continue;
        }

        if (bytes_received == -1)
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m Failed to receive data");

        if (bytes_received == 0)
            throw std::runtime_error("\033[1;31m[ERROR]\033[0m Server disconnected");
    }
}

// Function to turn off console echo
void Client::turnOffEcho() {
    struct termios term;
    tcgetattr(STDIN_FILENO, &term);
    term.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &term);
}

// Function to turn on console echo
void Client::turnOnEcho() {
    struct termios term;
    tcgetattr(STDIN_FILENO, &term);
    term.c_lflag |= ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &term);
    std::cout << std::endl;
}
