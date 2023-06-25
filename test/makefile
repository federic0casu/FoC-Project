CXX = g++
CXXFLAGS = -std=c++14
LIBS = -lssl -lcrypto -pthread

SERVER_SRCS = ../src/Server/Server.cpp ../src/Server/main_server.cpp ../src/Server/Worker.cpp
CLIENT_SRCS = ../src/Client/Client.cpp ../src/Client/main_client.cpp
PACKET_SRCS = ../src/Packet/SessionMessage.cpp
SECURITY_SRCS = ../src/Crypto/AES_CBC.cpp ../src/Crypto/HMAC.cpp ../src/Crypto/DiffieHellman.cpp ../src/Crypto/RSASignature.cpp ../src/Crypto/SHA_512.cpp
UTILITY_SRCS = ../src/Utility/FileManager.cpp ../src/Utility/TransferManager.cpp

SERVER_EXEC = server
CLIENT_EXEC = client

.PHONY: all clean

all: $(SERVER_EXEC) $(CLIENT_EXEC)

$(SERVER_EXEC): $(SERVER_OBJS)
	$(CXX) $(CXXFLAGS) $(SERVER_SRCS) $(PACKET_SRCS) $(SECURITY_SRCS) $(UTILITY_SRCS) -o $(SERVER_EXEC) $(LIBS)

$(CLIENT_EXEC): $(CLIENT_OBJS)
	$(CXX) $(CXXFLAGS) $(CLIENT_SRCS) $(PACKET_SRCS) $(SECURITY_SRCS) -o $(CLIENT_EXEC) $(LIBS)

clean:
	rm -f $(SERVER_EXEC) $(CLIENT_EXEC)

