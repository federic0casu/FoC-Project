CXX = g++
CXXFLAGS = -std=c++14 -Wall -Wextra
LIBS = -lssl -lcrypto -pthread

SERVER_SRCS = ../src/Server/Server.cpp ../src/Server/main_server.cpp ../src/Server/Worker.cpp
CLIENT_SRCS = ../src/Client/Client.cpp ../src/Client/main_client.cpp
PACKET_SRCS = ../src/Packet/List.cpp ../src/Packet/SessionMessage.cpp
SECURITY_SRCS = ../src/Security/AES_CBC.cpp ../src/Security/HMAC.cpp 

SERVER_EXEC = server
CLIENT_EXEC = client

.PHONY: all clean

all: $(SERVER_EXEC) $(CLIENT_EXEC)

$(SERVER_EXEC): $(SERVER_OBJS)
	$(CXX) $(CXXFLAGS) $(SERVER_SRCS) $(PACKET_SRCS) $(SECURITY_SRCS) -o $(SERVER_EXEC) $(LIBS)

$(CLIENT_EXEC): $(CLIENT_OBJS)
	$(CXX) $(CXXFLAGS) $(CLIENT_SRCS) $(PACKET_SRCS) $(SECURITY_SRCS) -o $(CLIENT_EXEC) $(LIBS)

clean:
	rm -f $(SERVER_EXEC) $(CLIENT_EXEC)

