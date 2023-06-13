CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra -Werror
LIBS = -lssl -lcrypto -pthread

SERVER_SRCS = ../src/Server.cpp ../src/main_server.cpp
CLIENT_SRCS = ../src/Client.cpp ../src/main_client.cpp

SERVER_EXEC = server
CLIENT_EXEC = client

.PHONY: all clean

all: $(SERVER_EXEC) $(CLIENT_EXEC)

$(SERVER_EXEC): $(SERVER_OBJS)
	$(CXX) $(CXXFLAGS) $(SERVER_SRCS) -o $(SERVER_EXEC) $(LIBS)

$(CLIENT_EXEC): $(CLIENT_OBJS)
	$(CXX) $(CXXFLAGS) $(CLIENT_SRCS) -o $(CLIENT_EXEC) $(LIBS)

clean:
	rm -f $(SERVER_EXEC) $(CLIENT_EXEC)

