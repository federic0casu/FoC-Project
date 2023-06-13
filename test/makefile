CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra -Werror
LIBS = -lssl -lcrypto -pthread

SERVER_SRCS = ../src/Server/Server.cpp ../src/Server/main_server.cpp
CLIENT_SRCS = ../src/Client/Client.cpp ../src/Client/main_client.cpp

SERVER_OBJS = $(SERVER_SRCS:.cpp=.o)
CLIENT_OBJS = $(CLIENT_SRCS:.cpp=.o)

SERVER_EXEC = server
CLIENT_EXEC = client

.PHONY: all clean

all: $(SERVER_EXEC) $(CLIENT_EXEC)

$(SERVER_EXEC): $(SERVER_OBJS)
	$(CXX) $(CXXFLAGS) $(SERVER_OBJS) -o $(SERVER_EXEC) $(LIBS)

$(CLIENT_EXEC): $(CLIENT_OBJS)
	$(CXX) $(CXXFLAGS) $(CLIENT_OBJS) -o $(CLIENT_EXEC) $(LIBS)

.cpp.o:
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(SERVER_OBJS) $(CLIENT_OBJS) $(SERVER_EXEC) $(CLIENT_EXEC)

