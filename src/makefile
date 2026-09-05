# Makefile — Task 2: Secure DTLS 1.2 peer-to-peer chat (Alice & Bob)

# Toolchain
CXX      := g++
CXXFLAGS := -Wall -std=c++11
LIBS     := -lssl -lcrypto -pthread

# Inputs / outputs
SRC := secure_chat_app.cpp
OBJ := $(SRC:.cpp=.o)
BIN := securechat

# Build the binary by default
all: $(BIN)

# Link stage
$(BIN): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

# Compile stage
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Housekeeping
clean:
	rm -f $(BIN) $(OBJ)

.PHONY: all clean
