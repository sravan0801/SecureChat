# Makefile — Task 3: chat_START_SSL downgrade attack
#
# Builds two binaries:
#   secure_chat_app          - Alice/Bob chat app, downgrade-aware (from ../secure_chat_app.cpp)
#   secure_chat_interceptor  - Trudy's downgrade attacker ( -d alice1 bob1 )

CXX      := g++
CXXFLAGS := -Wall -std=c++11
LIBS     := -lssl -lcrypto -pthread

APP_SRC := secure_chat_app.cpp
INT_SRC := secure_chat_interceptor.cpp
APP_BIN := secure_chat_app
INT_BIN := secure_chat_interceptor

all: $(APP_BIN) $(INT_BIN)

# Chat app needs OpenSSL + pthreads
$(APP_BIN): $(APP_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LIBS)

# Interceptor is plain sockets only
$(INT_BIN): $(INT_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $<

clean:
	rm -f $(APP_BIN) $(INT_BIN)

.PHONY: all clean
