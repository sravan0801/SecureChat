# Makefile — Task 4: active MITM (fake-certificate) attack
#
#   secure_chat_app                 Alice/Bob chat app (verbatim copy of the
#                                   Task 3 build; runs unchanged here)
#   secure_chat_active_interceptor  Trudy's active MITM proxy ( -m alice1 bob1 )

CXX      := g++
CXXFLAGS := -Wall -std=c++11
LIBS     := -lssl -lcrypto -pthread

BINS := secure_chat_app secure_chat_active_interceptor

all: $(BINS)

secure_chat_app: secure_chat_app.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LIBS)

secure_chat_active_interceptor: secure_chat_active_interceptor.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f $(BINS)

.PHONY: all clean
