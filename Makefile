TARGETS = radio-proxy radio-client

FLAGS = -Wall -Wextra -O2

all: $(TARGETS)

err.o: err.h
	g++ $(FLAGS) -c err.c

radio-proxy.o: radio-proxy.cpp
	g++ $(FLAGS) -c radio-proxy.cpp

radio-proxy: err.o radio-proxy.o
	g++ $(FLAGS) radio-proxy.o err.o -o radio-proxy

radio-client.o: radio-client.cpp
	g++ $(FLAGS) -c radio-client.cpp

radio-client: err.o radio-client.o
	g++ $(FLAGS) radio-client.o err.o -o radio-client

.PHONY: clean

clean:
	rm -f $(TARGETS) *.o *~ *.bak
