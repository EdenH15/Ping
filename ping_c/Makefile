CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -pedantic
RM = rm -f

EXE = ping
IP1 = 1.1.1.1 #Default ip for IPv4
IP2 = 2001:4860:4860::8888  #Default ip for IPv6

.PHONY: all clean runp runsp runp6 runsp6

# Default target
all: $(EXE)

# Compile the ping program
$(EXE): ping.o
	$(CC) $(CFLAGS) -o $(EXE) ping.o

# Compile the object file
ping.o: ping.c ping.h
	$(CC) $(CFLAGS) -c ping.c

# Run ping program for IPv4
runp4: $(EXE)
	sudo ./ping -a $(IP1) -t 4

# Run ping program for IPv6
runp6: $(EXE)
	sudo ./ping -a $(IP2) -t 6

# Run ping program with strace for IPv4
runsp4: $(EXE)
	sudo strace ./ping -a $(IP1) -t 4

# Run ping program with strace for IPv6
runsp6: $(EXE)
	sudo strace ./ping -a $(IP2) -t 6

# Clean up generated files
clean:
	$(RM) *.o $(EXE)
