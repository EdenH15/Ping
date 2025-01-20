CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c99 -pedantic

# Object file
OBJ = Traceroute.o

# Executable file name
EXE = Traceroute
IP= 1.1.1.1 ##Default ip for IPv4

# Default target
all: $(EXE)

# Rule to create the executable
$(EXE): $(OBJ)
	$(CC) $(CFLAGS) -o $(EXE) $(OBJ)

# Rule to compile the C file to object file
Traceroute.o: Traceroute.c Traceroute.h
	$(CC) $(CFLAGS) -c Traceroute.c

run:$(EXE)
	sudo ./$(EXE) -a $(IP) 

# Clean up files
clean:
	rm -f $(OBJ) $(EXE)
