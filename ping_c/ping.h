#ifndef PING_H
#define PING_H

#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 64
#define TIMEOUT 10000 // Timeout in milliseconds (10 seconds)

typedef struct {
    char *a;  // Target IP address
    int t;    // Communication type (IPv4/IPv6)
    int c;    // Number of pings
    int f;    // Flood mode (no delay between pings)
} PingFlags;

// Calculate the checksum for the ICMP header
unsigned short int calculate_checksum(void *data, unsigned int bytes);

// Parse command-line flags and options
PingFlags manFlags(int argc, char *argv[]);

// Send ping requests based on the type (IPv4/IPv6)
void typePing(PingFlags opt);

// Signal handler for SIGINT
void handle_sigint(int sig);

#endif
