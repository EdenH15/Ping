#ifndef TRACEROUTE_H
#define TRACEROUTE_H

#include <sys/time.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define MAX_HOPS 30
#define TIMEOUT 1
#define PACKETS_PER_HOP 3

// Structure for IP header
struct ip_header {
    uint8_t version_ihl;        
    uint8_t tos;                
    uint16_t total_length;      
    uint16_t identification;    
    uint16_t flags_offset;      
    uint8_t ttl;                
    uint8_t protocol;           
    uint16_t checksum;          
    uint32_t source_ip;         
    uint32_t dest_ip;           
};



// Calculates the checksum for a given data buffer
unsigned short calculate_checksum(void *data, unsigned int len);

void traceroute(const char *destination_ip);

#endif
