#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h> 
#include "Traceroute.h"

// Function to calculate checksum
// This function computes the checksum for the given data buffer.
// It ensures data integrity by adding all 16-bit words together and performing a final one's complement.
unsigned short int calculate_checksum(void *data, unsigned int bytes) {
    unsigned short int *data_pointer = (unsigned short int *)data;
    unsigned int total_sum = 0;

    // Sum the 16-bit words
    while (bytes > 1) {
        total_sum += *data_pointer++;
        bytes -= 2;
    }

    // If there is a leftover byte, add it
    if (bytes > 0)
        total_sum += *((unsigned char *)data_pointer);

    // Add the overflow bits
    while (total_sum >> 16)
        total_sum = (total_sum & 0xFFFF) + (total_sum >> 16);

    return ~((unsigned short int)total_sum);
}

// Function to perform traceroute
// This function traces the route to the specified destination IP address.
// It sends ICMP Echo requests with increasing TTL values and reports the round-trip time (RTT) for each hop.
void traceroute(const char *destination_ip) {
    int sock;
    struct sockaddr_in dest_addr;
    struct timeval start, end;
    char buffer[1024];

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    inet_pton(AF_INET, destination_ip, &dest_addr.sin_addr);

    sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    printf("traceroute to %s, %d hops max\n", destination_ip, MAX_HOPS);

    // Loop through each TTL value (hop)
    for (int ttl = 1; ttl <= MAX_HOPS; ttl++) {
        setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

        struct sockaddr_in recv_addr;
        socklen_t recv_len = sizeof(recv_addr);
        int received_replies = 0;
        double rtt[PACKETS_PER_HOP];
        char ip_address[INET_ADDRSTRLEN] = "*";

        // Send multiple packets per hop
        for (int i = 0; i < PACKETS_PER_HOP; i++) {
            // Create ICMP header
            struct icmphdr icmp_hdr;
            memset(&icmp_hdr, 0, sizeof(icmp_hdr));
            icmp_hdr.type = ICMP_ECHO;
            icmp_hdr.code = 0;
            icmp_hdr.un.echo.id = getpid();
            icmp_hdr.un.echo.sequence = ttl * 100 + i;
            icmp_hdr.checksum = calculate_checksum(&icmp_hdr, sizeof(icmp_hdr));

            // Create custom IP header
            struct ip_header ip_hdr;
            memset(&ip_hdr, 0, sizeof(ip_hdr));
            
            ip_hdr.version_ihl = (4 << 4) | 5; // IPv4 and IHL of 5 (20 bytes)
            ip_hdr.tos = 0;
            ip_hdr.total_length = htons(sizeof(struct ip_header) + sizeof(struct icmphdr));
            ip_hdr.identification = htons(12345); // Random identifier
            ip_hdr.flags_offset = 0;
            ip_hdr.ttl = ttl;
            ip_hdr.protocol = IPPROTO_ICMP;
            ip_hdr.source_ip = inet_addr("192.168.1.1"); // Source IP address
            ip_hdr.dest_ip = inet_addr(destination_ip); // Destination IP address
            ip_hdr.checksum = calculate_checksum(&ip_hdr, sizeof(ip_hdr)); // IP header checksum

            // Send packet with IP and ICMP headers
            sendto(sock, &ip_hdr, sizeof(ip_hdr), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            sendto(sock, &icmp_hdr, sizeof(icmp_hdr), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            gettimeofday(&start, NULL);

            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(sock, &fds);

            struct timeval timeout;
            timeout.tv_sec = TIMEOUT;
            timeout.tv_usec = 0;

            // Wait for reply with a timeout
            int ret = select(sock + 1, &fds, NULL, NULL, &timeout);

            if (ret > 0) {
                int bytes_received = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&recv_addr, &recv_len);
                gettimeofday(&end, NULL);

                if (bytes_received > 0) {
                    double rtt_ms = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_usec - start.tv_usec) / 1000.0;
                    rtt[i] = rtt_ms;
                    received_replies++;
                    inet_ntop(AF_INET, &(recv_addr.sin_addr), ip_address, INET_ADDRSTRLEN);
                } else {
                    rtt[i] = -1; // Indicate timeout
                }
            } else {
                rtt[i] = -1; 
            }
        }

        // Print results for this hop
        printf("%2d  %s  ", ttl, ip_address);
        for (int i = 0; i < PACKETS_PER_HOP; i++) {
            if (rtt[i] >= 0) {
                printf("%.3fms  ", rtt[i]);
            } else {
                printf("*  ");
            }
        }
        printf("\n");

        // Stop if destination reached
        if (strcmp(ip_address, destination_ip) == 0) {
            printf("Destination reached.\n");
            break;
        }
    }

    close(sock);
}

int main(int argc, char *argv[]) {
    // Check arguments and call traceroute
    if (argc != 3 || strcmp(argv[1], "-a") != 0) {
        fprintf(stderr, "Usage: sudo %s -a <destination_ip>\n", argv[0]);
        return EXIT_FAILURE;
    }

    traceroute(argv[2]);
    return EXIT_SUCCESS;
}
