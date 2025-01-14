#ifndef PING_H
#define PING_H

#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 64
#define TIMEOUT 10000 // 10 שניות

typedef struct {
    char *a;  // כתובת ה-IP של היעד
    int t;    // סוג התקשורת (IPv4/IPv6)
    int c;    // מספר הפינגים
    int f;    // flood (ללא עיכוב)
} PingFlags;

// חישוב ה-checksum
unsigned short int calculate_checksum(void *data, unsigned int bytes);

// ניתוח דגלים
PingFlags manFlags(int argc,char *argv[]);

// שליחת פינג
void typePing(PingFlags opt);

void handle_sigint(int sig);

#endif