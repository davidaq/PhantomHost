#ifndef __DEFS_H
#define __DEFS_H

#define MAXBUF  0xFFFF

// Divert function pointers

typedef HANDLE (*WinDivertOpenFunc)(
    __in        const char *filter,
    __in        WINDIVERT_LAYER layer,
    __in        INT16 priority,
    __in        UINT64 flags);

typedef BOOL (*WinDivertCloseFunc)(
    __in        HANDLE handle);

typedef BOOL (*WinDivertRecvFunc)(
    __in        HANDLE handle,
    __out       PVOID pPacket,
    __in        UINT packetLen,
    __out_opt   PWINDIVERT_ADDRESS pAddr,
    __out_opt   UINT *readLen);

typedef BOOL (*WinDivertSendFunc)(
    __in        HANDLE handle,
    __in        PVOID pPacket,
    __in        UINT packetLen,
    __in        PWINDIVERT_ADDRESS pAddr,
    __out_opt   UINT *writeLen);

typedef UINT (*WinDivertHelperCalcChecksumsFunc)(
    __inout     PVOID pPacket,
    __in        UINT packetLen,
    __in        UINT64 flags);

typedef BOOL (*WinDivertHelperParsePacketFunc)(
    __in        PVOID pPacket,
    __in        UINT packetLen,
    __out_opt   PWINDIVERT_IPHDR *ppIpHdr,
    __out_opt   PWINDIVERT_IPV6HDR *ppIpv6Hdr,
    __out_opt   PWINDIVERT_ICMPHDR *ppIcmpHdr,
    __out_opt   PWINDIVERT_ICMPV6HDR *ppIcmpv6Hdr,
    __out_opt   PWINDIVERT_TCPHDR *ppTcpHdr,
    __out_opt   PWINDIVERT_UDPHDR *ppUdpHdr,
    __out_opt   PVOID *ppData,
    __out_opt   UINT *pDataLen);


// Program context structure

struct DIVERT_FUNCS_S {
    WinDivertOpenFunc Open;
    WinDivertCloseFunc Close;
    WinDivertRecvFunc Recv;
    WinDivertSendFunc Send;
    WinDivertHelperCalcChecksumsFunc HelperCalcChecksums;
    WinDivertHelperParsePacketFunc HelperParsePacket;
};
typedef DIVERT_FUNCS_S DIVERT_FUNCS;

struct PORT_ROUTE_S {
    UINT ip;
    USHORT port;
};
typedef struct PORT_ROUTE_S PORT_ROUTE;

struct PACKET_CONTEXT_S {
    DIVERT_FUNCS divert;

    PORT_ROUTE* route[65536];

    const char* host_domain;
    UINT host_ip;

    HANDLE hFilter;
    WINDIVERT_ADDRESS addr;
    PWINDIVERT_IPHDR ip_header;
    PWINDIVERT_IPV6HDR ipv6_header;
    PWINDIVERT_ICMPHDR icmp_header;
    PWINDIVERT_ICMPV6HDR icmpv6_header;
    PWINDIVERT_TCPHDR tcp_header;
    PWINDIVERT_UDPHDR udp_header;
    void* payload;
    UCHAR packet[MAXBUF];
    UINT packet_len, payload_len;
};
typedef PACKET_CONTEXT_S PACKET_CONTEXT;

// DNS structures

struct DNS_HEADER_S {
    uint16_t id;
    uint16_t option;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((__packed__));
typedef struct DNS_HEADER_S DNS_HEADER;

struct DNS_QUERY_S {
    uint16_t type;
    uint16_t clazz;
} __attribute__((__packed__));
typedef struct DNS_QUERY_S DNS_QUERY;

struct DNS_ANSWER_S {
    uint16_t name;
    uint16_t type;
    uint16_t clazz;
    uint32_t ttl;
} __attribute__((__packed__));
typedef struct DNS_ANSWER_S DNS_ANSWER;

// packet handler functions

BOOL handle_dns(PACKET_CONTEXT& ctx);
BOOL handle_tcp(PACKET_CONTEXT& ctx);
BOOL handle_icmp(PACKET_CONTEXT& ctx);

// static functions
#include <stdio.h>
static inline const std::string iptostr(const UINT& ipVal) {
    char ip_str[20];
    UCHAR* ip = (UCHAR*)&ipVal;
    sprintf(ip_str, "%d.%d.%d.%d", (int)ip[0], (int)ip[1], (int)ip[2], (int)ip[3]);
    return ip_str;
}

#endif // __DEFS_H
