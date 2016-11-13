#include <iostream>
#include "include/windivert.h"
#include "include/defs.h"

BOOL handle_dns(PACKET_CONTEXT& ctx) {
    if (!ctx.ip_header || ctx.addr.Direction != WINDIVERT_DIRECTION_OUTBOUND) {
        return FALSE;
    }
    if (!ctx.udp_header || htons(ctx.udp_header->DstPort) != 53) {
        return FALSE;
    }
    if (!ctx.payload || ctx.payload_len <= sizeof(DNS_HEADER) || ctx.payload_len > 512) {
        return FALSE;
    }
    unsigned char* data = (unsigned char*)ctx.payload;
    size_t data_len = ctx.payload_len;
    DNS_HEADER* dns_header = (DNS_HEADER*)data;
    data += sizeof(DNS_HEADER);
    data_len -= sizeof(DNS_HEADER);
    if (ntohs(dns_header->option) != 0x0100)
        return FALSE;
    if (ntohs(dns_header->qdcount) != 1)
        return FALSE;
    if (ntohs(dns_header->ancount) != 0)
        return FALSE;
    if (ntohs(dns_header->nscount) != 0)
        return FALSE;
    if (ntohs(dns_header->arcount) != 0)
        return FALSE;
    char domain_name[500];
    size_t i = 0, w = 0;
    while (i < data_len && data[i] != 0) {
        size_t len = data[i];
        if (i + len + 1 < data_len) {
            memcpy(domain_name + w, data + i + 1, len);
            w += len;
            domain_name[w++] = '.';
        }
        i += len + 1;
    }
    i++;
    domain_name[w - 1] = 0;
    if (i >= data_len)
        return FALSE;
    if (data_len - i != sizeof(DNS_QUERY))
        return FALSE;
    if (strcmp(domain_name, ctx.host_domain) != 0)
        return FALSE;
    DNS_QUERY *dnsq = (DNS_QUERY*)(data + i);
    if (ntohs(dnsq->type) != 0x0001) {
        return FALSE;
    }
    if (ntohs(dnsq->clazz) != 0x0001) {
        return FALSE;
    }

    char buf[1024];
    PDIVERT_IPHDR reply_ip_header = (PDIVERT_IPHDR)buf;
    PDIVERT_UDPHDR reply_udp_header = (PDIVERT_UDPHDR)(reply_ip_header + 1);
    DNS_HEADER *reply_dns_header = (DNS_HEADER*)(reply_udp_header + 1);
    UCHAR *reply_data = (UCHAR *)(reply_dns_header + 1);

    memset(reply_ip_header, 0, sizeof(DIVERT_IPHDR));
    reply_ip_header->Version   = 4;
    reply_ip_header->HdrLength = sizeof(DIVERT_IPHDR) / sizeof(uint32_t);
    reply_ip_header->Id        = (UINT16)rand();
    WINDIVERT_IPHDR_SET_DF(reply_ip_header, 1);
    reply_ip_header->TTL       = 32;
    reply_ip_header->Protocol  = 17;                // IP_PROTO_UDP
    memcpy(&reply_ip_header->SrcAddr, &ctx.ip_header->DstAddr, sizeof(reply_ip_header->SrcAddr));
    memcpy(&reply_ip_header->DstAddr, &ctx.ip_header->SrcAddr, sizeof(reply_ip_header->DstAddr));

    reply_udp_header->SrcPort = htons(53);          // DNS
    reply_udp_header->DstPort = ctx.udp_header->SrcPort;

    reply_dns_header->id      = dns_header->id;
    reply_dns_header->option  = htons(0x8180);      // Standard DNS response.
    reply_dns_header->qdcount = htons(1);
    reply_dns_header->ancount = htons(1);
    reply_dns_header->nscount = 0;
    reply_dns_header->arcount = 0;

    memcpy(reply_data, data, data_len);
    DNS_ANSWER *reply_dns_answer = (DNS_ANSWER*)(reply_data + data_len);
    reply_dns_answer->name   = htons(0xC00C);
    reply_dns_answer->type   = htons(0x0001);
    reply_dns_answer->clazz  = htons(0x0001);
    reply_dns_answer->ttl    = htonl(4);

    uint32_t *reply_dns_answer_res = (uint32_t *)(reply_dns_answer + 1);
    *reply_dns_answer_res = ctx.host_ip;

    size_t len = sizeof(DIVERT_IPHDR) + sizeof(DIVERT_UDPHDR) +
        sizeof(DNS_HEADER) + data_len + sizeof(DNS_ANSWER) +
        sizeof(uint32_t);
    reply_ip_header->Length = htons((uint16_t)len);
    reply_udp_header->Length = htons((uint16_t)len - sizeof(DIVERT_IPHDR));

    ctx.divert.HelperCalcChecksums(buf, len, 0);
    ctx.addr.Direction = DIVERT_DIRECTION_INBOUND;
    ctx.divert.Send(ctx.hFilter, buf, len, &ctx.addr, NULL);
    return FALSE;
}
