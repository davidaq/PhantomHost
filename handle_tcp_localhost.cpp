#include <iostream>
#include "include/windivert.h"
#include "include/defs.h"

struct OUT_PORT_RECORD_S {
    UINT ip;
    USHORT port;
    UINT origin_dst_ip;
    USHORT origin_dst_port;
    UINT origin_src_ip;
    USHORT origin_src_port;
};
typedef struct OUT_PORT_RECORD_S OUT_PORT_RECORD;


static BOOL handle(PACKET_CONTEXT& ctx) {
    static OUT_PORT_RECORD out_ports[65536] = {0};
    if (ctx.ip_header == NULL || ctx.tcp_header == NULL) {
        return FALSE;
    }
    BOOL modified = FALSE;

    OUT_PORT_RECORD origin;
    origin.origin_dst_ip = ctx.ip_header->DstAddr;
    origin.origin_dst_port = ctx.tcp_header->DstPort;
    origin.origin_src_ip = ctx.ip_header->SrcAddr;
    origin.origin_src_port = ctx.tcp_header->SrcPort;

    if (ctx.addr.Direction == WINDIVERT_DIRECTION_OUTBOUND) {
        if (ctx.ip_header->DstAddr == ctx.host_ip) {
            PORT_ROUTE* route = ctx.route[ctx.tcp_header->DstPort];
            if (route) {
                ctx.ip_header->DstAddr = route->ip;
                ctx.tcp_header->DstPort = route->port;
                if ((route->ip & 0xff) == 0x7f || ctx.ip_header->DstAddr == ctx.ip_header->SrcAddr) {
                    ctx.ip_header->DstAddr = ctx.ip_header->SrcAddr;
                    ctx.ip_header->SrcAddr = ctx.host_ip;
                    ctx.addr.Direction = WINDIVERT_DIRECTION_INBOUND;
                }
                OUT_PORT_RECORD& record = out_ports[ctx.tcp_header->SrcPort];
                record = origin;
                record.ip = ctx.ip_header->DstAddr;
                record.port = ctx.tcp_header->DstPort;
                return TRUE;
            }
            const OUT_PORT_RECORD &out = out_ports[ctx.tcp_header->DstPort];
            if (out.ip == ctx.ip_header->SrcAddr && out.port == ctx.tcp_header->SrcPort) {
                ctx.ip_header->SrcAddr = out.origin_dst_ip;
                ctx.tcp_header->SrcPort = out.origin_dst_port;
                ctx.ip_header->DstAddr = out.origin_src_ip;
                ctx.tcp_header->DstPort = out.origin_src_port;
                ctx.addr.Direction = WINDIVERT_DIRECTION_INBOUND;
                return TRUE;
            }
        }
    } else if (ctx.addr.Direction == WINDIVERT_DIRECTION_INBOUND) {
        const OUT_PORT_RECORD &out = out_ports[ctx.tcp_header->DstPort];
        if (out.ip == ctx.ip_header->SrcAddr && out.port == ctx.tcp_header->SrcPort) {
            ctx.ip_header->SrcAddr = out.origin_dst_ip;
            ctx.tcp_header->SrcPort = out.origin_dst_port;
            ctx.ip_header->DstAddr = out.origin_src_ip;
            ctx.tcp_header->DstPort = out.origin_src_port;
            return TRUE;
        }
    }
    return FALSE;
}

BOOL handle_tcp(PACKET_CONTEXT& ctx) {
    if (handle(ctx)) {
        if (ctx.tcp_header->Syn) {
            std::cout << (ctx.addr.Direction == WINDIVERT_DIRECTION_INBOUND ? "IN  ":"OUT ") << ' '
                << iptostr(ctx.ip_header->SrcAddr) << ':' << ntohs(ctx.tcp_header->SrcPort) << "\t -> "
                << iptostr(ctx.ip_header->DstAddr) << ':' << ntohs(ctx.tcp_header->DstPort) << std::endl;
        }
        ctx.divert.HelperCalcChecksums(ctx.packet, ctx.packet_len, 0);
        ctx.divert.Send(ctx.hFilter, ctx.packet, ctx.packet_len, &ctx.addr, &ctx.packet_len);
        return TRUE;
    }
    return FALSE;
}
