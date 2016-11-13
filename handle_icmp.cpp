#include <iostream>
#include "include/windivert.h"
#include "include/defs.h"

BOOL handle_icmp(PACKET_CONTEXT& ctx) {
    if (!ctx.ip_header || !ctx.icmp_header || ctx.addr.Direction != WINDIVERT_DIRECTION_OUTBOUND) {
        return FALSE;
    }
    if (ctx.icmp_header->Type != 0x8 || ctx.icmp_header->Code != 0 ||  ctx.ip_header->DstAddr != ctx.host_ip) {
        return FALSE;
    }
    ctx.icmp_header->Type = 0;
    ctx.ip_header->DstAddr = ctx.ip_header->SrcAddr;
    ctx.ip_header->SrcAddr = ctx.host_ip;
    ctx.addr.Direction = WINDIVERT_DIRECTION_INBOUND;
    ctx.divert.HelperCalcChecksums(ctx.packet, ctx.packet_len, WINDIVERT_HELPER_NO_UDP_CHECKSUM);
    ctx.divert.Send(ctx.hFilter, ctx.packet, ctx.packet_len, &ctx.addr, &ctx.packet_len);
    return TRUE;
}
