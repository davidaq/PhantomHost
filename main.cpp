#include <iostream>
#include <sstream>
#include <windows.h>
#include <cstdlib>
#include <stdio.h>
#include "include/windivert.h"
#include "include/defs.h"

const char* HELP_MESSAGE =
    "Usage:\n"
    "   PhantomHost [--host domain.name] [--ip x.x.x.x] [PORT=DEST_IP:DEST_PORT] ...\n"
    "\n"
    "Example:\n"
    "   PhantomHost --host my.domain.com --ip 1.1.1.1 80=192.168.1.1:8088\n"
    "\n"
    "Multiple port mapping is allowed, just append mapping rule in the arguments.\n"
    "\n";

std::string program(int argc, char** argv, int& exitCode) {
    if (argc <= 1) {
        std::cout << HELP_MESSAGE << std::endl;
        return "";
    }

    PACKET_CONTEXT ctx = {0};

    HINSTANCE hDLL = LoadLibrary("lib\\WinDivert");
    if (!hDLL) {
        return "Can not find WinDivert library";
    }
#define DEF_STR(X) #X
#define DIVERT(X) ctx.divert.X = (WinDivert ## X ## Func)GetProcAddress(hDLL, DEF_STR(WinDivert ## X))
    DIVERT(Open);
    DIVERT(Close);
    DIVERT(Recv);
    DIVERT(Send);
    DIVERT(HelperParsePacket);
    DIVERT(HelperCalcChecksums);
#undef DIVERT
#undef DEF_STR

    ctx.host_domain = "phantom.name";
    const char* key = 0;
    BOOL has_route = FALSE;
    for (int i = 1; i < argc; i++) {
        char* arg = argv[i];
        if (key) {
            if (strcmp(key, "domain") == 0) {
                ctx.host_domain = arg;
            } else if (strcmp(key, "ip") == 0) {
                UCHAR* ip = (UCHAR*)&ctx.host_ip;
                char* ptr = arg;
                for (int i = 0; i < 4; i++) {
                    ip[i] = strtol(ptr, &ptr, 10);
                    if (ptr[0] != 0 && ptr[0] != '.') {
                        ctx.host_ip = 0;
                        break;
                    }
                    ptr++;
                }
                if (ctx.host_ip) {
                    ctx.host_ip = ctx.host_ip;
                }
            }
            key = 0;
        } else if (arg[0] == '-') {
            key = arg + 1;
            if (key[0] == '-')
                key++;
            if (strcmp(key, "help") == 0 || strcmp(key, "h") == 0) {
                std::cout << HELP_MESSAGE << std::endl;
                return "";
            }
        } else {
            char* ptr = arg;
            UINT dest_ip = 0;
            UCHAR* ip;
            USHORT port = htons((USHORT)strtol(ptr, &ptr, 10));
            if (ptr[0] != '=')
                continue;
            ptr++;
            ip = (UCHAR*)&dest_ip;
            for (int i = 0; i < 4; i++) {
                ip[i] = (UCHAR)strtol(ptr, &ptr, 10);
                if (ptr[0] != ':' && ptr[0] != '.') {
                    dest_ip = 0;
                    break;
                }
                ptr++;
            }
            if (!dest_ip) {
                continue;
            }
            USHORT dest_port = htons((USHORT)strtol(ptr, &ptr, 10));
            if (ptr[0] != 0) {
                continue;
            }
            ctx.route[port] = (PORT_ROUTE*)malloc(sizeof(PORT_ROUTE));
            ctx.route[port]->ip = dest_ip;
            ctx.route[port]->port = dest_port;
            has_route = TRUE;
        }
    }
    if (!has_route) {
        std::cout << std::endl << HELP_MESSAGE << std::endl;
        return "Must define at least one route rule";
    }
    if (ctx.host_domain[0] == 0) {
        return "Invalid host name";
    }
    UCHAR host_ip[4];
    if (!ctx.host_ip) {
        UCHAR h = 0, l = 0;
        for (const char* ptr = ctx.host_domain; *ptr != 0; ptr++) {
            h ^= *ptr;
            l += ((int)l + (int)*ptr) & 0xff;
        }
        host_ip[0] = 0x0a;
        host_ip[1] = 0xf7;
        host_ip[2] = h;
        host_ip[3] = l;
        ctx.host_ip = *((UINT*)host_ip);
    } else {
        *((UINT*)(&host_ip)) = ctx.host_ip;
    }
    const std::string& host_ip_str = iptostr(*((UINT*)host_ip)).c_str();
    std::cout << "Creating phantom host:     " << ctx.host_domain << " (" << host_ip_str << ')' << std::endl;

    std::stringstream filter_expr_io;
    filter_expr_io << "(udp and outbound and udp.DstPort == 53) or "
        << "(icmp and outbound and ip.DstAddr == " << host_ip_str << ") or ";

    for (int i = 0; i < 65536; i++) {
        if (ctx.route[i]) {
            UINT dest_ip = ctx.route[i]->ip;
            UCHAR* ip = (UCHAR*)&dest_ip;
            std::stringstream ip_str_io;
            ip_str_io << (int)ip[0] << '.' << (int)ip[1] << '.' << (int)ip[2] << '.' << (int)ip[3];
            const std::string& ip_str = ip_str_io.str();
            const UINT dest_port = ntohs(ctx.route[i]->port);
            std::cout << "    " << ntohs(i) << " ==> " << ip_str << ":" << dest_port << std::endl;
            if (ip[0] != 127) {
                filter_expr_io << "(tcp and inbound and ip.SrcAddr == " << ip_str << " and tcp.SrcPort == " << dest_port << ") or ";
            }
        }
    }
    filter_expr_io << "(tcp and outbound and ip.DstAddr == " << host_ip_str << ")";
    const std::string& filter_expr = filter_expr_io.str();

    ctx.hFilter = ctx.divert.Open(filter_expr.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);
    if (ctx.hFilter == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err == 2) {
            return "Can not find WinDivert driver";
            exitCode = 1;
        }
        if (err == 5) {
            exitCode = 2;
            return "Must start as administrator";
        }
        return "Can not setup TCP filtering.";
    }
    std::cout << "Tunneling..." << std::endl;
    for (;;) {
        if (!ctx.divert.Recv(ctx.hFilter, ctx.packet, sizeof(ctx.packet), &ctx.addr, &ctx.packet_len)) {
            std::cerr << "warning: failed to read packet" << std::endl;
            continue;
        }
        ctx.divert.HelperParsePacket(ctx.packet, ctx.packet_len, &ctx.ip_header,
            &ctx.ipv6_header, &ctx.icmp_header, &ctx.icmpv6_header, &ctx.tcp_header,
            &ctx.udp_header, &ctx.payload, &ctx.payload_len);
#define RUN_HANDLER(X) if (X(ctx)) continue
        RUN_HANDLER(handle_dns);
        RUN_HANDLER(handle_tcp);
        RUN_HANDLER(handle_icmp);
#undef RUN_HANDLER
        ctx.divert.Send(ctx.hFilter, ctx.packet, ctx.packet_len, &ctx.addr, &ctx.packet_len);
    }
    ctx.divert.Close(ctx.hFilter);
    return "";
}

int main(int argc, char** argv) {
    int exitCode = 0;
    std::string errmsg = program(argc, argv, exitCode);
    if (errmsg.size()) {
        std::cerr << "Error: " << errmsg << std::endl;
        if (!exitCode)
            exitCode = -1;
    }
    return exitCode;
}
