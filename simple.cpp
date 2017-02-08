#include <iostream>
#include <windows.h>
#include <cstdlib>
#include <stdio.h>
#include "include/windivert.h"
#include "include/defs.h"

const char* HELP_MESSAGE =
    "Usage:\n"
    "   SambaProxy [-ip VirtualIP] TargetIP[:TargetPort]"
    "\n"
    "By default VirtualIP would be 1.1.1.1 and TargetPort be 445\n"
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

    const char* key = 0;
    BOOL has_route = FALSE;
    USHORT smb_port = htons(445);
//    for (int i = 1; i < argc; i++) {
//        char* arg = argv[i];
//        if (key) {
//            if (strcmp(key, "ip") == 0) {
//                UCHAR* ip = (UCHAR*)&ctx.host_ip;
//                char* ptr = arg;
//                for (int i = 0; i < 4; i++) {
//                    ip[i] = strtol(ptr, &ptr, 10);
//                    if (ptr[0] != 0 && ptr[0] != '.') {
//                        ctx.host_ip = 0;
//                        break;
//                    }
//                    ptr++;
//                }
//                if (ctx.host_ip) {
//                    ctx.host_ip = ctx.host_ip;
//                }
//            }
//            key = 0;
//        } else if (arg[0] == '-') {
//            key = arg + 1;
//            if (key[0] == '-')
//                key++;
//            if (strcmp(key, "help") == 0 || strcmp(key, "h") == 0) {
//                std::cout << HELP_MESSAGE << std::endl;
//                return "";
//            }
//        } else {
//            char* ptr = arg;
//            UINT dest_ip = 0;
//            UCHAR* ip;
//            ip = (UCHAR*)&dest_ip;
//            for (int i = 0; i < 4; i++) {
//                ip[i] = (UCHAR)strtol(ptr, &ptr, 10);
//                if (ptr[0] != ':' && ptr[0] != '.' && ptr[0] != 0) {
//                    dest_ip = 0;
//                    break;
//                }
//                if (i < 3)
//                    ptr++;
//            }
//            if (!dest_ip) {
//                continue;
//            }
//            USHORT dest_port;
//            if (ptr[0] == 0) {
//                dest_port = 445;
//            } else {
//                ptr++;
//                dest_port = htons((USHORT)strtol(ptr, &ptr, 10));
//            }
//            if (ptr[0] != 0) {
//                continue;
//            }
//            ctx.route[smb_port] = (PORT_ROUTE*)malloc(sizeof(PORT_ROUTE));
//            ctx.route[smb_port]->ip = dest_ip;
//            ctx.route[smb_port]->port = dest_port;
//            has_route = TRUE;
//        }
//    }
    ctx.route[smb_port] = (PORT_ROUTE*)malloc(sizeof(PORT_ROUTE));
    ctx.route[smb_port]->ip = 0x0100007f;
    ctx.route[smb_port]->port = dest_port;
//    if (!ctx.route[smb_port]) {
//        std::cout << std::endl << HELP_MESSAGE << std::endl;
//        return "Must define target host";
//    }
    if (!ctx.host_ip) {
        ctx.host_ip = 0x01010101;
    }
    const std::string& host_ip_str = iptostr(ctx.host_ip).c_str();
    const std::string& dest_ip_str = iptostr(ctx.route[smb_port]->ip).c_str();
    std::cout << "Creating Samba Proxy:     " << host_ip_str << std::endl;
    if (ctx.route[smb_port]) {
        UINT dest_ip = ctx.route[smb_port]->ip;
        UCHAR* ip = (UCHAR*)&dest_ip;
        std::cout << "    " << 445 << " ==> " << iptostr(dest_ip)
            << ":" << ntohs(ctx.route[smb_port]->port) << std::endl;
    }

    const char* host_ip_str_c = host_ip_str.c_str();
    const char* dest_ip_str_c = dest_ip_str.c_str();
    char filter_expr[500];
    sprintf(
        filter_expr,
        "(icmp and outbound and ip.DstAddr == %s) or "
        "(tcp and outbound and ip.DstAddr == %s and tcp.DstPort == 445) or "
        "(tcp and inbound and ip.SrcAddr == %s and tcp.SrcPort = %d)",
        host_ip_str_c, host_ip_str_c, dest_ip_str_c, ntohs(ctx.route[smb_port]->port)
    );
    ctx.hFilter = ctx.divert.Open(filter_expr, WINDIVERT_LAYER_NETWORK, 0, 0);
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
        RUN_HANDLER(handle_tcp_localhost);
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
