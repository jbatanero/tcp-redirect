#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include "windivert.h"

#define MAXBUF 0xFFFF

int main(int argc, char **argv)
{
    if (argc != 4)
    {
        printf("Uso:\n");
        printf("redirect.exe <IP> <porta_origem> <porta_destino>\n");
        return 1;
    }

    const char *target_ip = argv[1];
    int src_port = atoi(argv[2]);
    int dst_port = atoi(argv[3]);

    char filter[256];

    sprintf(filter,
        "tcp and ip.DstAddr == %s and tcp.DstPort == %d and outbound",
        target_ip,
        src_port);

    HANDLE handle;
    WINDIVERT_ADDRESS addr;
    UINT8 packet[MAXBUF];
    UINT packet_len;

    WINDIVERT_IPHDR *ip_header = NULL;
    WINDIVERT_TCPHDR *tcp_header = NULL;

    handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);

    if (handle == INVALID_HANDLE_VALUE)
    {
        printf("Erro ao abrir WinDivert\n");
        return 1;
    }

    printf("Redirecionando %s:%d -> %s:%d\n",
           target_ip, src_port, target_ip, dst_port);

    while (1)
    {
        if (!WinDivertRecv(handle, packet, sizeof(packet), &packet_len, &addr))
            continue;

        ip_header = NULL;
        tcp_header = NULL;

        WinDivertHelperParsePacket(
            packet,
            packet_len,
            &ip_header,     // IPv4
            NULL,           // IPv6
            NULL,           // ICMP
            NULL,           // ICMPv6
            NULL,           // IGMP
            &tcp_header,    // TCP
            NULL,           // UDP
            NULL,           // payload
            NULL,           // payloadLen
            NULL,           // next
            NULL            // nextLen
        );

        if (tcp_header && ntohs(tcp_header->DstPort) == src_port)
        {
            printf("Pacote interceptado -> redirecionando\n");

            tcp_header->DstPort = htons(dst_port);

          WinDivertHelperCalcChecksums(
    packet,
    packet_len,
    0,
    0
);  
        }

        WinDivertSend(handle, packet, packet_len, NULL, &addr);
    }

    WinDivertClose(handle);
    return 0;
}