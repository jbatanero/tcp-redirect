#include <stdio.h>
#include <winsock2.h>
#include "windivert.h"

#define OLD_PORT 5152
#define NEW_PORT 10000

int main()
{
    HANDLE handle;
    WINDIVERT_ADDRESS addr;
    char packet[65535];
    UINT packet_len;

    PWINDIVERT_IPHDR ip_header;
    PWINDIVERT_TCPHDR tcp_header;

    handle = WinDivertOpen(
        "outbound and tcp.DstPort == 5152",
        WINDIVERT_LAYER_NETWORK,
        0,
        0
    );

    if (handle == INVALID_HANDLE_VALUE)
    {
        printf("Erro ao abrir WinDivert\n");
        return 1;
    }

    printf("Interceptando conexoes na porta %d...\n", OLD_PORT);

    while (1)
    {
        if (!WinDivertRecv(handle, packet, sizeof(packet), &packet_len, &addr))
            continue;

        WinDivertHelperParsePacket(
    packet,
    packet_len,
    &ip_header,
    NULL,
    NULL,
    NULL,
    &tcp_header,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
);

        if (tcp_header && ntohs(tcp_header->DstPort) == OLD_PORT)
        {
            printf("Redirecionando %d -> %d\n", OLD_PORT, NEW_PORT);

            tcp_header->DstPort = htons(NEW_PORT);

            WinDivertHelperCalcChecksums(packet, packet_len, &addr, 0);
        }

        WinDivertSend(handle, packet, packet_len, NULL, &addr);
    }

    WinDivertClose(handle);

    return 0;
}