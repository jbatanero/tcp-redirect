tcp-redirect

Ferramenta em C para Windows que intercepta conexões TCP e redireciona a porta de destino utilizando o driver WinDivert.

Exemplo de uso:

10.0.0.0:5152 → 10.0.0.0:10000

Requisitos

Windows 10 ou superior
Driver WinDivert
GCC (MinGW ou similar)
Executar como Administrador

Arquivos necessários na pasta do projeto:

WinDivert.dll
WinDivert.lib
WinDivert64.sys
windivert.h
main.c


Compilação

No prompt de comando dentro da pasta do projeto:

gcc main.c -o redirect.exe WinDivert.lib -lws2_32

A biblioteca ws2_32 pertence à Winsock, responsável pelas funções de rede do Windows.


Execução

Abra o Prompt de Comando como Administrador.

Execute: redirect.exe <IP> <porta_origem> <porta_destino>

Saída esperada: Redirecionando 10.0.0.0:5152 → 10.0.0.0:10000


Funcionamento

O programa:

Intercepta pacotes TCP que saem da máquina

Filtra conexões destinadas ao IP e porta especificados

Altera o campo Destination Port no cabeçalho TCP

Recalcula checksums

Reenvia o pacote modificado


Fluxo simplificado:

Aplicação
   ↓
TCP Packet (porta 5152)
   ↓
WinDivert intercepta
   ↓
tcp-redirect altera porta
   ↓
TCP Packet (porta 10000)
   ↓
Rede
