#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static uint16_t checksum(const uint8_t *p, size_t n) {
    uint32_t sum = 0;
    while (n > 1) { sum += ((uint16_t)p[0] << 8) | p[1]; p += 2; n -= 2; }
    if (n) sum += (uint16_t)p[0] << 8;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    const uint8_t good[6] = {0x02,0,0,0,0xa1,0x01};
    const uint8_t bad[6] = {0x02,0,0,0,0xa1,0xff};
    const uint8_t peer[6] = {0x02,0,0,0,0xa1,0x02};
    uint8_t frame[128] = {0}; size_t length = 0;
    if (!strcmp(argv[1], "wrong-mac") || !strcmp(argv[1], "wrong-ip")) {
        const uint8_t *srcmac = !strcmp(argv[1], "wrong-mac") ? bad : good;
        memcpy(frame, peer, 6); memcpy(frame + 6, srcmac, 6);
        frame[12] = 0x08; frame[13] = 0x00;
        uint8_t *ip = frame + 14;
        ip[0] = 0x45; ip[2] = 0; ip[3] = 40; ip[4] = 0; ip[5] = 1;
        ip[8] = 64; ip[9] = 253;
        inet_pton(AF_INET, !strcmp(argv[1], "wrong-ip") ? "10.0.0.99" : "10.0.0.10", ip + 12);
        inet_pton(AF_INET, "10.0.0.20", ip + 16);
        uint16_t c = htons(checksum(ip, 20)); memcpy(ip + 10, &c, 2);
        memcpy(ip + 20, "fabric-v3-spoof-test", 20); length = 54;
    } else if (!strcmp(argv[1], "arp-mac") || !strcmp(argv[1], "arp-ip")) {
        memset(frame, 0xff, 6); memcpy(frame + 6, good, 6);
        frame[12] = 0x08; frame[13] = 0x06;
        uint8_t *arp = frame + 14;
        arp[1] = 1; arp[2] = 0x08; arp[3] = 0; arp[4] = 6; arp[5] = 4; arp[7] = 1;
        const uint8_t *sha = !strcmp(argv[1], "arp-mac") ? bad : good;
        memcpy(arp + 8, sha, 6);
        inet_pton(AF_INET, !strcmp(argv[1], "arp-ip") ? "10.0.0.99" : "10.0.0.10", arp + 14);
        inet_pton(AF_INET, "10.0.0.20", arp + 24); length = 42;
    } else return 2;
    unsigned index = if_nametoindex("eth0"); if (!index) return 3;
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); if (fd < 0) return 4;
    struct sockaddr_ll s = {.sll_family=AF_PACKET,.sll_protocol=htons(ETH_P_ALL),.sll_ifindex=(int)index};
    ssize_t sent = sendto(fd, frame, length, 0, (struct sockaddr *)&s, sizeof(s));
    close(fd); if (sent != (ssize_t)length) return 5;
    printf("sent guest probe %s length=%zu\n", argv[1], length); fflush(stdout);
    return 0;
}
