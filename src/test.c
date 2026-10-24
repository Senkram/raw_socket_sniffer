#define _GNU_SOURCE

#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/ethernet.h>    // Ethernet başlık yapısı (struct ethhdr) için
#include <linux/if_packet.h> // AF_PACKET için
#include <arpa/inet.h>       // htons() fonksiyonu için
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <linux/if_vlan.h>

struct vlanhdr
{
    uint16_t vlan_TCI;                // 3-bit Priority + 1-bit DEI + 12-bit VLAN ID
    uint16_t vlan_encapsulated_proto; // Asıl Protokol (IPv4 - ARP vb.)
};

int main()
{
    int socket_id = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (socket_id < 0)
    {
        perror("Socket oluşturulamadı");
        exit(EXIT_FAILURE);
    }

    printf("Raw socket oluşturuldu. Socket ID: %d\n", socket_id);

    unsigned char buffer[65536];
    while (1)
    {
        int data_size = recvfrom(socket_id, buffer, sizeof(buffer), 0, (struct sockaddr *)NULL, NULL);

        if (data_size < (int)sizeof(struct ethhdr)) // Eksik/hatalı paket kontrolü
        {
            continue;
        }

        // Ethernet başlığını ayrıştır
        struct ethhdr *eth = (struct ethhdr *)buffer;
        int l2_hlength = sizeof(struct ethhdr);

        // Loopback Filtresi
        if (memcmp(eth->h_source, (unsigned char[6]){0}, 6) == 0)
        {
            continue;
        }

        uint16_t eth_type = ntohs(eth->h_proto);
        printf("Kaynak MAC Adresi: %02X:%02X:%02X:%02X:%02X:%02X\n",
               eth->h_source[0], eth->h_source[1], eth->h_source[2],
               eth->h_source[3], eth->h_source[4], eth->h_source[5]);
        printf("Hedef MAC Adresi: %02X:%02X:%02X:%02X:%02X:%02X\n",
               eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
               eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
        printf("Ethernet Tipi: 0x%04X\n", ntohs(eth->h_proto));

        if (eth_type == ETH_P_8021Q)
        { // VLAN etiketi
            struct vlanhdr *vlan = (struct vlanhdr *)(buffer + l2_hlength);

            uint16_t tci = ntohs(vlan->vlan_TCI);
            uint16_t vlan_id = tci & 0x0FFF;       // Son 12-bit VLAN ID
            uint8_t priority = (tci >> 13) & 0x07; // İlk 3 bit QoS Önceliğidir (0-7)

            printf("(L2) [VLAN Etiketi] ID: %d | Öncelik (PCP): %d \n", vlan_id, priority);

            // VLAN etiketini atıp asıl L3 protokolünü tanımlıyoruz
            eth_type = ntohs(vlan->vlan_encapsulated_proto);

            l2_hlength += sizeof(struct vlanhdr);
        }

        // IP başlığını ayrıştır
        if (eth_type == ETH_P_IP)
        {
            struct iphdr *ip = (struct iphdr *)(buffer + l2_hlength);

            printf("(L3) Kaynak IP Adresi: %s \n", inet_ntoa((struct in_addr){.s_addr = ip->saddr}));
            printf("(L3) Hedef IP Adresi: %s \n", inet_ntoa((struct in_addr){.s_addr = ip->daddr}));

            switch (ip->protocol)
            {
            default:
            {
                printf("(L4) Başka bir protokol tanımlı. Protokol No: %d \n", ip->protocol);
                break;
            }
            case IPPROTO_TCP:
            {
                struct tcphdr *tcp = (struct tcphdr *)(buffer + l2_hlength + (ip->ihl * 4));

                printf("(L4) Protokol: TCP \n");
                printf("Kaynak Port: %d \n", ntohs(tcp->source));
                printf("Hedef Port: %d \n", ntohs(tcp->dest));
                if (tcp->syn && !tcp->ack)
                    printf("Bayrak: [SYN] Bağlantı Başlatma\n");
                if (tcp->fin)
                    printf("Bayrak: [FIN] Bağlantı Sonlandırma\n");
                break;
            }
            case IPPROTO_UDP:
            {
                struct udphdr *udp = (struct udphdr *)(buffer + l2_hlength + (ip->ihl * 4));

                printf("(L4) Protokol: UDP \n");
                printf("Kaynak Port: %d \n", ntohs(udp->source));
                printf("Hedef Port: %d \n", ntohs(udp->dest));
                break;
            }
            case IPPROTO_ICMP:
            {
                struct icmphdr *icmp = (struct icmphdr *)(buffer + l2_hlength + (ip->ihl * 4));

                printf("(L4) Protokol: ICMP \n");
                printf("Mesaj Tipi: %d \n", icmp->type);
                printf("ICMP Kod: %d \n", icmp->code);
                printf("ICMP Checksum (Veri Bütünlüğü Kontrolü): %d \n", icmp->checksum);

                break;
            }
            }
        }
        else if (eth_type == ETH_P_ARP)
        {
            printf("(L2 - L3) Protokol: ARP \n");
        }

        else
        {
            printf("(L2) Protokol: IPv4 veya ARP değil. EtherType: 0x%04X \n", eth_type);
        }

        // Satır olarak ayırma
        printf("-------------------------------\n");
    }
    close(socket_id);
    return 0;
}