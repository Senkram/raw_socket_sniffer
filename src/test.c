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
#include <time.h>
#include <stdbool.h>

struct vlanhdr
{
    uint16_t vlan_TCI;                // 3-bit Priority + 1-bit DEI + 12-bit VLAN ID
    uint16_t vlan_encapsulated_proto; // Asıl Protokol (IPv4 - ARP vb.)
};

// log tuttuğumuz dosya
FILE *log_file = NULL;

void log_packet()
{
    if (!log_file)
    {
        printf("There is no file.\n");
        return;
    }

    time_t now = time(NULL);
    struct tm *time_struct = localtime(&now);
    char time_str[100];
    strftime(time_str, 100, "%d.%m.%Y %H:%M:%S", time_struct); // time bilgisine format veriyoruz

    printf("%s \n", time_str);
    fprintf(log_file, "%s \n", time_str);
}

int main(int argc, char *argv[]) // argv[0]: Program adı, argv[1]: Paket kapasitesi
{
    int packet_cap = 10; // default paket kapasitesi
    int packet_count = 0;

    if (argc > 1)
    {
        int packet_cap_input = atoi(argv[1]);
        packet_cap_input <= 0 ? printf("Geçersiz paket kapasite değeri!") : (packet_cap = packet_cap_input);
        // Paket kapasitesi değeri 0 veya küçükse uyar ve default değeri kullan, değilse paket kapasitesi olarak set et
    }

    // Dosyayı append modunda açıyoruz (append: Yoksa oluştur, varsa ekleme yap)
    log_file = fopen("sniffer.log", "a");

    // Paketleri alacak soketi oluşturuyoruz
    int socket_id = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (socket_id < 0)
    {
        perror("Socket oluşturulamadı");
        exit(EXIT_FAILURE);
    }

    printf("Raw socket oluşturuldu. Socket ID: %d\n", socket_id);
    log_packet();

    unsigned char buffer[65536];      // Paketleri alacağımız buffer (tampon)
    while (packet_count < packet_cap) // Paket sayısı paket kapasitesinden az ise devam ets
    {
        // Paketi çekiyoruz
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

        // Paket kabul edildi
        packet_count++;

        uint16_t eth_type = ntohs(eth->h_proto);
        printf("Kaynak MAC Adresi: %02X:%02X:%02X:%02X:%02X:%02X\n",
               eth->h_source[0], eth->h_source[1], eth->h_source[2],
               eth->h_source[3], eth->h_source[4], eth->h_source[5]);
        fprintf(log_file, "Kaynak MAC Adresi: %02X:%02X:%02X:%02X:%02X:%02X\n",
                eth->h_source[0], eth->h_source[1], eth->h_source[2],
                eth->h_source[3], eth->h_source[4], eth->h_source[5]);
        printf("Hedef MAC Adresi: %02X:%02X:%02X:%02X:%02X:%02X\n",
               eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
               eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
        fprintf(log_file, "Hedef MAC Adresi: %02X:%02X:%02X:%02X:%02X:%02X\n",
                eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
                eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

        printf("Ethernet Tipi: 0x%04X\n", ntohs(eth->h_proto));
        fprintf(log_file, "Ethernet Tipi: 0x%04X\n", ntohs(eth->h_proto));

        if (eth_type == ETH_P_8021Q)
        { // VLAN etiketi
            struct vlanhdr *vlan = (struct vlanhdr *)(buffer + l2_hlength);

            if ((data_size - l2_hlength) < sizeof(struct vlanhdr))
            {
                // Eğer paket boyutu l2_hlength çıkıldığında (Şuan sadece ethernet hdr boyutu kadar)
                // vlanhdr boyutundan küçükse paketi çöpe at
                // Not: Şuan Ethernet etiketindeki kodlar yine de çalışıyor
                continue;
            }

            uint16_t tci = ntohs(vlan->vlan_TCI);
            uint16_t vlan_id = tci & 0x0FFF;       // Son 12-bit VLAN ID
            uint8_t priority = (tci >> 13) & 0x07; // İlk 3 bit QoS Önceliğidir (0-7)

            printf("(L2) [VLAN Etiketi] ID: %d | Öncelik (PCP): %d \n", vlan_id, priority);
            fprintf(log_file, "(L2) [VLAN Etiketi] ID: %d | Öncelik (PCP): %d \n", vlan_id, priority);

            // VLAN etiketini atıp asıl L3 protokolünü tanımlıyoruz
            eth_type = ntohs(vlan->vlan_encapsulated_proto);

            // VLAN etiketini katman 2 boyutuna ekliyoruz
            l2_hlength += sizeof(struct vlanhdr);
        }

        // IP başlığını ayrıştır
        if (eth_type == ETH_P_IP)
        {
            struct iphdr *ip = (struct iphdr *)(buffer + l2_hlength);

            if ((ip->ihl < 5) | ((data_size - l2_hlength) < (ip->ihl * 4)))
            {
                // Eğer ihl değeri 5'den küçükse (ihl * 4 == L3 hdr size) veya
                // paket (L2 header kısmı çıkartıldığında) belirtilen değerden küçükse paketi kabul etme
                // Not: Şuan paket burada çıkarılsa bile L2 kısmındaki işlemler gerçekleşiyor
                continue;
            }

            if (ntohs(ip->tot_len) > (data_size - l2_hlength))
            {
                // Eğer Total length (L3 hdr + payload) alınan paketten büyükse paket eksik gelmiş demektir
                // Not: Total length paketten daha küçük olabilir çünkü pakete padding eklenebilir
                continue;
            }

            // Katman 3 header boyutu
            int l3_hlength = ip->ihl * 4;

            // Bu paket parça şeklinde mi?
            bool bis_fragment = false;

            switch (((ntohs(ip->frag_off) >> 13) & 0x07))
            {
            // 0-0-0: Bölünebilir, son parça
            // 0-0-1: Bölünebilir, daha fazla parça var
            // 0-1-0: Bölünemez
            case 0x00:
            {
                break;
            }

            case 0x01:
            {
                break;
            }

            case 0x02:
            {
                // Bölünemez ve offset var ise hatalı
                // 0001-1111-1111-1111 ile çarp
                if ((ntohs(ip->frag_off) & 0x1FFF) != 0)
                    continue;

                break;
            }

            // Hatalı paket
            default:
                continue;
            }

            // Eğer offset 0 ise ilk paket
            if ((ntohs(ip->frag_off) & 0x1FFF) == 0)
            {
                // L4 parse etmeye devam et
            }
            // Offset 0 değil ise
            else
            {
                // Bu bir parça (fragment) yani L4 header'ı yok
                bis_fragment = true;
            }

            printf("(L3) Kaynak IP Adresi: %s \n", inet_ntoa((struct in_addr){.s_addr = ip->saddr}));
            printf("(L3) Hedef IP Adresi: %s \n", inet_ntoa((struct in_addr){.s_addr = ip->daddr}));
            printf("(L3) Bu paket bir parça mı: %d \n", (int)bis_fragment);
            fprintf(log_file, "(L3) Kaynak IP Adresi: %s \n", inet_ntoa((struct in_addr){.s_addr = ip->saddr}));
            fprintf(log_file, "(L3) Hedef IP Adresi: %s \n", inet_ntoa((struct in_addr){.s_addr = ip->daddr}));

            switch (ip->protocol)
            {
            default:
            {
                printf("(L4) Başka bir protokol tanımlı. Protokol No: %d \n", ip->protocol);
                fprintf(log_file, "(L4) Başka bir protokol tanımlı. Protokol No: %d \n", ip->protocol);
                break;
            }
            case IPPROTO_TCP:
            {
                struct tcphdr *tcp = (struct tcphdr *)(buffer + l2_hlength + l3_hlength);

                if ((data_size - (l2_hlength + l3_hlength) < sizeof(struct tcphdr)))
                {
                    // Paket (L2 ve L3 header kısmı çıkartıldığında) belirtilen değerden küçükse paketi kabul etme
                    // Not: Şuan paket burada çıkarılsa bile L2 ve L3 kısmındaki işlemler gerçekleşiyor
                    continue;
                }

                printf("(L4) Protokol: TCP \n");
                printf("Kaynak Port: %d \n", ntohs(tcp->source));
                printf("Hedef Port: %d \n", ntohs(tcp->dest));
                fprintf(log_file, "(L4) Protokol: TCP \n");
                fprintf(log_file, "Kaynak Port: %d \n", ntohs(tcp->source));
                fprintf(log_file, "Hedef Port: %d \n", ntohs(tcp->dest));

                if (tcp->syn && !tcp->ack)
                {
                    printf("Bayrak: [SYN] Bağlantı Başlatma\n");
                    fprintf(log_file, "Bayrak: [SYN] Bağlantı Başlatma\n");
                }
                if (tcp->fin)
                {
                    printf("Bayrak: [FIN] Bağlantı Sonlandırma\n");
                    fprintf(log_file, "Bayrak: [FIN] Bağlantı Sonlandırma\n");
                }
                break;
            }
            case IPPROTO_UDP:
            {
                struct udphdr *udp = (struct udphdr *)(buffer + l2_hlength + l3_hlength);

                if ((data_size - (l2_hlength + l3_hlength) < sizeof(struct udphdr)))
                {
                    // Paket (L2 ve L3 header kısmı çıkartıldığında) belirtilen değerden küçükse paketi kabul etme
                    // Not: Şuan paket burada çıkarılsa bile L2 ve L3 kısmındaki işlemler gerçekleşiyor
                    continue;
                }

                printf("(L4) Protokol: UDP \n");
                printf("Kaynak Port: %d \n", ntohs(udp->source));
                printf("Hedef Port: %d \n", ntohs(udp->dest));

                fprintf(log_file, "(L4) Protokol: UDP \n");
                fprintf(log_file, "Kaynak Port: %d \n", ntohs(udp->source));
                fprintf(log_file, "Hedef Port: %d \n", ntohs(udp->dest));
                break;
            }
            case IPPROTO_ICMP:
            {
                struct icmphdr *icmp = (struct icmphdr *)(buffer + l2_hlength + l3_hlength);

                if ((data_size - (l2_hlength + l3_hlength) < sizeof(struct icmphdr)))
                {
                    // Paket (L2 ve L3 header kısmı çıkartıldığında) belirtilen değerden küçükse paketi kabul etme
                    // Not: Şuan paket burada çıkarılsa bile L2 ve L3 kısmındaki işlemler gerçekleşiyor
                    continue;
                }

                printf("(L4) Protokol: ICMP \n");
                printf("Mesaj Tipi: %d \n", icmp->type);
                printf("ICMP Kod: %d \n", icmp->code);
                printf("ICMP Checksum (Veri Bütünlüğü Kontrolü): %d \n", icmp->checksum);

                fprintf(log_file, "(L4) Protokol: ICMP \n");
                fprintf(log_file, "Mesaj Tipi: %d \n", icmp->type);
                fprintf(log_file, "ICMP Kod: %d \n", icmp->code);
                fprintf(log_file, "ICMP Checksum (Veri Bütünlüğü Kontrolü): %d \n", icmp->checksum);

                break;
            }
            }
        }
        else if (eth_type == ETH_P_ARP)
        {
            printf("(L2 - L3) Protokol: ARP \n");
            fprintf(log_file, "(L2 - L3) Protokol: ARP \n");
        }

        else
        {
            printf("(L2) Protokol: IPv4 veya ARP değil. EtherType: 0x%04X \n", eth_type);
            fprintf(log_file, "(L2) Protokol: IPv4 veya ARP değil. EtherType: 0x%04X \n", eth_type);
        }

        // Satır olarak ayırma
        printf("-------------------------------\n");
        fprintf(log_file, "-------------------------------\n");
    }

    fclose(log_file);
    close(socket_id);
    return 0;
}