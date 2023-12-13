#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>

extern int DebugPrintf(char *fmt, ...);
extern int DebugPerror(char *msg);

/*
ネットワークインターフェースに関する情報を収集・設定するためのデータ構造
struct ifreq {
    char ifr_name[IFNAMSIZ]; /* インターフェースの名前 (e.g., "eth0")
    union {
        struct sockaddr ifr_addr;      インターフェースのアドレス
        struct sockaddr ifr_dstaddr;   P-to-P リンクの宛先アドレス
        struct sockaddr ifr_broadaddr; ブロードキャストアドレス
        struct sockaddr ifr_netmask;   サブネットマスク
        struct sockaddr ifr_hwaddr;    ハードウェアアドレス
        short           ifr_flags;     フラグ
        int             ifr_ifindex;   インターフェースのインデックス
        int             ifr_metric;    インターフェースのメトリック
        int             ifr_mtu;       MTU のサイズ
        struct ifmap    ifr_map;       メモリマップ構造体
        char            ifr_slave[IFNAMSIZ]; スレーブのインターフェース名
        char            ifr_newname[IFNAMSIZ]; インターフェースの新しい名前
        char            ifr_data[IFHWADDRLEN]; ハードウェアアドレス
    };
};

ローカルリンク層のアドレスを表現するためのデータ構造体
struct sockaddr_ll {
    unsigned short sll_family;    Always AF_PACKET
    unsigned short sll_protocol;  パケットのプロトコル
    int            sll_ifindex;  インターフェースのインデックス
    unsigned short sll_hatype;   ハードウェアアドレスのタイプ
    unsigned char  sll_pkttype;  パケットのタイプ
    unsigned char  sll_halen;    ハードウェアアドレスの長さ
    unsigned char  sll_addr[8];  ハードウェアアドレス
};


*/

int InitRawSocket(char *device, int promiscFlag, int ipOnly)
{

    struct ifreq ifreq;    // ローカルリンク層のアドレスを表現するためのデータ構造体
    struct sockaddr_ll sa; // ネットワークインターフェースに関する情報を収集・設定するためのデータ構造
    int soc;               // socket識別子

    if (ipOnly)
    {
        // socket: ソケットを作成するためのシステムコール。
        // PF_PACKET: パケットファミリーを指定ner workfamily を直接取り扱うため
        // データリンク層を指定->SOCK_RAW
        // protocol->ether_header,protocol->IPのみを指定
        if ((soc = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0)
        {
            DebugPerror("socket");
            return (-1);
        }
    }
    else
    {
        if ((soc = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
        {
            DebugPerror("socket");
            return (-1);
        }
    }

    memset(&ifreq, 0, sizeof(struct ifreq));
    strncpy(ifreq.ifr_name, device, sizeof(ifreq.ifr_name) - 1);
    // protocol->findindec->ネットワークデバイスのインデックス
    if (ioctl(soc, SIOCGIFINDEX, &ifreq) < 0)
    {
        DebugPerror("ioctl");
        close(soc);
        return (-1);
    }
    // sockROWを指定
    sa.sll_family = PF_PACKET;

    if (ipOnly)
    {
        sa.sll_protocol = htons(ETH_P_IP);
    }
    else
    {
        sa.sll_protocol = htons(ETH_P_ALL);
    }
    sa.sll_ifindex = ifreq.ifr_ifindex; // ネットワークデバイスのインデックス

    // bind 関数を使用して、interface indexとdeviceを結びつける
    if (bind(soc, (struct sockaddr *)&sa, sizeof(sa)) < 0)
    {
        DebugPerror("bind");
        close(soc);
        return (-1);
    }

    if (promiscFlag)
    {
        //
        if (ioctl(soc, SIOCGIFFLAGS, &ifreq) < 0)
        {
            DebugPerror("ioctl");
            close(soc);
            return (-1);
        }
        ifreq.ifr_flags = ifreq.ifr_flags | IFF_PROMISC;
        if (ioctl(soc, SIOCSIFFLAGS, &ifreq) < 0)
        {
            DebugPerror("ioctl");
            close(soc);
            return (-1);
        }
    }

    return (soc);
}

int GetDeviceInfo(char *device, __u_char hwaddr[6], struct in_addr *uaddr, struct in_addr *subnet, struct in_addr *mask)
{
    struct ifreq ifreq;
    struct sockaddr_in addr;
    int soc;
    __u_char *p;

    // socket システムコール PF_INET->IPv4 SOCK_DGRAM->UDPsoc
    if ((soc = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
    {
        DebugPerror("socket");
        return (-1);
    }

    // reset
    memset(&ifreq, 0, sizeof(struct ifreq));
    strncpy(ifreq.ifr_name, device, sizeof(ifreq.ifr_name) - 1);

    // control->SIOCGIFHWADDR（ネットワークデバイスのハードウェアアドレスを取得する）
    if (ioctl(soc, SIOCGIFHWADDR, &ifreq) == -1)
    {
        DebugPerror("ioctl");
        close(soc);
        return (-1);
    }
    else
    {
        // ハードウェアアドレス（MACアドレス）を取得する
        p = (__u_char *)&ifreq.ifr_hwaddr.sa_data;
        memcpy(hwaddr, p, 6);
    }

    // SIOCGIFADDR は、指定されたネットワークデバイスのIPv4アドレスを取得
    // 取得したアドレスがIPv4であるかどうかを確認。成功した場合、取得したIPv4アドレスが uaddr に格納されます。
    if (ioctl(soc, SIOCGIFADDR, &ifreq) == -1)
    {
        DebugPerror("ioctl");
        close(soc);
        return (-1);
    }
    else if (ifreq.ifr_addr.sa_family != PF_INET)
    {
        // PF_INET（IPv4のファミリー）でない場合
        DebugPrintf("%s not PF_INET\n", device);
        close(soc);
        return (-1);
    }
    else
    {
        // addrにIPv4を代入　
        memcpy(&addr, &ifreq.ifr_addr, sizeof(struct sockaddr_in));
        *uaddr = addr.sin_addr;
    }

    // SIOCGIFNETMASK は、指定されたネットワークデバイスのサブネットマスクを取得する
    if (ioctl(soc, SIOCGIFNETMASK, &ifreq) == -1)
    {
        DebugPerror("ioctl");
        close(soc);
        return (-1);
    }
    else
    {
        // addrにサブネットマスクを代入
        memcpy(&addr, &ifreq.ifr_addr, sizeof(struct sockaddr_in));
        *mask = addr.sin_addr;
    }

    // subnet->s_addr に、ネットワークデバイスのIPアドレス (uaddr->s_addr) とサブネットマスク (mask->s_addr)
    // をビット単位でAND演算した結果を代入します。
    // これにより、ネットワークアドレス（サブネット部分）が subnet に格納されます。
    subnet->s_addr = ((uaddr->s_addr) & (mask->s_addr));

    close(soc);

    return (0);
}

// MACaddの文字列化する
char *my_ether_ntoa_r(u_char *hwaddr, char *buf, socklen_t size)
{
    snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x",
             hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);

    return (buf);
}

// IPアドレスの文字列化 (struct in_addr用)
char *my_inet_ntoa_r(struct in_addr *addr, char *buf, socklen_t size)
{
    inet_ntop(PF_INET, addr, buf, size);

    return (buf);
}

// IPadd （in_addr_t用）
char *in_addr_t2str(in_addr_t addr, char *buf, socklen_t size)
{
    struct in_addr a;

    a.s_addr = addr;
    inet_ntop(PF_INET, &a, buf, size);

    return (buf);
}

int PrintEtherHeader(struct ether_header *eh, FILE *fp)
{
    char buf[80];

    fprintf(fp, "ether_header----------------------------\n");
    fprintf(fp, "ether_dhost=%s\n", my_ether_ntoa_r(eh->ether_dhost, buf, sizeof(buf)));
    fprintf(fp, "ether_shost=%s\n", my_ether_ntoa_r(eh->ether_shost, buf, sizeof(buf)));
    fprintf(fp, "ether_type=%02X", ntohs(eh->ether_type));
    switch (ntohs(eh->ether_type))
    {
    case ETH_P_IP:
        fprintf(fp, "(IP)\n");
        break;
    case ETH_P_IPV6:
        fprintf(fp, "(IPv6)\n");
        break;
    case ETH_P_ARP:
        fprintf(fp, "(ARP)\n");
        break;
    default:
        fprintf(fp, "(unknown)\n");
        break;
    }

    return (0);
}

u_int16_t checksum(__u_char *data, int len)
{
    register u_int32_t sum;
    register u_int16_t *ptr;
    register int c;

    sum = 0;
    ptr = (u_int16_t *)data;

    for (c = len; c > 1; c -= 2)
    {
        sum += (*ptr);
        if (sum & 0x80000000)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        ptr++;
    }
    if (c == 1)
    {
        u_int16_t val;
        val = 0;
        memcpy(&val, ptr, sizeof(u_int8_t));
        sum += val;
    }

    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (~sum);
}

u_int16_t checksum2(__u_char *data1, int len1, __u_char *data2, int len2)
{
    register u_int32_t sum;
    register u_int16_t *ptr;
    register int c;

    sum = 0;
    ptr = (u_int16_t *)data1;
    for (c = len1; c > 1; c -= 2)
    {
        sum += (*ptr);
        if (sum & 0x80000000)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        ptr++;
    }
    if (c == 1)
    {
        u_int16_t val;
        val = ((*ptr) << 8) + (*data2);
        sum += val;
        if (sum & 0x80000000)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        ptr = (u_int16_t *)(data2 + 1);
        len2--;
    }
    else
    {
        ptr = (u_int16_t *)data2;
    }
    for (c = len2; c > 1; c -= 2)
    {
        sum += (*ptr);
        if (sum & 0x80000000)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        ptr++;
    }
    if (c == 1)
    {
        u_int16_t val;
        val = 0;
        memcpy(&val, ptr, sizeof(u_int8_t));
        sum += val;
    }

    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (~sum);
}

int checkIPchecksum(struct iphdr *iphdr, __u_char *option, int optionLen)
{
    struct iphdr iptmp;
    unsigned short sum;

    memcpy(&iptmp, iphdr, sizeof(struct iphdr));

    if (optionLen == 0)
    {
        sum = checksum((__u_char *)&iptmp, sizeof(struct iphdr));
        if (sum == 0 || sum == 0xFFFF)
        {
            return (1);
        }
        else
        {
            return (0);
        }
    }
    else
    {
        sum = checksum2((__u_char *)&iptmp, sizeof(struct iphdr), option, optionLen);
        if (sum == 0 || sum == 0xFFFF)
        {
            return (1);
        }
        else
        {
            return (0);
        }
    }
}

typedef struct
{
    struct ether_header eh;
    struct ether_arp arp;
} PACKET_ARP;

// ARPリクエストを構築し、指定されたソケットを介してネットワークに送信。
int SendArpRequestB(int Soc, in_addr_t target_ip, __u_char target_mac[6], in_addr_t my_ip, __u_char my_mac[6])
{
    PACKET_ARP arp;
    int total;
    __u_char *p;
    __u_char buf[sizeof(struct ether_header) + sizeof(struct ether_arp)];
    union
    {
        unsigned long l;
        __u_char c[4];
    } lc;

    int i;

    arp.arp.arp_hrd = htons(ARPHRD_ETHER); // ハードウェアアドレスのフォーマット
    arp.arp.arp_pro = htons(ETHERTYPE_IP); // プロトコルの種類
    arp.arp.arp_hln = 6;                   // MACアドレスは通常6バイト
    arp.arp.arp_pln = 4;                   // 。IPアドレスは4バイト
    arp.arp.arp_op = htons(ARPOP_REQUEST); // ARPオペレーションコード

    //
    for (i = 0; i < 6; i++)
    {
        // 送信元MACアドレス (arp_sha) に、自身のMACアドレス (my_mac) を設定
        arp.arp.arp_sha[i] = my_mac[i];
    }
    for (i = 0; i < 6; i++)
    {
        arp.arp.arp_tha[i] = 0;
    }

    lc.l = my_ip;
    for (i = 0; i < 4; i++)
    {
        arp.arp.arp_spa[i] = lc.c[i];
    }

    lc.l = target_ip;
    for (i = 0; i < 4; i++)
    {
        arp.arp.arp_tpa[i] = lc.c[i];
    }

    arp.eh.ether_dhost[0] = target_mac[0];
    arp.eh.ether_dhost[1] = target_mac[1];
    arp.eh.ether_dhost[2] = target_mac[2];
    arp.eh.ether_dhost[3] = target_mac[3];
    arp.eh.ether_dhost[4] = target_mac[4];
    arp.eh.ether_dhost[5] = target_mac[5];

    arp.eh.ether_shost[0] = my_mac[0];
    arp.eh.ether_shost[1] = my_mac[1];
    arp.eh.ether_shost[2] = my_mac[2];
    arp.eh.ether_shost[3] = my_mac[3];
    arp.eh.ether_shost[4] = my_mac[4];
    arp.eh.ether_shost[5] = my_mac[5];

    arp.eh.ether_type = htons(ETHERTYPE_ARP);

    memset(buf, 0, sizeof(buf));
    p = buf;
    memcpy(p, &arp.eh, sizeof(struct ether_header));
    p += sizeof(struct ether_header);
    memcpy(p, &arp.arp, sizeof(struct ether_arp));
    p += sizeof(struct ether_arp);
    total = p - buf;

    write(Soc, buf, total);

    return (0);
}
