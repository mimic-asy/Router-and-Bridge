// main() main function
// initRawSocket() raw socket はユーザーが自身でプロトコルの制御が可能。ネットワークパケットのヘッダ情報にアクセスできる。第2層を扱える。
// PrintEtherHeader() イーサ header を表示する。
// my_ether_ntoa_r() MACアドレスの文字列化

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
// 以下のファイルがネットワークインターフェイス及びデータリンク層を扱う
#include <linux/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>

// デバイスのディスクリプタを作成し、それをもとにパケットの設定を行う

//[device]->[デバイス名] [promiscFlag]->[自分宛でないパケットを受信するモードのフラグ] [ipOnly]->[IPパケットのみを対象にするフラグ]
int InitRawSocket(char *device, int promiscFlag, int ipOnly)
{
    struct ifreq ifreq;
    struct sockaddr_ll sa;
    int soc;

    // inOnlyが指定の値であった場合、IPアドレスのみを扱うデータリンク層のディスクリプタを作成する。
    // 　それ以外の場合は全てのパケットを扱うデータリンク層のディスクリプタを作成する
    if (ipOnly)
    {
        // プロトコルファミリーの指定->[PF_PACKET]（データリンク層）, 通信方式->[SOCK_RAW]（データリンク層)
        // プロトコルの指定->[ETH_P_IP](IPパケットのみ)
        if ((soc = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0)
        {
            perror("socket");
            return (-1);
            // socが0以下の場合エラーを出力する。
        }
    }
    else
    {
        // プロトコルの指定->[ETH_P_ALL](全パケット)
        if ((soc = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
        {
            perror("socket");
            return (-1);
            // socが0以下の場合エラーを出力する。
        }
    }

    // struct ifreqのメモリ領域をmemsetを用いて0で埋める
    // 第一引数->[先頭のメモリ],  第2引数->[埋める数], 第3引数->[埋めるメモリのサイズ]
    memset(&ifreq, 0, sizeof(struct ifreq));
    // strncpyを用いてifreq.itr_nameのサイズに対応させたdeviceを代入する。 　
    // 第1引数->[コピー先], 第2引数->[コピー元], 第3引数->[文字列の最大長](-1はnull終端文字を考慮)
    strncpy(ifreq.ifr_name, device, sizeof(ifreq.ifr_name) - 1);

    // ioctlを用いてインターフェイスのインデックスを取得する
    // 第１引数->[対象のディスクリプタ],第２引数->[対象のインターフェイスインデックスを取得するコマンド].第３引数->[取得したインデックスを格納する場所]
    if (ioctl(soc, SIOCGIFINDEX, &ifreq) < 0)
    {
        perror("ioctl");
        close(soc);
        return (-1);
    }
    // アドレスファミリ（通信形式）を指定する（PF_PACKET->Lunixのrawソケットを使用する際の形式）
    sa.sll_family = PF_PACKET;
    // ipOnlyの場合、プロトコルの指定をIPのみにする
    if (ipOnly)
    {
        sa.sll_protocol = htons(ETH_P_IP);
    }
    else
    {
        sa.sll_protocol = htons(ETH_P_ALL);
    }
    // ifreq.ifr_ifindexのインターフェイスインデックスを指定する
    sa.sll_ifindex = ifreq.ifr_ifindex;

    // bindを用いてソケットディスクリプタ（soc）にアドレスを紐付ける
    // 　struct sockaddはソケットアドレスの構造体、saを参照しソケットアドレス型に方を変換する
    // 　sizeof(sa)=アドレス構造体のサイズ
    if (bind(soc, (struct sockadd *)&sa, sizeof(sa)) < 0)
    {
        perror("bind");
        close(soc);
        return (-1);
    }

    if (promiscFlag)
    {
        // socからflagを取得し、ifreq.ifr_flagsに代入する
        if (ioctl(soc, SIOCGIFFLAGS, &ifreq) < 0)
        {
            perror("ioctl");
            close(soc);
            return (-1);
        }
        //| ビット演算子は、元の ifr_flags に IFF_PROMISC フラグを追加してpromiscastモードにする
        ifreq.ifr_flags = ifreq.ifr_flags | IFF_PROMISC;
        if (ioctl(soc, SIOCSIFFLAGS, &ifreq) < 0)
        {
            perror("bind");
            close(soc);
            return (-1);
        }
    }
    return (soc);
}

// MACアドレスを文字列にする
char *my_ether_ntoa_r(__u_char *hwaddr, char *buf, socklen_t size)
{
    snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x",
             hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);

    return (buf);
}

// イーサネットヘッダーをデバッグする関数、第一引数にイーサパケットのアドレス、第２引数に出力先ファイルポインタ
int PrintEtherHeader(struct ether_header *eh, FILE *fp)
{
    char buf[80];
    fprintf(fp, "ether_header -----------------------------------'n");
    fpeintf(fp, "ether_dhost=%s 'n", my_ether_ntoa_r(eh->ether_dhost, buf, sizeof(buf)));
    fpeintf(fp, "ether_shost=%s 'n", my_ether_ntoa_r(eh->ether_shost, buf, sizeof(buf)));
    fpeintf(fp, "ether_type=%02X", ntohs(eh->ether_type));
    switch (ntohs(eh->ether_type))
    {
    case ETH_P_IP:
        fprintf(fp, "(IP)'n");
        break;
    case ETH_P_IPV6:
        fprintf(fp, "(IPv6)'n");
        break;

    case ETH_P_ARP:
        fprintf(fp, "(ARP)'n");
        break;

    default:
        fprintf(fp, "(unknow)'n");
        break;
    }
    return (0);
}

int main(int argc, char *argv[], char *envp[])
{
    int soc, size;
    __u_char buf[2048];
    // 起動時引数にネットワークインターフェイス名を指定
    if (argc <= 1)
    {
        fprintf(stderr, "ltest device-name'n");
        return (1);
    }
    // データリンク層を扱うディスクリプタを取得する
    if (soc = InitRawSocket(argv[1], 0, 0))
    {
        fprintf(stderr, "InitRawSocket:error:%s 'n", argv[1]);
        return (-1);
    }

    // readでデータを受信。イーサヘッダサイズ以上に受信できた場合にPrintEtherHeaderでデバッグ表示する処理を繰り返す
    while (1)
    {
        if ((size = read(soc, buf, sizeof(buf))) <= 0)
        {
            perror("read");
        }
        else
        {
            if (size >= sizeof(struct ether_header))
            {
                PrintEtherHeader((struct ether_header *)buf, stdout);
            }
            else
            {
                fprintf(stderr, "read_size(%d) < %d 'n", size, sizeof(struct ether_header));
            }
        }
    }
    close(soc);

    return (0);
}