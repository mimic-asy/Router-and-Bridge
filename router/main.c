#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <pthread.h>
#include "netutil.h"
#include "base.h"
#include "ip2mac.h"
#include "sendBuf.h"

// ディスクリプタの構造体
typedef struct
{
    char *Device1;    // 送信元デバイス
    char *Device2;    // 送信先デバイス
    int DebugOut;     // debag Option
    char *NextRouter; // 送信先ルータアドレス
} PARAM;
PARAM Param = {"eth1", "eth2", 0, "192.168.0.254"};

struct in_addr NextRouter; // 上位ルータアドレス

DEVICE Device[2]; // 2つのネットワークデバイスのディスクリプタを保持する

int EndFlag = 0; // 終了フラグ

int DebugPrintf(char *fmt, ...)
{
    // 可変長リストで指定された引数を出力
    if (Param.DebugOut)
    {
        va_list args;

        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);
    }

    return (0);
}

int DebugPerror(char *msg)
{
	if(Param.DebugOut){
		fprintf(stderr,"%s : %s\n",msg,strerror(errno));
	}

	return(0);
}

int SendIcmpTimeExceeded(int deviceNo, struct ether_header *eh, struct iphdr *iphdr, u_char *data, int size)
{
    struct ether_header reh;
    struct iphdr rih;
    struct icmp icmp;
    __u_char *ipptr;
    __u_char *ptr, buf[1500];
    int len;

    // イーサヘッダのdhost/shostに引数イーサヘッダのdhost/shostをコピー
    memcpy(reh.ether_dhost, eh->ether_shost, 6);
    memcpy(reh.ether_shost, Device[deviceNo].hwaddr, 6);
    reh.ether_type = htons(ETHERTYPE_IP); // データタイプをIPアドレスに指定

    rih.version = 4;                               // Ipv4
    rih.ihl = 20 / 4;                              // headerの長さ（32bit)
    rih.tos = 0;                                   // サービスの種類　通常は0
    rih.tot_len = htons(sizeof(struct icmp) + 64); // データのサイズ（icmpのサイズ+63bit）
    rih.id = 0;                                    // 識別子
    rih.frag_off = 0;                              // offset 通常は０
    rih.ttl = 64;                                  // time to live
    rih.protocol = IPPROTO_ICMP;                   // ICmp set
    rih.check = 0;                                 // checksum
    rih.saddr = Device[deviceNo].addr.s_addr;      // 送信元IP
    rih.daddr = iphdr->saddr;                      // 宛先IP（前のIPヘッダから取得）

    rih.check = checksum((__u_char *)&rih, sizeof(struct iphdr)); // sumcheckをする

    icmp.icmp_type = ICMP_TIME_EXCEEDED;
    icmp.icmp_code = ICMP_TIMXCEED_INTRANS;
    icmp.icmp_cksum = 0;
    icmp.icmp_void = 0;

    ipptr = data + sizeof(struct ether_header);
    icmp.icmp_cksum = checksum2((__u_char *)&icmp, 8, ipptr, 64);

    ptr = buf;
    memcpy(ptr, &reh, sizeof(struct ether_header));
    ptr += sizeof(struct iphdr);
    memcpy(ptr, &icmp, 8);
    ptr += 8;

    memcpy(ptr, ipptr, 64);
    ptr += 64;
    len = ptr - buf;

    DebugPrintf("write:sendIcmpTimeExceeded:[%d]%dbytest\n", deviceNo, len);
    write(Device[deviceNo].soc, buf, len);
    return (0);
}

int AnalyzePacket(int deviceNo, __u_char *data, int size)
{
    __u_char *ptr;
    int lest;
    struct ether_header *eh;
    char buf[80];
    int tno;
    __u_char hwaddr[6];

    ptr = data;
    lest = size;

    // イーサヘッダ分データを取得できているか調べる
    if (lest < sizeof(struct ether_header))
    {
        DebugPrintf("[%d]:lest(%d)<sizeof(struct ether_header)\n", deviceNo, lest);
        return (-1);
    }
    // ポインタを勧め、取得したデータ部データサイズを縮小する
    eh = (struct ether_header *)ptr;
    ptr += sizeof(struct ether_header);

    lest = sizeof(struct ether_header);

    // deviceNo==dhostが一致するか調べる
    if (memcmp(&eh->ether_dhost, Device[deviceNo].hwaddr, 6) != 0)
    {
        DebugPrintf("[%d]:dhost not match %s\n", deviceNo, my_ether_ntoa_r((u_char *)&eh->ether_dhost, buf, sizeof(buf)));
        return (-1);
    }
    // データタイプがARP出会った場合、サイズが十分にあるか確認し、Ip2Macにデバイスナンバー、
    // ARPパケット内の送信元IPアドレス (arp_spa),送信元MACアドレス （arp->arp_sha）を収納する
    if (ntohs(eh->ether_type) == ETHERTYPE_ARP)
    {
        struct ether_arp *arp;

        if (lest < sizeof(struct ether_arp))
        {
            DebugPrintf("[%d]:lest(%d)<sizeof(struct ether_arp)\n", deviceNo, lest);
            return (-1);
        }
        arp = (struct ether_arp *)ptr;
        ptr += sizeof(struct ether_arp);
        lest -= sizeof(struct ether_arp);

        if (arp->arp_op == htons(ARPOP_REQUEST))
        {
            DebugPrintf("[%d]recv:ARP REQUEST:%dbytes\n", deviceNo, size);
            Ip2Mac(deviceNo, *(in_addr_t *)arp->arp_spa, arp->arp_sha);
        }
        if (arp->arp_op == htons(ARPOP_REPLY))
        {
            DebugPrintf("[%d]recv:ARP REPLY:%dbytes\n", deviceNo, size);
            Ip2Mac(deviceNo, *(in_addr_t *)arp->arp_spa, arp->arp_sha);
        }
    }
    // type=IPの場合はチェックサムを行いTTLを１減らす
    else if (ntohs(eh->ether_type) == ETHERTYPE_IP)
    {
        struct iphdr *iphdr;
        u_char option[1500];
        int optionLen;

        if (lest < sizeof(struct iphdr))
        {
            DebugPrintf("[%d]:lest(%d)<sizeof(struct iphdr)\n", deviceNo, lest);
            return (-1);
        }
        iphdr = (struct iphdr *)ptr;
        ptr += sizeof(struct iphdr);
        lest -= sizeof(struct iphdr);

        optionLen = iphdr->ihl * 4 - sizeof(struct iphdr);
        if (optionLen > 0)
        {
            if (optionLen >= 1500)
            {
                DebugPrintf("[%d]:IP optionLen(%d):too big\n", deviceNo, optionLen);
                return (-1);
            }
            memcpy(option, ptr, optionLen);
            ptr += optionLen;
            lest -= optionLen;
        }

        if (checkIPchecksum(iphdr, option, optionLen) == 0)
        {
            DebugPrintf("[%d]:bad ip checksum\n", deviceNo);
            fprintf(stderr, "IP checksum error\n");
            return (-1);
        }

        if (iphdr->ttl - 1 == 0)
        {
            DebugPrintf("[%d]:iphdr->ttl==0 error\n", deviceNo);
            SendIcmpTimeExceeded(deviceNo, eh, iphdr, data, size);
            return (-1);
        }

        // ここまでは理解
        tno = (!deviceNo);

        // iphdr->daddr が目的地のネットワークセグメントに属しているかどうかを確認します。
        // これは、送信先IP アドレスが Device[tno].subnet と Device[tno].netmask によって指定されるネットワークセグメントに属しているかどうかを確認しています。
        if ((iphdr->daddr & Device[tno].netmask.s_addr) == Device[tno].subnet.s_addr)
        {
            // 属していた場合
            IP2MAC *ip2mac;

            // IP アドレス (iphdr->daddr) および送信先のネットワークセグメントへの情報を表示
            DebugPrintf("[%d]:%s to TargetSegment\n", deviceNo, in_addr_t2str(iphdr->daddr, buf, sizeof(buf)));

            // 送信先 IP アドレスが、デバイスの自身の IP アドレス (Device[tno].addr.s_addr) と一致しているかどうかを確認します。
            if (iphdr->daddr == Device[tno].addr.s_addr)
            {
                // 送信先 IP アドレスが自身の IP アドレスと一致している場合、デバッグ情報を表示して（DebugPrintf）
                // return (1) で処理を終了します。これは、送信先が自身である場合に特定の処理（ここでは return (1)）を行うための分岐です
                DebugPrintf("[%d]:recv:myaddr\n", deviceNo);
                return (1);
            }

            // FLAG_NG(エラー)かip2mac->sd.dno != 0（送信中）である場合にエラー処理を行う
            ip2mac = Ip2Mac(tno, iphdr->daddr, NULL);
            if (ip2mac->flag == FLAG_NG || ip2mac->sd.dno != 0)
            {
                DebugPrintf("[%d]:Ip2Mac:error or sending\n", deviceNo);
                AppendSendData(ip2mac, 1, iphdr->daddr, data, size);
                return (-1);
            }
            else
            {
                // エラーが発生しなかった場合、ip2mac->hwaddr から MAC アドレスを取得し、それを hwaddr にコピーします。
                memcpy(hwaddr, ip2mac->hwaddr, 6);
            }
        }
        else
        {
            // 目的地と現在のアドレスが一致していなかった場合
            IP2MAC *ip2mac;

            DebugPrintf("[%d]:%s to NextRouter\n", deviceNo, in_addr_t2str(iphdr->daddr, buf, sizeof(buf)));
            // 次のルータのアドレスに書き変える
            ip2mac = Ip2Mac(tno, NextRouter.s_addr, NULL);
            if (ip2mac->flag == FLAG_NG || ip2mac->sd.dno != 0)
            {
                // エラーの処理
                DebugPrintf("[%d]:Ip2Mac:error or sending\n", deviceNo);
                AppendSendData(ip2mac, 1, NextRouter.s_addr, data, size);
                return (-1);
            }
            else
            {
                // write hsaddr to MAC addres
                memcpy(hwaddr, ip2mac->hwaddr, 6);
            }
        }

        // write ether_header to MAC add and now device add
        memcpy(eh->ether_dhost, hwaddr, 6);
        memcpy(eh->ether_shost, Device[tno].hwaddr, 6);
        // ttl -1
        iphdr->ttl--;
        // sumcheck reset
        iphdr->check = 0;
        // sumcheck;
        iphdr->check = checksum2((u_char *)iphdr, sizeof(struct iphdr), option, optionLen);

        write(Device[tno].soc, data, size);
    }

    return (0);
}

int Router()
{
    // network intarfaces descripta set by pollfd
    struct pollfd targets[2];
    int nready, i, size;
    u_char buf[2048];

    // target deviceにイベントフラグを追加
    targets[0].fd = Device[0].soc;
    targets[0].events = POLLIN | POLLERR;
    targets[1].fd = Device[1].soc;
    targets[1].events = POLLIN | POLLERR;

    while (EndFlag == 0)
    {
        // pollのイベントの回数を数える
        switch (nready = poll(targets, 2, 100))
        {
        //-1回（エラーの場合）
        case -1:
            if (errno != EINTR)
            {
                DebugPerror("poll");
            }
            break;
        case 0:
            // 0回
            break;
        default:
            // ターゲットのふらぐを見て出力する
            for (i = 0; i < 2; i++)
            {
                if (targets[i].revents & (POLLIN | POLLERR))
                {
                    if ((size = read(Device[i].soc, buf, sizeof(buf))) <= 0)
                    {
                        // 読み込めていなかった場合はエラーを出力
                        DebugPerror("read");
                    }
                    else
                    {
                        // APIかIPか判別し、アドレスの確認を行って送信先を決め、送信する。
                        AnalyzePacket(i, buf, size);
                    }
                }
            }
            break;
        }
    }

    return (0);
}

// カーネルのIPフォワードを止める（カーネルが勝手にインターフェイス間のパケットを転送しないようにするため）
int DisableIpForward()
{
    FILE *fp;

    if ((fp = fopen("/proc/sys/net/ipv4/ip_forward", "w")) == NULL)
    {
        DebugPrintf("cannot write /proc/sys/net/ipv4/ip_forward\n");
        return (-1);
    }
    fputs("0", fp);
    fclose(fp);

    return (0);
}

// 送信街データをバックグラウンドで並列処理させる
void *BufThread(void *arg)
{
    BufferSend();

    return (NULL);
}

void EndSignal(int sig)
{
    EndFlag = 1;
}

pthread_t BufTid;

int main(int argc, char *argv[], char *envp[])
{
    char buf[80];
    pthread_attr_t attr;
    int status;

    inet_aton(Param.NextRouter, &NextRouter);                                      // 上位ルータのIPアドレスを文字列からざstruct in_addr型に変換する
    DebugPrintf("NextRouter=%s\n", my_inet_ntoa_r(&NextRouter, buf, sizeof(buf))); // 出力

    // DeviceのMac add, IP addr, subnet,maskがエラーであった場合
    if (GetDeviceInfo(Param.Device1, Device[0].hwaddr, &Device[0].addr, &Device[0].subnet, &Device[0].netmask) == -1)
    {
        DebugPrintf("GetDeviceInfo:error:%s\n", Param.Device1);
        return (-1);
    }
    if ((Device[0].soc = InitRawSocket(Param.Device1, 0, 0)) == -1)
    {
        // インターフェイスエラー
        DebugPrintf("InitRawSocket:error:%s\n", Param.Device1);
        return (-1);
    }

    // 通信がうまく行った場合アドレスやサブネットが出力される
    DebugPrintf("%s OK\n", Param.Device1);
    DebugPrintf("addr=%s\n", my_inet_ntoa_r(&Device[0].addr, buf, sizeof(buf)));
    DebugPrintf("subnet=%s\n", my_inet_ntoa_r(&Device[0].subnet, buf, sizeof(buf)));
    DebugPrintf("netmask=%s\n", my_inet_ntoa_r(&Device[0].netmask, buf, sizeof(buf)));

    if (GetDeviceInfo(Param.Device2, Device[1].hwaddr, &Device[1].addr, &Device[1].subnet, &Device[1].netmask) == -1)
    {
        DebugPrintf("GetDeviceInfo:error:%s\n", Param.Device2);
        return (-1);
    }
    if ((Device[1].soc = InitRawSocket(Param.Device2, 0, 0)) == -1)
    {
        DebugPrintf("InitRawSocket:error:%s\n", Param.Device1);
        return (-1);
    }
    DebugPrintf("%s OK\n", Param.Device2);
    DebugPrintf("addr=%s\n", my_inet_ntoa_r(&Device[1].addr, buf, sizeof(buf)));
    DebugPrintf("subnet=%s\n", my_inet_ntoa_r(&Device[1].subnet, buf, sizeof(buf)));
    DebugPrintf("netmask=%s\n", my_inet_ntoa_r(&Device[1].netmask, buf, sizeof(buf)));

    // カーネルを止める
    DisableIpForward();

    // 処理街バッファ専用のスレッドの起動
    pthread_attr_init(&attr);
    if ((status = pthread_create(&BufTid, &attr, BufThread, NULL)) != 0)
    {
        DebugPrintf("pthread_create:%s\n", strerror(status));
    }
    // signalをEndsignalに定義してパイプ切断やTTYよみかきのシグナルを無視するようにする
    signal(SIGINT, EndSignal);
    signal(SIGTERM, EndSignal);
    signal(SIGQUIT, EndSignal);

    signal(SIGPIPE, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    signal(SIGTTOU, SIG_IGN);

    DebugPrintf("router start\n");
    Router(); // ルータを呼び出して処理を開始する
    DebugPrintf("router end\n");
    // 処理街バッファのスレッドを終了
    pthread_join(BufTid, NULL);

    close(Device[0].soc);
    close(Device[1].soc);

    return (0);
}
