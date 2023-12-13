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
#include "netutil.h"

// 動作パラメータを保持するPARAM
typedef struct
{
    char *Device1;
    char *Device2;
    int DebugOut;
} PARAM;

PARAM Param = {"eth0", "eth3", 0};

// ２つのネットワークインターフェイスのソケットディスクリプタを保持する
typedef struct
{
    int soc;
} DEVICE;

// Device = [DEVICE[0],DEVICE[1]];
DEVICE Device[2];

// 終了シグナルの状態用グローバル変数
int EndFlag = 0;

void ParseCommandLine(int argc, char *argv[], PARAM *param)
{
    int opt;
    // getoptを使用してコマンドライン引数を解析する
    while ((opt = getopt(argc, argv, "d")) != -1)
    {
        switch (opt)
        {
        case 'd':
            //-dオプションが指定された場合、 debugOutを有効にする
            param->DebugOut = 1;
            break;
        default:
            fprintf(stderr, "Usage: %s [-d] [device1] [device2]\n", argv[0]);
            break;
        }
    }

    if (argc > 3)
    {
        param->Device1 = argv[2];
        param->Device2 = argv[3];
    }
    else if (argc < 3)
    {
        fprintf(stderr, "デバイスを２つ渡してください\n");
        _exit(1);
    }
    else
    {
        param->Device1 = argv[1];
        param->Device2 = argv[2];
    }
}

int DebugPrintf(char *fmt, ...)
{

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
    if (Param.DebugOut)
    {
        // strerror(errno): errno は、最後に発生したエラー番号を表す整数です
        // strerror 関数は、指定されたエラー番号に対応するエラーメッセージを返します。
        fprintf(stderr, "%s : %s\n", msg, strerror(errno));
    }

    return (0);
}

// イーサヘッダの解析関数
int AnalyzePacket(int deviceNo, __u_char *data, int size)
{
    __u_char *ptr;
    int lest;
    struct ether_header *eh;

    ptr = data;
    lest = size;

    // サイズが足りていない場合はエラーを出して終了
    if (lest < sizeof(struct ether_header))
    {
        DebugPrintf("[%d]:lest(%d)<sizeof(struct ether_header)\n", deviceNo, lest);
        return (-1);
    }
    // イーサネットヘッダのポインタを取得し、ポインタを進めてパケットデータの残りサイズを更新します。
    eh = (struct ether_header *)ptr;
    ptr += sizeof(struct ether_header);
    lest -= sizeof(struct ether_header);

    // デバッグをするか否か
    DebugPrintf("[%d]", deviceNo);

    // デバッグを行う場合はイーサヘッダを出力
    if (Param.DebugOut)
    {
        PrintEtherHeader(eh, stderr);
    }

    return (0);
}

// ブリッジの処理、受信したインターフェイスから違うインターフェイスに書き出す　
int Bridge()
{
    struct pollfd targets[2];
    int nready, i, size;
    __u_char buf[2048];

    targets[0].fd = Device[0].soc;
    targets[0].events = POLLIN | POLLERR;
    targets[1].fd = Device[1].soc;
    targets[1].events = POLLIN | POLLERR;

    while (EndFlag == 0)
    {
        switch (nready = poll(targets, 2, 100))
        {
        case -1:
            if (errno != EINTR)
            {
                perror("poll");
            }
            break;
        case 0:
            break;
        default:
            for (i = 0; i < 2; i++)
            {
                if (targets[i].revents & (POLLIN | POLLERR))
                {
                    if ((size = read(Device[i].soc, buf, sizeof(buf))) <= 0)
                    {
                        perror("read");
                    }
                    else
                    {
                        if (AnalyzePacket(i, buf, size) != -1)
                        {
                            if ((size = write(Device[(!i)].soc, buf, size)) <= 0)
                            {
                                perror("write");
                            }
                        }
                    }
                }
            }
            break;
        }
    }

    return (0);
}

// カーネルのIPフォワードを止める
// proc/sys/net/ipv4/ip_forwardが1になっているとカーネルがパケットを転送するので０にして止める
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

// bridgeのループを抜ける
void EndSignal(int sig)
{
    EndFlag = 1;
}

int main(int argc, char *argv[], char *envp[])
{
    // 引数からデバイスを設定
    ParseCommandLine(argc, argv, &Param);


    // ディスクリプタ構築エラー
    if ((Device[0].soc = InitRawSocket(Param.Device1, 1, 0)) == -1)
    {
        DebugPrintf("InitRawSocket:error:%s\n", Param.Device1);
        return (-1);
    }
    // debag Device1　接続確認

    DebugPrintf("%s OK\n", Param.Device1);

    // ディスクリプタ構築エラー
    if ((Device[1].soc = InitRawSocket(Param.Device2, 1, 0)) == -1)
    {
        DebugPrintf("InitRawSocket:error:%s\n", Param.Device1);
        return (-1);
    }
    // debag Device2　接続確認
    DebugPrintf("%s OK\n", Param.Device2);

    DisableIpForward();

    signal(SIGINT, EndSignal);
    signal(SIGTERM, EndSignal);
    signal(SIGQUIT, EndSignal);

    signal(SIGPIPE, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    signal(SIGTTOU, SIG_IGN);

    DebugPrintf("bridge start\n");
    Bridge();
    DebugPrintf("bridge end\n");

    close(Device[0].soc);
    close(Device[1].soc);

    return (0);
}