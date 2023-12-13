typedef struct
{
    int soc; //ソケット
    u_char hwaddr[6];//アドレス
    struct in_addr addr, subnet, netmask; //
} DEVICE;

#define FLAG_FREE 0
#define FLAG_OK 1
#define FLAG_NG -1

//双方向データの格納をする
typedef struct  _data_buf_{
        struct _data_buf_       *next;
        struct _data_buf_       *before;
        time_t  t;
        int     size;
        unsigned char   *data;
}DATA_BUF;

//送信街データを保持する
typedef struct  {
        DATA_BUF        *top;
        DATA_BUF        *bottom;
        unsigned long   dno;
        unsigned long   inBucketSize;
        pthread_mutex_t mutex;
}SEND_DATA;

typedef struct  {
        int     flag; // 使用されているかどうかのフラグ
        int     deviceNo; //デバイスの番号
        in_addr_t       addr; //IP アドレス
        unsigned char   hwaddr[6]; //MACアドレス
        time_t  lastTime; //最後に更新された時間
        SEND_DATA       sd;// 送信データ
}IP2MAC;
//IPアドレスとMACアドレスの関連付け
