//ネットワーク関連の関数プロトタイプ宣言を記述
char *my_ether_ntoa_r(__u_char *hwaddr,char *buf,socklen_t size);
int PrintEtherHeader(struct ether_header *eh,FILE *fp);
int InitRawSocket(char *device,int promiscFlag,int ipOnly);
