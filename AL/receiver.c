#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/time.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UDP_DATA_MAXSIZE 65527
#define IPV4_DATA_MAXSIZE 1440
#define DATALINK_DATA_MAXSIZE 1500

#define BUFLEN 1518
#define PORT 8200
#define LISTNUM 200

void PrintBinary(const int argc, int bit_begin, int bit_end)
{
    for (int i = bit_begin; i >= bit_end; i--) //高位到低位输出
    {
        int a;
        a = 0x01 & argc >> i;
        printf("%d", a);
    }
}
int GetBinary(const unsigned int argc, int bit_begin, int bit_end)
{
    unsigned int a;
    a = argc << (32 - bit_begin - 1);
    a = a >> (32 - bit_begin - 1 + bit_end);
    return a;
}



////////////////////////////传输层////////////////////////////////////
struct UDP_Packet
{
    // 16 bit
    unsigned short UDP_SRC_PORT;
    // 16 bit
    unsigned short UDP_DES_PORT;
    // 16 Byte
    unsigned short UDP_LEN;
    // 16 Byte
    unsigned short UDP_CHECK_SUM;
    // (26-8)~(1480-8) Byte
    unsigned char UDP_Data[1472];
};

unsigned char UDP_PACKET[UDP_DATA_MAXSIZE + 8];
int UDP_LEN = 0;

void transfer_layer_receriver(unsigned char *UDP_DATA, int len)
{
    printf("UDP Combined Length: %d\n", UDP_LEN);
    //UDP_SRC_PORT
    unsigned short UDP_SRC_PORT;
    memcpy(&UDP_SRC_PORT, &UDP_DATA[0], 2);
    printf("UDP_SRC_PORT: ");
    PrintBinary((int)UDP_SRC_PORT, 15, 0);
    printf("\n");

    //UDP_DES_PORT
    unsigned short UDP_DES_PORT;
    memcpy(&UDP_DES_PORT, &UDP_DATA[2], 2);
    printf("UDP_DES_PORT: ");
    PrintBinary((int)UDP_DES_PORT, 15, 0);
    printf("\n");

    //UDP_LEN
    unsigned short UDP_LEN;
    memcpy(&UDP_LEN, &UDP_DATA[4], 2);
    printf("UDP_LEN: ");
    PrintBinary((int)UDP_LEN, 15, 0);
    printf("\n");

    //UDP_CHECK_SUM
    unsigned short UDP_CHECK_SUM;
    memcpy(&UDP_CHECK_SUM, &UDP_DATA[6], 2);
    printf("UDP_CHECK_SUM: ");
    PrintBinary((int)UDP_CHECK_SUM, 15, 0);
    printf("\n");

    //UDP_Data
    int Data_Len = (int)UDP_LEN - 8;
    unsigned char UDP_Data[65535];
    memcpy(&UDP_Data, &UDP_DATA[8], Data_Len);

    //暂时不打印UDP_Data
    // printf("UDP_Data: ");
    // for (int i = 0; i < Data_Len; ++i)
    // {
    //     PrintBinary((int)UDP_Data[i], 7, 0); // 16,17,18,19 byte
    // }
    // printf("\n");
    printf("UDP_Data: ");
    for (int i = 0; i < Data_Len; ++i)
    {
        printf("%c", UDP_Data[i]);
    }
    printf("\n");
}
////////////////////////////传输层////////////////////////////////


/////////////////////////网络层///////////////////////////////////
#define DATA_MAXSIZE 1440 //字节
#define DATA_MI NSIZE 26   //字节
struct IP_Packet
{
    // 4 bit
    unsigned int IPv4_Version : 4;
    // 4 bit
    unsigned int IPv4_IHL : 4;
    // 8 bit
    unsigned int IPv4_TOS : 8;

    // 16 bit
    unsigned int IPv4_TotalLength : 16;

    // 16 bit
    unsigned int IPv4_Identification : 16;

    // 1 bit
    unsigned int IPv4_NoFunc : 1;
    // 1 bit
    unsigned int IPv4_DF : 1;
    // 1 bit
    unsigned int IPv4_MF : 1;
    // 13 bit
    unsigned int IPv4_FragmentOffset : 13;

    // 8 bit
    unsigned int IPv4_TimeTolive : 8;
    // 8 bit
    unsigned int IPv4_Protocol : 8;

    // 16 bit
    unsigned int IPv4_HeaderCheckSum : 16;

    // 32 bit
    unsigned int IPv4_SourceAddr : 32;

    // 32 bit
    unsigned int IPv4_DesAddr : 32;

    // 40 Byte
    unsigned char IPv4_Option[40];

    // 26~1480 Byte
    unsigned char IPv4_Data[DATA_MAXSIZE];
};

// unsigned short extendl_16bit(unsigned int bit_content, int bit_offset)
// {
//     bit_content = bit_content << bit_offset;
//     unsigned short res = 0b0; //16 bit
//     res += bit_content;
//     return res;
// }

// unsigned short extendr_16bit(unsigned int bit_content, int bit_offset)
// {
//     bit_content = bit_content >> bit_offset;
//     unsigned short res = 0b0; //16 bit
//     res += bit_content;
//     return res;
// }

// unsigned short extendl_8bit(unsigned int bit_content, int bit_offset)
// {
//     bit_content = bit_content << bit_offset;
//     unsigned char res = 0b0; //16 bit
//     res += bit_content;
//     return res;
// }

// unsigned short extendr_8bit(unsigned int bit_content, int bit_offset)
// {
//     bit_content = bit_content >> bit_offset;
//     unsigned char res = 0b0; //16 bit
//     res += bit_content;
//     return res;
// }

void network_layer_receriver(unsigned char *payload, int len)
{
    //IPv4_Version
    unsigned char IPv4_Version;
    memcpy(&IPv4_Version, &payload[0], 1);
    printf("IPv4_Version: ");
    PrintBinary((int)IPv4_Version, 7, 4);
    printf("\n");

    //IPv4_IHL
    unsigned char IPv4_IHL;
    memcpy(&IPv4_IHL, &payload[0], 1);
    printf("IPv4_IHL: ");
    //PrintBinary((int)IPv4_Version,3,0); // 0 byte
    PrintBinary((int)IPv4_Version, 7, 0); // 0 byte
    printf("\n");
    IPv4_IHL = IPv4_IHL << 4;
    IPv4_IHL = IPv4_IHL >> 4;

    //IPv4_TOS
    unsigned char IPv4_TOS;
    memcpy(&IPv4_TOS, &payload[1], 1);
    printf("IPv4_TOS: ");
    PrintBinary((int)IPv4_TOS, 7, 0); // 1 byte
    printf("\n");

    //IPv4_TotalLength
    unsigned short IPv4_TotalLength;
    memcpy(&IPv4_TotalLength, &payload[2], 2);
    printf("IPv4_TotalLength: ");
    PrintBinary((int)IPv4_TotalLength, 15, 0); // 2,3 byte
    printf("\n");

    //IPv4_Identification
    unsigned short IPv4_Identification;
    memcpy(&IPv4_Identification, &payload[4], 2);
    printf("IPv4_Identification: ");
    PrintBinary((int)IPv4_Identification, 15, 0); // 4,5 byte
    printf("\n");

    //IPv4_NoFunc
    unsigned short IPv4_NoFunc;
    memcpy(&IPv4_NoFunc, &payload[6], 2);
    printf("IPv4_NoFunc: ");
    PrintBinary((int)IPv4_NoFunc, 15, 15); // 6,7 byte
    printf("\n");

    //IPv4_DF
    unsigned short IPv4_DF;
    memcpy(&IPv4_DF, &payload[6], 2);
    printf("IPv4_DF: ");
    PrintBinary((int)IPv4_DF, 14, 14); // 6,7 byte
    printf("\n");

    //IPv4_MF
    unsigned short IPv4_MF;
    memcpy(&IPv4_MF, &payload[6], 2);
    printf("IPv4_MF: ");
    PrintBinary((int)IPv4_MF, 13, 13); // 6,7 byte
    printf("\n");

    //IPv4_FragmentOffset
    unsigned short IPv4_FragmentOffset;
    memcpy(&IPv4_FragmentOffset, &payload[6], 2);
    printf("IPv4_FragmentOffset: ");
    PrintBinary((int)IPv4_FragmentOffset, 12, 0); // 6,7 byte
    printf("\n");

    //IPv4_TimeTolive
    unsigned char IPv4_TimeTolive;
    memcpy(&IPv4_TimeTolive, &payload[8], 1);
    printf("IPv4_TimeTolive: ");
    PrintBinary((int)IPv4_TimeTolive, 7, 0); // 8 byte
    printf("\n");

    //IPv4_Protocol
    unsigned char IPv4_Protocol;
    memcpy(&IPv4_Protocol, &payload[9], 1);
    printf("IPv4_Protocol: ");
    PrintBinary((int)IPv4_Protocol, 7, 0); // 9 byte
    printf("\n");

    //IPv4_HeaderCheckSum
    unsigned short IPv4_HeaderCheckSum;
    memcpy(&IPv4_HeaderCheckSum, &payload[10], 2);
    printf("IPv4_HeaderCheckSum: ");
    PrintBinary((int)IPv4_HeaderCheckSum, 15, 0); // 10,11 byte
    printf("\n");

    //IPv4_SourceAddr
    unsigned int IPv4_SourceAddr;
    memcpy(&IPv4_SourceAddr, &payload[12], 4);
    printf("IPv4_SourceAddr: ");
    PrintBinary((int)IPv4_SourceAddr, 31, 0); // 12,13,14,15 byte
    printf("\n");

    //IPv4_DesAddr
    unsigned int IPv4_DesAddr;
    memcpy(&IPv4_DesAddr, &payload[16], 4);
    printf("IPv4_DesAddr: ");
    PrintBinary((int)IPv4_DesAddr, 31, 0); // 16,17,18,19 byte
    printf("\n");

    //IPv4_Option
    int Option_Len = (int)IPv4_IHL * 4 - 20;
    unsigned char IPv4_Option[40]; //最多40个Byte
    memcpy(&IPv4_Option, &payload[20], Option_Len);
    printf("IPv4_Option: ");
    for (int i = 0; i < Option_Len; ++i)
    {
        PrintBinary((int)IPv4_Option[i], 7, 0); // 16,17,18,19 byte
    }
    printf("\n");

    //IPv4_Data
    int Data_Len = (int)IPv4_TotalLength - (int)IPv4_IHL - 5;
    unsigned char IPv4_Data[1500]; //最多40个Byte
    memcpy(&IPv4_Data, &payload[20 + Option_Len], Data_Len);

    //开始拼接
    unsigned short DF, MF, FragmentOffset;
    DF = GetBinary(IPv4_DF, 14, 14);// 决定能否被分片。=1允许分片；=0禁止分片
    MF = GetBinary(IPv4_MF, 13, 13);//用来告知目的主机该 IP数据报是否为原始数据报的最后一个片。=1还有；=0最后一个
    FragmentOffset = GetBinary(IPv4_FragmentOffset, 12, 0);//它指出较长的分组在分片后，某片在原分组中的相对位置
    printf("MF= %d\n", MF);
	////////////////////////////////////////////分别打印分片数据
	if (MF == 1)
    { //后面还有分片
        UDP_LEN += IPV4_DATA_MAXSIZE;
		printf("分片数据为：");
        for (int i = FragmentOffset * IPV4_DATA_MAXSIZE, l = 0; i < ((FragmentOffset + 1) * IPV4_DATA_MAXSIZE); i++, l++)
        {
            UDP_PACKET[i] = IPv4_Data[l];
            if (i >= 8 && FragmentOffset == 0 || FragmentOffset != 0)
			    printf("%c",UDP_PACKET[i]);
        }
		printf("\n");
    }
    else
    { //最后一个分片
        UDP_LEN += Data_Len;
		printf("最后一个分片数据为：");
        for (int i = FragmentOffset * IPV4_DATA_MAXSIZE, l = 0; i < (FragmentOffset * IPV4_DATA_MAXSIZE + Data_Len); i++, l++)
        {
            UDP_PACKET[i] = IPv4_Data[l];
			if ((i < (FragmentOffset * IPV4_DATA_MAXSIZE + Data_Len)-26) && (i >= 8 && FragmentOffset == 0 || FragmentOffset != 0))
				printf("%c",UDP_PACKET[i]);
        }
    }
    ////////////////////////////////////运输层传输
    printf("网络层解封装结束，打包UDPpacket->运输层\n");
    transfer_layer_receriver(UDP_PACKET, UDP_LEN);
    ////////////////////////////////////////////////汇总打印，后期注释掉
    // printf("\n");
    // printf("<============================================>\n");
    // printf("Sender说：");
    // for (int ii = 0; ii < (FragmentOffset * IPV4_DATA_MAXSIZE + Data_Len)-26; ii++)
    // {
    //     printf("%c", UDP_PACKET[ii]);
    // }
    // printf("\n");
    // UDP_LEN=0;	
}
////////////////////////网络层///////////////////////////////////

///////////////////////数据链路层////////////////////////////////
#define MAXSIZE 1500
#define MINSIZE 46

#define bool char
#define true 1
#define false 0

// SIZE:    6Bytes   6Bytes   2Bytes         46-1500Bytes   4Bytes
// MEANING: DA       SA       ProtocalType   PayLoad        FCS

// Mac地址
typedef unsigned char mac_addr[6];
mac_addr my_mac = {0x3D, 0xE1, 0x2D, 0x6F, 0xE9, 0x34};
unsigned char buffer[65536];

// 打印MAC地址
void show_mac_addr(unsigned char m[6])
{
    for (int i = 0; i < 6; i++)
    {
        printf("%02x", m[i]);
        if (i != 5)
            printf(":");
    }
}

void Print_Binary(const char argc)
{
    for (int i = 7; i >= 0; i--) //高位到低位输出
    {
        int a;
        a = 0x01 & argc >> i;
        printf("%d", a);
    }
}

// 打印有效荷载
void show_payload(unsigned char *pl, long int len)
{
    for (int i = 0; i < len; i++)
    {
        Print_Binary(pl[i]);
    }
}

// 打印协议的类型
void show_protocol(unsigned char m[2])
{
    for (int i = 1; i >= 0; i--)
    {
        printf("%02x", m[i]);
    }
}

// CRC校验
unsigned int crc32(unsigned char *data, int len)
{
    unsigned int crc = 0xFFFFFFFF;
    for (int i = 0; i < len; i++)
    {
        crc = crc ^ data[i];
        for (int j = 0; j < 8; j++)
        {
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
        }
    }
    return ~crc;
}

// 检验MAC地址是否相同
bool mac_same(unsigned char *dst_mac, unsigned char *my_mac, int mac_len)
{
    for (int i = 0; i < mac_len; i++)
    {
        if (dst_mac[i] != my_mac[i])
        {
            return false;
        }
    }
    return true;
}
//////////////////////////////////////////////////////////////////////////////////

int main()
{
    printf("欢迎您进入接收端\n");
    int sockfd, newfd;
    struct sockaddr_in s_addr, c_addr;
    char buf[BUFLEN];
    socklen_t len;
    unsigned int port, listnum;
    fd_set rfds;
    struct timeval tv;
    int retval, maxfd;

    // 建立socket
    if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1)
    {
        printf("创建SOCKET失败\n");
        perror("socket");
        exit(errno);
    }
    else
        printf("--------------------------------------------\n");
    printf("创建SOCKET成功\n");

    memset(&s_addr, 0, sizeof(s_addr));
    s_addr.sin_family = AF_INET;
    s_addr.sin_port = htons(PORT);
    s_addr.sin_addr.s_addr = htons(INADDR_ANY);

    // 地址和端口绑定到Socket上
    if ((bind(sockfd, (struct sockaddr *)&s_addr, sizeof(struct sockaddr))) == -1)
    {
        perror("bind");
        exit(errno);
    }
    else
    {
        printf("地址与端口绑定Socket成功(成功设置接收端的地址以及端口)\n");
        printf("***当前端的地址是：%s，端口是：%d***\n", inet_ntoa(s_addr.sin_addr), ntohs(s_addr.sin_port));
    }
    //侦听本地端口
    if (listen(sockfd, listnum) == -1)
    {
        perror("listen");
        exit(errno);
    }
    else
        printf("正在监听本地端口...\n");
    while (1)
    {
        printf("等待请求端接入...\n");
        len = sizeof(struct sockaddr);
        if ((newfd = accept(sockfd, (struct sockaddr *)&c_addr, &len)) == -1)
        {
            perror("accept");
            exit(errno);
        }
        else
        {
            printf("-------发送端建立连接的请求成功-------\n");
            printf("***发送端的地址是：%s，端口是：%d***\n", inet_ntoa(c_addr.sin_addr), ntohs(c_addr.sin_port));
            printf("您现在可与发送端进行通信...\n");
            printf("--------------------------------------------\n");
        }
        while (1)
        {
            FD_ZERO(&rfds);
            FD_SET(0, &rfds);
            maxfd = 0;
            FD_SET(newfd, &rfds);
            // 找出文件描述符集合中最大的文件描述符
            if (maxfd < newfd)
                maxfd = newfd;
            // 设置超时时间
            tv.tv_sec = 10;
            tv.tv_usec = 0;
            // 等待对方消息
            retval = select(maxfd + 1, &rfds, NULL, NULL, &tv);
            if (retval == -1)
            {
                printf("Select Error: exiting...\n");
                break;
            }
            else if (retval == 0)
            {
                continue;
            }
            else
            {
                /*用户输入信息了*/
                if (FD_ISSET(0, &rfds))
                {

                    /******发送消息*******/
                    memset(buf, 0, sizeof(buf));
                    /*fgets函数：从流中读取BUFLEN-1个字符*/
                    fgets(buf, BUFLEN, stdin);
                    /*打印发送的消息*/
                    // fputs(buf,stdout);
                    if (!strncasecmp(buf, "quit", 4))
                    {
                        printf("server 请求终止聊天!\n");
                        break;
                    }
                    len = send(newfd, buf, strlen(buf), 0);
                    if (len > 0)
                    {
                        printf("=======>消息发送成功：%s", buf);
                        printf("--------------------------------------------\n");
                    }
                    else
                    {
                        printf("=======>消息发送失败!");
                        printf("--------------------------------------------\n");
                        break;
                    }
                }
                /*客户端发来了消息*/
                if (FD_ISSET(newfd, &rfds))
                {
                    /******接收消息*******/
                    memset(buf, 0, sizeof(buf));
                    /*fgets函数：从流中读取BUFLEN-1个字符*/
                    len = recv(newfd, buf, BUFLEN, 0);
                    if (len > 0)
                    {
                        printf("<===============================>\n");
                        //仅供数据链路层测试，后期注释掉
                        // printf("对方说：\n");
                        // printf("%d", len);
                        // printf("\n");
                        // for (int ii = 0; ii < len; ii++)
                        // {
                        //     printf("%c", buf[ii]);
                        // }
                        // printf("\n");

                        // CRC
                        unsigned int crc32_result = crc32((unsigned char *)buf, len - 4);
                        unsigned char crc32_result_c[4];
                        memcpy(crc32_result_c, &crc32_result, sizeof(crc32_result));
                        // Judge whether the CRC check code is consistent
                        bool bool_crc_same = crc32_result_c[3] == buf[len - 1] &&
                                             crc32_result_c[2] == buf[len - 2] &&
                                             crc32_result_c[1] == buf[len - 3] &&
                                             crc32_result_c[0] == buf[len - 4];
                        if (!bool_crc_same)
                        {
                            printf("CRC correct\n");
                            // exit(0);
                        }
                        // MAC
                        unsigned char dst_mac[6];
                        memcpy(&dst_mac, &buf, 6);
                        // 判断MAC地址是否一样
                        bool bool_mac_same = mac_same(dst_mac, my_mac, 6);
                        if (!bool_mac_same)
                        {
                            printf("MAC ERROR\n");
                            exit(0);
                        }
                        printf("DA_MAC:\n");
                        show_mac_addr(dst_mac);
                        printf("\n");

                        unsigned char src_mac[6];
                        memcpy(&src_mac, &buf[6], 6);
                        printf("SA_MAC:\n");
                        show_mac_addr(src_mac);
                        printf("\n");

                        unsigned char protocol_type[2];
                        memcpy(&protocol_type, &buf[12], 2);
                        printf("ProtocalType:\n");
                        show_protocol(protocol_type);
                        printf("\n");

						unsigned char payload[1500];
                        memcpy(payload, &buf[14], len - 18);
						printf("数据链路层解封装成功，开始网络层解封装\n");
                        network_layer_receriver(payload, len - 18);

                        // printf("Sender说：");
                        // for (int ii = 14; ii < len - 4; ii++)
                        // {
                        //     printf("%c", buf[ii]);
                        // }
                        printf("<===============================>\n");
                    }
                    else
                    {
                        if (len < 0)
                            printf("接受消息失败！\n");
                        else
                            printf("客户端退出了，聊天终止！\n");
                        break;
                    }
                }
            }
        }
        // 关闭聊天的套接字
        close(newfd);
        // 是否退出服务器
        printf("确认退出?\ny->是; n->否? ");
        bzero(buf, BUFLEN);
        fgets(buf, BUFLEN, stdin);
        if (!strncasecmp(buf, "y", 1))
        {
            printf("------------------感谢您的使用----------------\n");
            break;
        }
    }
    // 关闭服务器的Socket
    close(sockfd);
    return 0;
}