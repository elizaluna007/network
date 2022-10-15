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

void PrintBinary(const char argc)
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
        PrintBinary(pl[i]);
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
                        printf("对方说：\n");
                        printf("%d", len);
                        printf("\n");
                        for (int ii = 0; ii < len; ii++)
                        {
                            printf("%c", buf[ii]);
                        }
                        printf("\n");

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
                        printf("Sender说：");
                        for (int ii = 14; ii < len - 4; ii++)
                        {
                            printf("%c", buf[ii]);
                        }
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