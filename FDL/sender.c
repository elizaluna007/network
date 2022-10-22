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

#define BUFLEN 65535
#define PORT 8200

#define UDP_DATA_MAXSIZE 65527
#define IPV4_DATA_MAXSIZE 1440
#define DATALINK_DATA_MAXSIZE 1500

///////////////////////数据链路层////////////////////////////////
#define MAXSIZE 1500
#define MINSIZE 46

// SIZE:    6Bytes   6Bytes   2Bytes         46-1500Bytes   4Bytes
// MEANING: DA       SA       ProtocalType   PayLoad        FCS

// Mac Address
typedef unsigned char mac_addr[6];
mac_addr DesMacAddr = {0x3D, 0xE1, 0x2D, 0x6F, 0xE9, 0x34};
mac_addr SrcMacAddr = {0x34, 0xE1, 0x2D, 0x6F, 0xE9, 0x3D};

// Data source and data destination
FILE *fileIn, *fileOut;
// 最后一帧的位置
long int LastFramePos;
long int PayLoadCount, AllByteCount;
long int RestByteCount, LackByteCount;

// CRC序列校验
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

// 形成帧
unsigned short make_frame(mac_addr *dst, mac_addr *src, unsigned short protocol, unsigned char *payload, int payloadlen, unsigned char *result)
{
    memcpy(&result[0], dst, 6);
    memcpy(&result[6], src, 6);
    memcpy(&result[12], &protocol, sizeof(protocol));
    memcpy(&result[14], payload, payloadlen);
    unsigned int crc32_result = crc32(result, payloadlen + 14);
    memcpy(&result[14 + payloadlen], &crc32_result, sizeof(crc32_result));
    return 18 + payloadlen;
}

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

// 发送帧
int send_frame(unsigned char *frame_data, unsigned short len, int sockfd)
{
    int send_len= send(sockfd, (char *)frame_data, (int)len, 0);
    return send_len;
}

// 数据链路层发送数据
int datalink_layer_send(unsigned char *buf, int len, int sockfd)
{
    unsigned char FrameBuffer[DATALINK_DATA_MAXSIZE + 18];
    unsigned short FrameLength = make_frame(&DesMacAddr, &SrcMacAddr, 0x0800, buf, len, FrameBuffer);
    return send_frame(FrameBuffer, FrameLength, sockfd);
}
///////////////////////数据链路层////////////////////////////////

/////////////////////////main//////////////////////////////////


int main(int argc, char **argv)
{
	printf("欢迎您进入发送端\n");
    int sockfd;
    struct sockaddr_in s_addr;
    socklen_t len;
    unsigned int port;
    char buf[BUFLEN];
    fd_set rfds;
    struct timeval tv;
    int retval, maxfd;

    // 建立socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        printf("创建SOCKET失败\n");
        perror("socket");
        exit(errno);
    }
    else
        printf("--------------------------------------------\n");
        printf("创建SOCKET成功\n");

    // 设置服务器ip
    memset(&s_addr, 0, sizeof(s_addr));
    s_addr.sin_family = AF_INET;
    s_addr.sin_port = htons(PORT);
    if (inet_aton(argv[1], (struct in_addr *)&s_addr.sin_addr.s_addr) == 0)
    {
        perror(argv[1]);
        exit(errno);
    }
    else
    {
        printf("接收端的IP地址成功设置为%s，端口成功设置为%d\n",argv[1],ntohs(s_addr.sin_port));
    }
    // 开始连接服务器
    if (connect(sockfd, (struct sockaddr *)&s_addr, sizeof(struct sockaddr)) == -1)
    {
        perror("connect");
        exit(errno);
    }
    else
	{
		printf("-------发送端成功连接接收端-------\n");
		printf("***接受端的地址是：%s，端口是：%d***\n", inet_ntoa(s_addr.sin_addr), ntohs(s_addr.sin_port));
		printf("您现在可与接收端进行通信...\n");
		printf("--------------------------------------------\n");
	}
        
    while (1)
    {
        FD_ZERO(&rfds);
        FD_SET(0, &rfds);
        maxfd = 0;
        FD_SET(sockfd, &rfds);
        if (maxfd < sockfd)
            maxfd = sockfd;
        tv.tv_sec = 10;
        tv.tv_usec = 0;
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
            // 服务器发来了消息
            if (FD_ISSET(sockfd, &rfds))
            {
                /******接收消息*******/
                bzero(buf, BUFLEN);
                len = recv(sockfd, buf, BUFLEN, 0);
                if (len > 0)
				{
					printf("Receiver说%s", buf);
					printf("--------------------------------------------\n");
				}
                else
                {
                    if (len < 0)
					{
						printf("接受消息失败！\n");
						printf("--------------------------------------------\n");
					}   
                    else
                        printf("Receiver已退出\n");
                    break;
                }
            }

            // 用户输入信息了,开始处理信息并发送
            if (FD_ISSET(0, &rfds))
            {
                /******发送消息*******/
                bzero(buf, BUFLEN);
                fgets(buf, BUFLEN, stdin);

                if (!strncasecmp(buf, "quit", 4))
                {
                    printf("Sender请求终止聊天!\n");
                    break;
                }
                //存放frame
                unsigned char FrameBuffer[DATALINK_DATA_MAXSIZE + 18];
                //形成frame，放入frame_data
                unsigned short FrameLength = make_frame(&DesMacAddr, &SrcMacAddr, 0x0800, buf, len, FrameBuffer);
                //将形成的frame发送给数据链路层处理
                //len = datalink_layer_send(FrameBuffer, FrameLength, sockfd);
				len=send_frame(FrameBuffer,FrameLength,sockfd);
                if (len > 0)
                {
                    printf("=======>消息发送成功：%s", buf);
					printf("--------------------------------------------\n");
                }
                else
                {
                    printf("可恶，消息发送失败!\n");
					printf("--------------------------------------------\n");
                    break;
                }
            }
        }
	}
    // 关闭连接
    close(sockfd);
    return 0;
}
//////////////////////////////////////////////////////////////////////////////////////////