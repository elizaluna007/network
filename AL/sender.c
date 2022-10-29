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
	printf("数据链路层一次封装成功,开始数据发送\n");
    return send_frame(FrameBuffer, FrameLength, sockfd);
}
///////////////////////数据链路层////////////////////////////////

//////////////////////////网络层///////////////////////////////////
#define DATA_MAXSIZE 1440 //字节
#define DATA_MINSIZE 26   //字节

typedef struct IP_Packet
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
}IP_Packet;

void PrintBinary(const int argc)
{
    for (int i = 15; i >= 0; i--) //高位到低位输出
    {
        int a;
        a = 0x01 & argc >> i;
        printf("%d", a);
    }
}

unsigned short extendl_16bit(unsigned int bit_content, int bit_offset)
{
    bit_content = bit_content << bit_offset;
    unsigned short res = 0b0; //16 bit
    res += bit_content;
    return res;
}

unsigned short extendr_16bit(unsigned int bit_content, int bit_offset)
{
    bit_content = bit_content >> bit_offset;
    unsigned short res = 0b0; //16 bit
    res += bit_content;
    return res;
}

unsigned char extendl_8bit(unsigned int bit_content, int bit_offset)
{
    bit_content = bit_content << bit_offset;
    unsigned char res = 0b0; //16 bit
    res += bit_content;
    return res;
}

unsigned char extendr_8bit(unsigned int bit_content, int bit_offset)
{
    bit_content = bit_content >> bit_offset;
    unsigned char res = 0b0; //16 bit
    res += bit_content;
    return res;
}

// CheckSum
// void HeaderSetCheckSum(IP_Packet &ip_packet)
// {
//     ip_packet.IPv4_HeaderCheckSum =

//         extendl_16bit(ip_packet.IPv4_Version, 12) +
//         extendl_16bit(ip_packet.IPv4_IHL, 8) +
//         extendl_16bit(ip_packet.IPv4_TOS, 0) +

//         extendl_16bit(ip_packet.IPv4_TotalLength, 0) +

//         extendl_16bit(ip_packet.IPv4_Identification, 0) +

//         extendl_16bit(ip_packet.IPv4_NoFunc, 15) +
//         extendl_16bit(ip_packet.IPv4_DF, 14) +
//         extendl_16bit(ip_packet.IPv4_MF, 13) +
//         extendl_16bit(ip_packet.IPv4_FragmentOffset, 0) +

//         extendl_16bit(ip_packet.IPv4_TimeTolive, 8) +
//         extendl_16bit(ip_packet.IPv4_Protocol, 0) +

//         extendl_16bit(ip_packet.IPv4_SourceAddr, 0) + //低16bit
//         extendr_16bit(ip_packet.IPv4_SourceAddr, 16) +

//         extendl_16bit(ip_packet.IPv4_DesAddr, 0) + //低16bit
//         extendr_16bit(ip_packet.IPv4_DesAddr, 16);
// }

// Make Ip packet
unsigned int MakeIpPacket(unsigned int DF, unsigned int MF, unsigned int FragmentOffset, const IP_Packet ip_packet, unsigned char *buf, unsigned char *IPv4_Option, long IPv4_Option_Len, unsigned char *IPv4_Data, short IPv4_Data_Len)
{
    //第一个byte
    unsigned char VersionAndIhl = extendl_8bit(ip_packet.IPv4_Version, 4) + extendl_8bit(ip_packet.IPv4_IHL, 0); //8 bit
    memcpy(buf, &VersionAndIhl, sizeof(VersionAndIhl));
    //第二个byte
    unsigned char IPv4_TOS = extendl_8bit(ip_packet.IPv4_TOS, 0); //8 bit
    memcpy(&buf[1], &IPv4_TOS, sizeof(IPv4_TOS));                 //1已经被占用
    //第三四个byte
    unsigned short IPv4_TotalLength = 5 + 40 + (short)IPv4_Data_Len; //ip_packet.IPv4_TotalLength;
    memcpy(&buf[2], &IPv4_TotalLength, sizeof(IPv4_TotalLength));    //3已经被占用
    //第五六个byte
    unsigned short IPv4_Identification = ip_packet.IPv4_Identification;
    memcpy(&buf[4], &IPv4_Identification, sizeof(IPv4_Identification)); //5已经被占用
    //第7、8个byte
    //unsigned short extendl_16bit(unsigned int bit_content, int bit_offset)
    unsigned short NoFunc_DF_FragmentOffset = extendl_16bit(ip_packet.IPv4_NoFunc, 15) + extendl_16bit(DF, 14) + extendl_16bit(MF, 13) + extendl_16bit(FragmentOffset, 0);
    memcpy(&buf[6], &NoFunc_DF_FragmentOffset, sizeof(NoFunc_DF_FragmentOffset)); //7已经被占用
    //第9、10个byte
    //unsigned short TimeTolive_Protocol=extendl_16bit(ip_packet.IPv4_TimeTolive,8)+extendl_16bit(ip_packet.IPv4_Protocol,0);
    unsigned short TimeTolive_Protocol = extendl_16bit(ip_packet.IPv4_Protocol, 8) + extendl_16bit(ip_packet.IPv4_TimeTolive, 0);
    memcpy(&buf[8], &TimeTolive_Protocol, sizeof(TimeTolive_Protocol)); //9已经被占用
    //11 12
    unsigned short HeaderCheckSum = ip_packet.IPv4_HeaderCheckSum;
    memcpy(&buf[10], &HeaderCheckSum, sizeof(HeaderCheckSum)); //11已经被占用
    //13 14 15 16
    unsigned int SourceAddr = ip_packet.IPv4_SourceAddr;
    memcpy(&buf[12], &SourceAddr, sizeof(SourceAddr)); //15已经被占用
    //17 18 19 20
    unsigned int DesAddr = ip_packet.IPv4_DesAddr;
    memcpy(&buf[16], &DesAddr, sizeof(DesAddr)); //19已经被占用
    // option
    memcpy(&buf[20], IPv4_Option, IPv4_Option_Len);
    // data
    memcpy(&buf[20 + IPv4_Option_Len], IPv4_Data, IPv4_Data_Len);
    //返回字节数
    return 20 + IPv4_Option_Len + IPv4_Data_Len;
}
//datalink_layer_send(buf, IpPacketLen,fileOut);
//将形成的UDP数据包发送给网络层处理
// network_layer_send(udp_buffer,UdpPacketLen,fileOut);
int network_layer_send(unsigned char *udp_packet, unsigned int udp_packet_len, int sockfd)
{
	//发送的数据的总长度
    int socket_send_len = 0;
	//IP数据报的基本格式
    struct IP_Packet ip_packet_info = {0b0100, 0b1111, 0b00000000,         //IPv4_Version,IPv4_IHL,IPv4_TOS
                                       0b0000000000000000,                 //IPv4_TotalLength
                                       0b0000000000000000,                 //IPv4_Identification
                                       0b0, 0b0, 0b0, 0b0000000000000,     //IPv4_NoFunc,IPv4_DF,IPv4_MF,IPv4_FragmentOffset
                                       0b01010101, 0b10101010,             //IPv4_TimeTolive,IPv4_Protocol
                                       0b0000000000000000,                 //IPv4_HeaderCheckSum
                                       0b11011010010001101111111101100001, //IPv4_SourceAddr //218.70.255.97
                                       0b01110010001101110101111100001110, //IPv4_DesAddr //114.55.95.14
                                       0b0,                                //IPv4_Option
                                       0b0};                               //IPv4_Data
    //开始分片
    // Split the data
    for (unsigned int j = 0; j <= udp_packet_len / 1440; j++)
    {
        // // 1 bit
        // unsigned int IPv4_NoFunc : 1;
        // // 1 bit
        // unsigned int IPv4_DF : 1; //DF=0允许分片；DF=1不允许分片。
        // // 1 bit
        // unsigned int IPv4_MF : 1;  //MF=1表示后面还有分片；MF=0表示这是最后一个分片
        // // 13 bit
        // unsigned int IPv4_FragmentOffset : 13;  //指明了每个分片相对于原始报文开头的偏移量，以8B为单位，即每个分片的长度必须是8B的整数倍。

		//如果输入的数据总长度超过1440字节，即数据部分长度超过1420字节，则需要分片，分别生成IPv4数据报发送到数据链路层
        if (j != udp_packet_len / 1440)
        {
			printf("发送一个分片\n");
            // 0~IPV4_DATA_MAXSIZE-1 ; IPV4_DATA_MAXSIZE~2*IPV4_DATA_MAXSIZE-1;
            // j*IPV4_DATA_MAXSIZE~((j+1)*IPV4_DATA_MAXSIZE-1)
            unsigned char udp_packet_splited[IPV4_DATA_MAXSIZE];
            for (int i = j * IPV4_DATA_MAXSIZE, l = 0; i < ((j + 1) * IPV4_DATA_MAXSIZE); i++, l++)
            {
                //printf("i:%d\n" ,i);
                udp_packet_splited[l] = udp_packet[i];
            }
            unsigned char ipv4_buffer[IPV4_DATA_MAXSIZE + 60]; //存放udp数据包
            unsigned int DF, MF, FragmentOffset;
            DF = 0;
            MF = 1;
            FragmentOffset = j;
            //unsigned int MakeIpPacket(unsigned int DF,unsigned int MF,unsigned int FragmentOffset, const IP_Packet ip_packet, unsigned char *buf, unsigned char *IPv4_Option, long IPv4_Option_Len, unsigned char *IPv4_Data, short IPv4_Data_Len)
            unsigned int IpPacketLen = MakeIpPacket(DF, MF, FragmentOffset, ip_packet_info, ipv4_buffer, ip_packet_info.IPv4_Option, 40, udp_packet_splited, 1440);
			printf("网络层分片+封成功,开始一次数据链路层封装\n");
            socket_send_len += datalink_layer_send(ipv4_buffer, IpPacketLen, sockfd);
			printf("分片数据发送成功：");
			for(int ii = 0;ii < 1440;ii++)
			{
                if ((ii >= 8 && FragmentOffset == 0) || (FragmentOffset > 0))
				    printf("%c",udp_packet_splited[ii]);
			}
			printf("\n");
        }
		//如果输入的数据总长度小于等于1440字节，即数据部分长度不超过1420字节，则不需要分片，直接生成IPv4数据报发送到数据链路层
        else
        {
			printf("发送最后一个分片\n");
            int RestByte = udp_packet_len - (udp_packet_len / 1440) * IPV4_DATA_MAXSIZE;
            unsigned char udp_packet_splited[IPV4_DATA_MAXSIZE];
            for (int i = j * IPV4_DATA_MAXSIZE, l = 0; i < udp_packet_len; i++, l++)
            {
                udp_packet_splited[l] = udp_packet[i];
            }
            //以8B为单位，即每个分片的长度必须是8B的整数倍。
            if (RestByte / 8 != 0)
            {
                int ToFill = 8 - (RestByte - (RestByte / 8) * 8);
                for (int k = 0; k < ToFill; k++)
                {
                    udp_packet_splited[RestByte + k] = 0b0;
                }
                RestByte += ToFill;
            }
            unsigned char ipv4_buffer[IPV4_DATA_MAXSIZE + 60]; //存放udp数据包
            int DF, MF, FragmentOffset;
            DF = 0;
            MF = 0;
            FragmentOffset = j;
            unsigned long IpPacketLen = MakeIpPacket(DF, MF, FragmentOffset, ip_packet_info, ipv4_buffer, ip_packet_info.IPv4_Option, 40, udp_packet_splited, RestByte);
			printf("网络层分片+封成功,开始一次数据链路层封装\n");
            socket_send_len += datalink_layer_send(ipv4_buffer, IpPacketLen, sockfd);
			printf("该信息的最后的分片数据发送成功：");
			for(int ii = 0;ii < udp_packet_len % 1440;ii++)
			{
                if ((ii >= 8 && FragmentOffset == 0) || (FragmentOffset > 0))
				    printf("%c",udp_packet_splited[ii]);
			}

        }
    }
    return socket_send_len;
}
/////////////////////////网络层//////////////////////////////////

///////////////////////////传输层////////////////////////////////
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

// Make Udp packet
unsigned long MakeUdpPacket(
    const struct UDP_Packet udp_packet,
    unsigned char *buf,
    unsigned int UDP_Data_Len,
    unsigned char *UDP_Data)
{
    unsigned short UDP_SRC_PORT = udp_packet.UDP_SRC_PORT;
    memcpy(buf, &UDP_SRC_PORT, sizeof(UDP_SRC_PORT));
    unsigned short UDP_DES_PORT = udp_packet.UDP_DES_PORT;
    memcpy(&buf[2], &UDP_DES_PORT, sizeof(UDP_DES_PORT));
    unsigned short UDP_LEN = UDP_Data_Len + 8; //udp_packet.UDP_LEN;
    memcpy(&buf[4], &UDP_LEN, sizeof(UDP_LEN));
    unsigned short UDP_CHECK_SUM = udp_packet.UDP_CHECK_SUM;
    memcpy(&buf[6], &UDP_CHECK_SUM, sizeof(UDP_CHECK_SUM));
    memcpy(&buf[8], UDP_Data, UDP_Data_Len);
    //返回字节数
    return 8 + UDP_Data_Len;
}
///////////////////////////传输层////////////////////////////////

/////////////////////////main//////////////////////////////////
struct UDP_Packet udp_packet_info = {
    0b0000000000000111, 0b1110000000000000, //UDP_SRC_PORT,UDP_DES_PORT
    0b1111111111111111, 0b0000000000000000, //UDP_LEN,UDP_CHECK_SUM
    0b0};                                   //UDP_Data


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

				// //*数据链路层封装（已废弃）
                // //存放frame
                // unsigned char FrameBuffer[DATALINK_DATA_MAXSIZE + 18];
                // //形成frame，放入frame_data
                // unsigned short FrameLength = make_frame(&DesMacAddr, &SrcMacAddr, 0x0800, buf, len, FrameBuffer);
                // //将形成的frame发送给数据链路层处理
                // //len = datalink_layer_send(FrameBuffer, FrameLength, sockfd);
				// len=send_frame(FrameBuffer,FrameLength,sockfd);

				//*网络层封装+数据链路层封装+发送 (已废弃)
				// len = network_layer_send(buf, strlen(buf), sockfd);

                //存放udp数据包
                unsigned char UDP_Buffer[UDP_DATA_MAXSIZE + 8];
                //形成udp数据包,放入UDP_Buffer
                unsigned int UdpPacketLen = MakeUdpPacket(udp_packet_info, UDP_Buffer, (int)strlen(buf), (unsigned char *)buf);
                //将形成的UDP数据包发送给网络层处理
                len = network_layer_send(UDP_Buffer, UdpPacketLen, sockfd);

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