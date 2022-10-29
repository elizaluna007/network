#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
int main(int argc, char **argv)
{
    system("ifconfig>ip.txt\n"); // 将ipconfig得到的数据记录到ip.txt中
    FILE *file = fopen("ip.txt", "r");
    char c;
    char ip[100] = "";
    int i = 0;
    int num = 0;
    int num_k = 0;
    while ((c = fgetc(file)) != EOF)
    {
        if (c == 't')
        {
            i++;
        }
        if (i == 2) // 第二个t之后
        {
            if (c == ' ')
            {
                num_k++;
            }
            if (num_k == 1 & c != ' ')
            {
                ip[num] = c;
                num++;
            }
        }
    }
    printf("%s\n", ip);
    fclose(file);
    return 0;
}