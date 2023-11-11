#include <iostream>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>

#define BUFF_SIZE 1024
int main(int argc, char *argv[])
{
    int server_sock;
    int str_len;
    char message[BUFF_SIZE];
    struct sockaddr_in server_addr;

    server_sock = socket(PF_INET, SOCK_DGRAM, 0); //0表示根据前面的参数，自动选择传输协议

    if (server_sock == -1)
    {
        std::cout << "socket error" << std::endl;
        return -1;
    }


    memset(&server_addr, 0, sizeof(server_addr));
    memset(message, 0, BUFF_SIZE);
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr.sin_port = htons(10000);

    while(1)
    {
        std::cout << "input:" << std::endl;
        std::cin >> message;
        if (strcmp(message, "q") == 0)
        {
            break;
        }
        socklen_t addr_size = sizeof(server_addr);
        sendto(server_sock, message, sizeof(message), 0, (struct sockaddr*)&server_addr, addr_size);
        str_len = recvfrom(server_sock, message, BUFF_SIZE, 0, (struct sockaddr*)&server_addr, &addr_size);
        message[str_len] = 0;
        std::cout << "echo: " << message << std::endl;
    }

    return 0;
}