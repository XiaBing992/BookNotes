#include <sys/socket.h>
#include <arpa/inet.h>
#include <iostream>
#include <string.h>
#include <unistd.h>

#define BUFF_SIZE 1024

int main(int argc, char *argv[])
{
    int server_sock, client_sock;
    char message[BUFF_SIZE];
    int str_len, i;

    struct sockaddr_in server_addr;

    //用于存储客户端信息，可以为NULL
    struct sockaddr_in client_addr;
    socklen_t client_addr_size;

    server_sock = socket(PF_INET, SOCK_STREAM, 0);
    if (server_sock == -1)
    {
        std::cout << "socket error" << std::endl;
        return -1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr=htonl(INADDR_ANY);
    server_addr.sin_port=htons(10001);

    // 设置套接字选项
    int re_use = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEPORT, &re_use, sizeof(re_use)) == -1)
    {
        return -1;
    }

    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1)
    {
        std::cout << "bind error" << std::endl;
        return -1;
    }

    if (listen(server_sock, 5) == -1)
    {
        return -1;
    }

    client_addr_size = sizeof(client_addr);
    
    for (int i = 0; i < 5; i++)
    {
        client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_addr_size);
        std::cout << "client fd: " << client_sock << std::endl;

        if (client_sock == -1)
        {
            return -1;
        }

        while ((str_len = read(client_sock, message, BUFF_SIZE)) != 0)
        {
            std::cout << "len:" << str_len << std::endl;
            write(client_sock, message, str_len);
        }

        close(client_sock);
    }
    close(server_sock);

    return 0;


}