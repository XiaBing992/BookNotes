#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <string.h>
#include <iostream>

#define BUFF_SZIE 1024
int main(int argc, char *argv[])
{
    int server_fd, client_fd;
    struct sockaddr_in server_addr;
    socklen_t addr_len;
    fd_set reads, cpy_reads; //描述符集合
    char message[BUFF_SZIE];

    server_fd = socket(AF_INET, SOCK_STREAM, 0);

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr.sin_port = htons(10001);
    int re_use = 1;
    if (setsockopt(server_fd,  SOL_SOCKET, SO_REUSEPORT, &re_use, sizeof(re_use)) == -1)
    {
        return -1;
    }

    if(bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1)
    {
        std::cout << "bind error" << std::endl;
        return -1;
    }

    if (listen(server_fd, 5) == -1)
    {
        return -1;
    }

    FD_ZERO(&reads);
    FD_SET(server_fd, &reads); //将server_fd添加到reads描述符集合
    //FD_SET(0, &reads);
    int fd_max = server_fd;
    struct timeval timeout;
    int fd_num;
    while(1)
    {
        cpy_reads = reads;
        timeout.tv_sec = 5;
        timeout.tv_usec = 5000;

        if ((fd_num = select(fd_max + 1, &cpy_reads, 0 , 0,  &timeout)) == -1)
        {
            std::cout << "fd_num: " << fd_num << std::endl;
            break;
        }
        if (fd_num == 0)
        {
            continue;
        }
        for (int i = 0; i < fd_max + 1; i++)
        {
            if (FD_ISSET(i, &cpy_reads)) // 判断i是否在描述符集合里
            {
                if (i == server_fd)
                {
                    addr_len = sizeof(server_addr);
                    client_fd = accept(server_fd, (struct sockaddr*)&server_addr, &addr_len);
                    FD_SET(client_fd, &reads); //将描述符加入
                    if (fd_max < client_fd)
                    {
                        fd_max = client_fd;
                    }
                    std::cout << "connected" << std::endl;
                }
                else
                {
                    int str_len = read(i,  message, BUFF_SZIE);
                    message[str_len] = 0;
                    if (str_len == 0)
                    {
                        FD_CLR(i, &reads); // 清除描述符
                        close(i);
                        std::cout << "close: " << i << std::endl;
                    }
                    else
                    {
                        std::cout << message << " len: " << str_len << std::endl;
                        write(i, message, str_len);
                    }
                }
            }
        }
    }
    std::cout << "end" << std::endl;
    close(server_fd);
    return 0;
}