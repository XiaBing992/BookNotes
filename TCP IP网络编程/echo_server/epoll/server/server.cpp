#include <arpa/inet.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <iostream>
#include <errno.h>

#define BUFF_SIZE 2
#define EPOLL_SIZE 50

int main()
{
    int server_fd, client_fd;
    sockaddr_in server_addr, client_addr;

    memset(&server_addr, 0, sizeof(server_addr));
    memset(&server_addr, 0, sizeof(client_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr.sin_port = htons(10001);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1)
    {
        return -1;
    }

    int re_use = 1;
    if (setsockopt(server_fd,  SOL_SOCKET, SO_REUSEPORT, &re_use, sizeof(re_use)) == -1)
    {
        return -1;
    }

    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof (server_addr)) == -1)
    {
        return -1;
    }

    if (listen(server_fd, 5) == -1)
    {
        return -1;
    }

    struct epoll_event *ep_events; //用来存储准备好的事件
    struct epoll_event event;
    int epoll_fd, event_cnt;
    char message[BUFF_SIZE];

    epoll_fd = epoll_create(EPOLL_SIZE);
    ep_events = (epoll_event*)malloc(sizeof(epoll_event) * EPOLL_SIZE);
    event.events = EPOLLIN;
    event.data.fd = server_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &event);

    while(true)
    {
        event_cnt = epoll_wait(epoll_fd, ep_events, EPOLL_SIZE, -1);

        if (event_cnt == -1)
        {
            return -1;
        }

        for (int i = 0; i < event_cnt; i++)
        {
            if (ep_events[i].data.fd == server_fd)
            {
                socklen_t addr_size = sizeof(server_addr);
                client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &addr_size);
                event.data.fd = client_fd;
                event.events = EPOLLIN | EPOLLET;

                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &event);
                std::cout << "connected: " << client_fd << std::endl;
            }
            else 
            {
                while(1) //边缘模式
                {
                    int str_len = read(ep_events[i].data.fd, message, BUFF_SIZE);
                    message[str_len] = 0;
                    if (str_len == 0)
                    {
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, ep_events[i].data.fd, NULL);
                        close(ep_events[i].data.fd);
                        std::cout << "close: " << ep_events[i].data.fd << std::endl;
                    }
                    else if (str_len < 0)
                    {
                        if (errno == EAGAIN)
                        break;
                    }
                    else
                    {
                        std::cout << message << " str_len:" << str_len << std::endl;
                        write(ep_events[i].data.fd, message, str_len);
                    }
                }
            }
        }
    }
    close(server_fd);
    close(epoll_fd);

    return 0;
}