#include <iostream>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <string>

#define BUFF_SIZE 1024
int main(int argc, char *argv[])
{
    int client_sock;
    int str_len;
    char message[BUFF_SIZE];
    struct sockaddr_in client_addr;

    client_sock = socket(PF_INET, SOCK_STREAM, 0); //0表示根据前面的参数，自动选择传输协议

    if (client_sock == -1)
    {
        std::cout << "socket error" << std::endl;
        return -1;
    }


    memset(&client_addr, 0, sizeof(client_addr));
    memset(message, 0, BUFF_SIZE);
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    client_addr.sin_port = htons(10001);


    if (connect(client_sock, (struct sockaddr*)&client_addr, sizeof(client_addr)) == -1)
    {
        std::cout << "connect error: " << errno << std::endl;
        return -1;
    }

    while(1)
    {
        std::cout << "input:" << std::endl;
        std::cin >> message;
        if (strcmp(message, "q") == 0)
        {
            break;
        }
        write(client_sock, message, strlen(message));
        str_len = read(client_sock, message, BUFF_SIZE - 1);
        message[str_len] = 0;
        std::cout << "echo: " << message << " len: " << str_len << std::endl;
    }

    return 0;
}