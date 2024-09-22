#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <fstream>
#include <unistd.h>

using namespace std;

int main(int argc, char *argv[])
{
    int buffer_size = 1024;
    char client_password[buffer_size];

    char ip_addr[] = "127.0.0.1";
    // args: ip_addr, file, password
    string commands[1024] = {};
    if (argc > 1)
    {
        if (argv[1] == std::string("--help") || argv[1] == std::string("-h"))
        {
            cout << argv[0] << " <password>" << " <filename>" << endl;
            return 0;
        }

        strncpy(client_password, argv[1], buffer_size);

        if (argc > 2)
        {
            ifstream file(argv[2]);
            string line;
            while (getline(file, line))
            {
                //cout << line << endl;
                commands->append(line);
            }
            file.close();
        }
    } /* else {
        cout << argv[0] << " <password>" << " <filename>" << endl;
        return 0;
    } */

    // connection
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(9999);
    // serverAddress.sin_addr.s_addr = INADDR_ANY;

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, ip_addr, &serverAddress.sin_addr) <= 0)
    {
        perror("Invalid address/Address not supported \n");
        exit(EXIT_FAILURE);
    }

    if (connect(clientSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)))
    {
        perror("Connection Failed \n");
        exit(EXIT_FAILURE);
    }

    // comunication
    char server_message[buffer_size];
    if (recv(clientSocket, server_message, sizeof(server_message), 0) <= 0) {
        perror("recv failed or connection closed");
        close(clientSocket);
        exit(EXIT_FAILURE);
    };

    cout << server_message;

    // clear buffer
    memset(server_message, 0, sizeof(server_message));

    if (argc == 1)
    {
        read(0, client_password, buffer_size);
    }

    if (send(clientSocket, client_password, strlen(client_password), 0) < 0) {
        perror("send failed");
        close(clientSocket);
        exit(EXIT_FAILURE);
    }

    if (recv(clientSocket, server_message, sizeof(server_message), 0) <= 0) {
        perror("recv failed or connection closed");
        close(clientSocket);
        exit(EXIT_FAILURE);
    };

    cout << server_message;

    if (string(server_message) == "Wrong password!")
    {
        return 0;
    }
    else
    {
        if (commands[0].empty())
        {
            char command[buffer_size];
            read(0, command, buffer_size);
            send(clientSocket, command, strlen(command), 0);
        }
        else
        {
            for (int i = 0; i < 1024; i++)
            {
                if (!commands[i].empty())
                {
                    send(clientSocket, commands[i].c_str(), commands[i].length(), 0);
                }
            }
        }
    }

    close(clientSocket);

    return 0;
}