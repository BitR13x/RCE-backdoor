#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <signal.h>

#include <fstream>
#include <unistd.h>

#include <termios.h>

#define ALLOW_CONNETIONS 11 // 100 sockets
static int master_socket, clients[ALLOW_CONNETIONS];

std::string exec(const char *cmd)
{
    char buffer[128];
    std::string result = "";
    FILE *pipe = popen(cmd, "r");
    if (!pipe)
        throw std::runtime_error("popen() failed!");
    try
    {
        while (fgets(buffer, sizeof buffer, pipe) != NULL)
        {
            result += buffer;
        }
    }
    catch (...)
    {
        pclose(pipe);
        throw;
    }
    pclose(pipe);
    return result;
}

void parse_recv(char *recv_output, int bytes_received)
{
    // overwrite newline with null-termination
    if (recv_output[bytes_received - 1] == '\n')
    {
        recv_output[bytes_received - 1] = '\0';
    }
    else
    {
        recv_output[bytes_received] = '\0';
    }
};

int respond(int client_slot, char *client_command)
{
    std::string output = exec(client_command);
    if (output.length() > 0) {
        const char *response = output.c_str();
        send(client_slot, response, strlen(response), 0);
    } else {
        char error_message[] = "Command failed!";
        send(client_slot, error_message, strlen(error_message), 0);
    }

    return 0;
}

int openSocket(in_addr_t s_addr, int server_port)
{
    int serverSocket;
    if ((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(server_port);

    // struct in_addr addr;
    // inet_aton("127.0.0.1", &addr);
    serverAddress.sin_addr.s_addr = s_addr;

    int yes = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0)
    {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }

    if (bind(serverSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
    {
        perror("bind failed");
        return EXIT_FAILURE;
    }
    else
    {
        std::cout << "Server is running " << s_addr << ":" << server_port << std::endl;
    };

    if (listen(serverSocket, 5) < 0)
    {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    signal(SIGCHLD, SIG_IGN);

    return serverSocket;
}

std::string generateRandomString(int length)
{
    // randomize seed
    srand(time(NULL));

    static const std::string characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::string randomString;
    for (int i = 0; i < length; ++i)
    {
        randomString += characters[rand() % characters.size()];
    }
    return randomString;
}

#include <openssl/evp.h>
std::string sha256(const std::string &input)
{
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    EVP_DigestInit_ex(context, EVP_sha256(), NULL);
    EVP_DigestUpdate(context, input.c_str(), input.size());
    unsigned char hash[EVP_MD_size(EVP_sha256())];
    EVP_DigestFinal_ex(context, hash, NULL);
    EVP_MD_CTX_free(context);

    std::string output = "";
    for (int i = 0; i < EVP_MD_size(EVP_sha256()); i++)
    {
        char hex[3];
        sprintf(hex, "%02x", hash[i]);
        output += hex;
    }
    return output;
}

bool verify_password(char *server_password, char client_password[])
{
    if (std::string(server_password) == sha256(client_password))
    {
        return true;
    }
    else
    {
        return false;
    }
}

void connection_info(struct sockaddr_in &client)
{
    char *connected_ip = inet_ntoa(client.sin_addr);
    int port = ntohs(client.sin_port);

    std::cout << "-[IP:" << connected_ip << ", Connected on PORT:" << port << "]" << std::endl;
}

int main(int argc, char *argv[])
{
    int buffer_size = 1024;
    char server_password[buffer_size];

    if (argc > 1 && argv[1] == std::string("-m"))
    {
        FILE *w_file = fopen(".hashpassword", "w");

        // terminal setup
        struct termios oldt, newt;
        tcgetattr(STDIN_FILENO, &oldt);
        newt = oldt;
        newt.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);

        std::cin.width(buffer_size);
        std::cout << "Choose your password (input is hidden):" << std::endl;

        std::cin >> server_password;
        strcpy(server_password, sha256(server_password).c_str());

        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

        std::cout << "Password successfully set\n";

        fwrite(server_password, sizeof(char), strlen(server_password), w_file);
        fclose(w_file);
    }
    else
    {
        if (FILE *file = fopen(".hashpassword", "r"))
        {
            fgets(server_password, buffer_size, file);
            fclose(file);
        }
        else
        {
            FILE *w_file = fopen(".hashpassword", "w");

            std::string randomString = generateRandomString(32);
            std::cout << "Your password:\n"
                      << randomString << std::endl;
            strcpy(server_password, sha256(randomString).c_str());

            fwrite(server_password, sizeof(char), strlen(server_password), w_file);
            fclose(w_file);
        }
    }

    u_int32_t ip_addr;
    int server_port = 9999;
    if (argc > 1 && argv[1] == std::string("localhost"))
    {
        ip_addr = htonl(INADDR_LOOPBACK);
    }
    else
    {
        ip_addr = htonl(INADDR_ANY);
    }

    master_socket = openSocket(ip_addr, server_port);
    int slot = 0;
    while (1)
    {
        // https://stackoverflow.com/questions/25091148/single-tcp-ip-server-that-handles-multiple-clients-in-c
        struct sockaddr_in client_info = {0};
        int addrlen = sizeof(client_info);
        int clientSocket;
        if ((clientSocket = accept(master_socket, (struct sockaddr *)&client_info, (socklen_t *)&addrlen)) < 0)
        {
            perror("accept failed");
            exit(EXIT_FAILURE);
        };

        // print client IP and connected port
        connection_info(client_info);

        char client_password[buffer_size] = {0};
        char message[] = "What's your password:\n";

        if (send(clientSocket, message, strlen(message), 0) < 0)
        {
            perror("send failed");
            close(clientSocket);
            continue;
        }

        int bytes_received = recv(clientSocket, client_password, buffer_size - 1, 0);
        if (bytes_received <= 0)
        {
            perror("recv failed or connection closed");
            close(clientSocket);
            continue;
        }

        // null-byte
        parse_recv(client_password, bytes_received);

        if (verify_password(server_password, client_password))
        {
            // write allowed access history
            FILE *w_file = fopen(".access_history", "a");
            char *connected_ip = inet_ntoa(client_info.sin_addr);
            fwrite(connected_ip, sizeof(char), strlen(connected_ip), w_file);
            fclose(w_file);

            const char correct_password_message[] = "Correct password!\n\n";
            if (send(clientSocket, correct_password_message, strlen(correct_password_message), 0) < 0)
            {
                perror("send correct_password_message failed");
                close(clientSocket);
                continue;
            }

            // execute commands
            char command_buffer[buffer_size] = {0};
            while (std::string(command_buffer) != "bye")
            {
                // clear command buffer
                memset(command_buffer, 0, sizeof(command_buffer));

                int bytes_received = recv(clientSocket, command_buffer, buffer_size - 1, 0);
                if (bytes_received <= 0)
                {
                    perror("command recv failed or connection closed");
                    break;
                };

                parse_recv(command_buffer, bytes_received);

                /* 
                //check buffer bytes
                for (int i = 0; i < buffer_size; i++)
                {
                    std::cout << std::hex <<  (int)command_buffer[i] << " ";
                }
                */

                //std::cout << "Message from client: " << command_buffer << " " << bytes_received << std::endl;
                if (std::string(command_buffer) == "bye") {
                    break;
                }

                respond(clientSocket, command_buffer);
            }
        }
        else
        {
            char wrong_password_message[] = "Wrong password!";
            send(clientSocket, wrong_password_message, strlen(wrong_password_message), 0);
        }

        close(clientSocket);
    }

    shutdown(master_socket, SHUT_RDWR);
    close(master_socket);
    return EXIT_SUCCESS;
}