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
    string commands[1024] = {};
    if (argc > 1) {
        if (argv[1] == std::string("--help") || argv[1] == std::string("-h")) {
            cout << argv[0] << "<filename>" << "\n";
            return 0;
        }
        ifstream file(argv[1]);
        string line;
        while (getline(file, line)) {
            cout << line << endl;
            commands->append(line);
        }
        file.close();
    }

    for (int i = 0; i < 1024; i++) {
        if (!commands[i].empty()) {
            cout << commands[i] << endl;
        }
    }

    // if \n split, send and execute
    // port knocking
    // password

    char command[10240];
    read(0, command, 10240);

    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(9999);
    //serverAddress.sin_addr.s_addr = INADDR_ANY;
    
    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, "127.0.0.1", &serverAddress.sin_addr) <=0 ) {
        perror("Invalid address/Address not supported \n");
        exit(EXIT_FAILURE);
    }

    if (connect(clientSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress))) {
        perror("Connection Failed \n");
        exit(EXIT_FAILURE);
    }

    send(clientSocket, command, strlen(command), 0);
    close(clientSocket);

    return 0;
}