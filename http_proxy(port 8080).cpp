#include <iostream>
#include <cstring>
#include <vector>
#include <thread>
#include <mutex>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib,"ws2_32.lib")

std::mutex clientSocketsMutex;

void ClientHandler(SOCKET clientSocket) {
    char buffer[1024];
    int bytesReceived;

    while (true) {
        bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
        if (bytesReceived > 0) {
            buffer[bytesReceived] = '\0';
            std::cout << "Received:\n" << buffer << std::endl;

            // Basic response to an HTTP GET request
            std::string httpResponse = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Hello, World!</h1></body></html>\r\n";
            send(clientSocket, httpResponse.c_str(), httpResponse.length(), 0);
        }
        else {
            break; // Handle errors or disconnection
        }
    }

    clientSocketsMutex.lock();
    std::cout << "Client disconnected.\n";
    closesocket(clientSocket);  // Close the socket of this client
    clientSocketsMutex.unlock();
}

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed.\n";
        return 1;
    }

    SOCKET serverSocket;
    struct sockaddr_in serverAddr, clientAddr;
    int addrSize = sizeof(struct sockaddr_in);

    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "Failed to create socket\n";
        WSACleanup();
        return 1;
    }

    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddr.sin_port = htons(8080); // Listen on port 8080

    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
        std::cerr << "Bind failed\n";
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    listen(serverSocket, SOMAXCONN);
    std::vector<std::thread> threads;

    while (true) {
        SOCKET clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &addrSize);
        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "Accept failed\n";
            break;
        }

        std::cout << "Client connected.\n";
        threads.push_back(std::thread(ClientHandler, clientSocket));
    }

    for (auto& th : threads) {
        if (th.joinable()) {
            th.join();
        }
    }

    closesocket(serverSocket);
    WSACleanup();
    return 0;
}
