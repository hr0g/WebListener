#include <iostream>
#include <iomanip>
#include <cstring>
#include <vector>
#include <thread>
#include <mutex>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#ifdef _WIN32
#include <openssl/applink.c>
#endif

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

std::mutex clientSocketsMutex;

void InitializeSSL() {
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
}

void CleanupSSL() {
    EVP_cleanup();
}

SSL_CTX* CreateContext() {
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    return ctx;
}

X509* LoadCertificate(const std::string& certPath) {
    FILE* certFile = fopen(certPath.c_str(), "r");
    if (!certFile) {
        std::cerr << "Failed to open certificate file.\n";
        return nullptr;
    }

    X509* cert = PEM_read_X509(certFile, nullptr, nullptr, nullptr);
    fclose(certFile);
    if (!cert) {
        std::cerr << "Failed to load certificate.\n";
    }

    return cert;
}

EVP_PKEY* LoadPrivateKey(const std::string& keyPath) {
    FILE* keyFile = fopen(keyPath.c_str(), "r");
    if (!keyFile) {
        std::cerr << "Failed to open key file.\n";
        return nullptr;
    }

    EVP_PKEY* key = PEM_read_PrivateKey(keyFile, nullptr, nullptr, nullptr);
    fclose(keyFile);
    if (!key) {
        std::cerr << "Failed to load private key.\n";
    }

    return key;
}

void ConfigureContext(SSL_CTX* ctx, X509* caCert, EVP_PKEY* caKey) {
    if (SSL_CTX_use_certificate(ctx, caCert) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if (SSL_CTX_use_PrivateKey(ctx, caKey) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        std::cerr << "Private key does not match the public certificate\n";
        exit(1);
    }
}

SOCKET ConnectToServer(const std::string& host, const std::string& port) {
    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "Failed to create server socket.\n";
        return INVALID_SOCKET;
    }

    struct addrinfo hints = { 0 }, * res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0) {
        std::cerr << "getaddrinfo failed.\n";
        closesocket(serverSocket);
        return INVALID_SOCKET;
    }

    if (connect(serverSocket, res->ai_addr, (int)res->ai_addrlen) == SOCKET_ERROR) {
        std::cerr << "Connect to destination failed.\n";
        closesocket(serverSocket);
        freeaddrinfo(res);
        return INVALID_SOCKET;
    }

    freeaddrinfo(res);
    return serverSocket;
}

void HandleSSLData(SSL* ssl) {
    char buffer[4096];
    int bytesReceived;

    while ((bytesReceived = SSL_read(ssl, buffer, sizeof(buffer))) > 0) {
        // Process received data
        std::cout << "Received data:\n";
        std::cout.write(buffer, bytesReceived);
        std::cout << std::endl;

        // Send the data to the other end
        SSL_write(ssl, buffer, bytesReceived);
    }

    if (bytesReceived < 0) {
        std::cerr << "SSL_read failed.\n";
    }
}

void TunnelData(SSL* clientSSL, SSL* serverSSL) {
    std::thread([clientSSL, serverSSL]() {
        HandleSSLData(clientSSL);
        SSL_shutdown(clientSSL);
        SSL_free(clientSSL);
        }).detach();

        HandleSSLData(serverSSL);
        SSL_shutdown(serverSSL);
        SSL_free(serverSSL);
}

void TunnelRawData(SOCKET clientSocket, SOCKET serverSocket) {
    std::thread([clientSocket, serverSocket]() {
        char buffer[4096];
        int bytesReceived;

        while ((bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0)) > 0) {
            send(serverSocket, buffer, bytesReceived, 0);
        }

        closesocket(serverSocket);
        }).detach();

        char buffer[4096];
        int bytesReceived;

        while ((bytesReceived = recv(serverSocket, buffer, sizeof(buffer), 0)) > 0) {
            send(clientSocket, buffer, bytesReceived, 0);
        }

        closesocket(clientSocket);
}

SOCKET CreateTunnel(SOCKET clientSocket, const std::string& request, SSL_CTX* ctx) {
    // Parse host and port from CONNECT request
    std::string host = request.substr(request.find(" ") + 1);
    host = host.substr(0, host.find(" "));
    std::string port = "443";  // Default HTTPS port

    if (host.find(":") != std::string::npos) {
        port = host.substr(host.find(":") + 1);
        host = host.substr(0, host.find(":"));
    }

    SOCKET serverSocket = ConnectToServer(host, port);
    if (serverSocket == INVALID_SOCKET) {
        return INVALID_SOCKET;
    }

    // Create SSL objects for client and server
    SSL* clientSSL = SSL_new(ctx);
    SSL* serverSSL = SSL_new(ctx);

    SSL_set_fd(clientSSL, clientSocket);
    SSL_set_fd(serverSSL, serverSocket);

    // Perform SSL handshake
    if (SSL_accept(clientSSL) <= 0) {
        std::cerr << "SSL_accept failed.\n";
        SSL_free(clientSSL);
        SSL_free(serverSSL);
        closesocket(serverSocket);
        return INVALID_SOCKET;
    }

    if (SSL_connect(serverSSL) <= 0) {
        std::cerr << "SSL_connect failed.\n";
        SSL_free(clientSSL);
        SSL_free(serverSSL);
        closesocket(serverSocket);
        return INVALID_SOCKET;
    }

    return serverSocket;
}

void ClientHandler(SOCKET clientSocket, SSL_CTX* ctx) {
    char buffer[1024];
    int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);

    if (bytesReceived > 0) {
        buffer[bytesReceived] = '\0';
        std::string request(buffer);

        std::cout << "Received request:\n" << request << std::endl;

        if (request.find("CONNECT") != std::string::npos) {
            // Handle HTTPS via CONNECT method
            std::string response = "HTTP/1.1 200 Connection Established\r\n\r\n";
            send(clientSocket, response.c_str(), response.length(), 0);

            // Create SSL objects and tunnel data
            SOCKET serverSocket = CreateTunnel(clientSocket, request, ctx);
            if (serverSocket != INVALID_SOCKET) {
                SSL* clientSSL = SSL_new(ctx);
                SSL* serverSSL = SSL_new(ctx);

                SSL_set_fd(clientSSL, clientSocket);
                SSL_set_fd(serverSSL, serverSocket);

                TunnelData(clientSSL, serverSSL);
            }
            else {
                std::cerr << "Failed to create tunnel to server.\n";
            }
        }
        else {
            // Handle normal HTTP request
            std::string host = "localhost";  // Default to localhost, modify as needed
            std::string port = "80";  // Default HTTP port

            SOCKET serverSocket = ConnectToServer(host, port);
            if (serverSocket != INVALID_SOCKET) {
                send(serverSocket, buffer, bytesReceived, 0);

                // Use TunnelRawData for HTTP connections
                TunnelRawData(clientSocket, serverSocket);
            }
            else {
                std::cerr << "Failed to connect to HTTP server.\n";
            }
        }
    }
    else {
        std::cerr << "Failed to receive request.\n";
    }

    closesocket(clientSocket);
}

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed.\n";
        return 1;
    }

    InitializeSSL();
    SSL_CTX* ctx = CreateContext();
    X509* caCert = LoadCertificate("server.crt");
    EVP_PKEY* caKey = LoadPrivateKey("server.key");
    if (caCert && caKey) {
        ConfigureContext(ctx, caCert, caKey);
    }
    else {
        std::cerr << "Failed to load CA certificate or private key.\n";
        return 1;
    }

    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "Failed to create socket\n";
        WSACleanup();
        return 1;
    }

    sockaddr_in serverAddr = { 0 };
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddr.sin_port = htons(8080);  // Listen on port 8080

    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed\n";
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Listen failed\n";
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "Server listening on port 8080...\n";

    while (true) {
        SOCKET clientSocket = accept(serverSocket, nullptr, nullptr);
        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "Accept failed\n";
            continue;
        }

        std::thread(ClientHandler, clientSocket, ctx).detach();
    }

    closesocket(serverSocket);
    CleanupSSL();
    WSACleanup();
    return 0;
}
