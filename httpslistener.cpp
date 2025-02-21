#pragma warning(disable:4996)
#include <iostream>
#include <iomanip>
#include <cstring>
#include <vector>
#include <thread>
#include <mutex>
#include <fstream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#ifdef _WIN32
#include <openssl/applink.c>
#endif

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

std::mutex clientSocketsMutex;

bool generateCertificate(const std::string& certFile, const std::string& keyFile) {
    EVP_PKEY* pKey = EVP_PKEY_new();
    RSA* rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    EVP_PKEY_assign_RSA(pKey, rsa);

    X509* x509 = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);  // Valid for one year
    X509_set_pubkey(x509, pKey);

    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"MyCompany", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"localhost", -1, -1, 0);
    X509_set_issuer_name(x509, name); // Self-signed

    X509_sign(x509, pKey, EVP_sha256());

    FILE* fCert = fopen(certFile.c_str(), "wb");
    if (fCert == NULL) return false;
    PEM_write_X509(fCert, x509);
    fclose(fCert);

    FILE* fKey = fopen(keyFile.c_str(), "wb");
    if (fKey == NULL) return false;
    PEM_write_PrivateKey(fKey, pKey, NULL, NULL, 0, NULL, NULL);
    fclose(fKey);

    EVP_PKEY_free(pKey);
    X509_free(x509);

    return true;
}

bool fileExists(const std::string& name) {
    std::ifstream f(name.c_str());
    return f.good();
}

void InitializeSSL() {
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
}

void CleanupSSL() {
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
}

SSL_CTX* CreateContext(const std::string& host) {
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    // Support a wider range of SSL/TLS versions
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    // Disable certificate validation for testing (Not recommended for production)
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);

    std::string certFile = host + ".crt";
    std::string keyFile = host + ".key";

    // Check if certificate files exist, if not generate them
    if (!fileExists(certFile) || !fileExists(keyFile)) {
        if (!generateCertificate(certFile, keyFile)) {
            std::cerr << "Failed to generate certificate for host: " << host << std::endl;
            SSL_CTX_free(ctx);
            return nullptr;
        }
    }

    if (SSL_CTX_use_certificate_file(ctx, certFile.c_str(), SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, keyFile.c_str(), SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return nullptr;
    }

    return ctx;
}

SOCKET ConnectToServer(const std::string& host, const std::string& port) {
    struct addrinfo hints = {}, * res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "Failed to create server socket.\n";
        return INVALID_SOCKET;
    }

    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0) {
        std::cerr << "Getaddrinfo failed.\n";
        closesocket(serverSocket);
        return INVALID_SOCKET;
    }

    if (connect(serverSocket, res->ai_addr, (int)res->ai_addrlen) == SOCKET_ERROR) {
        std::cerr << "Connect to server failed.\n";
        closesocket(serverSocket);
        freeaddrinfo(res);
        return INVALID_SOCKET;
    }

    freeaddrinfo(res);
    return serverSocket;
}

SSL_CTX* CreateSSLContext() {
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

SSL* CreateSSL(SSL_CTX* ctx, SOCKET socket) {
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, socket);
    return ssl;
}

void SendHTTPSRequest(SSL* ssl, const std::string& hostname) {
    std::string request =
        "GET / HTTP/1.1\r\n"
        "Host: " + hostname + "\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0\r\n"
        "Connection: close\r\n"
        "\r\n";

    SSL_write(ssl, request.c_str(), request.size());
}

void ReceiveHTTPSResponse(SSL* ssl, SSL* clientSSL) {
    const int bufferSize = 4096;
    char buffer[bufferSize];
    int bytesRead;

    do {
        bytesRead = SSL_read(ssl, buffer, bufferSize - 1);
        if (bytesRead > 0) {
            buffer[bytesRead] = '\0';
            std::cout << "Response from server: " << std::endl;
            std::cout << buffer;

            // Forward the response back to the client (browser)
            SSL_write(clientSSL, buffer, bytesRead);
        }
    } while (bytesRead > 0);
}

void TunnelData(SSL* clientSSL, SSL* serverSSL) {
    std::thread([clientSSL, serverSSL]() {
        char buffer[4096];
        int bytesRead, bytesWritten;
        while ((bytesRead = SSL_read(clientSSL, buffer, sizeof(buffer))) > 0) {
            bytesWritten = SSL_write(serverSSL, buffer, bytesRead);
            if (bytesWritten <= 0) {
                ERR_print_errors_fp(stderr);
                break;
            }
        }
        SSL_shutdown(clientSSL);
        SSL_free(clientSSL);
        }).detach();

        char buffer[4096];
        int bytesRead, bytesWritten;
        while ((bytesRead = SSL_read(serverSSL, buffer, sizeof(buffer))) > 0) {
            bytesWritten = SSL_write(clientSSL, buffer, bytesRead);
            if (bytesWritten <= 0) {
                ERR_print_errors_fp(stderr);
                break;
            }
        }
        SSL_shutdown(serverSSL);
        SSL_free(serverSSL);
}

void ClientHandler(SOCKET clientSocket, SSL_CTX* ctx) {
    char buffer[1024];
    int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
    if (bytesReceived > 0) {
        buffer[bytesReceived] = '\0';
        std::cout << "Received request:\n" << buffer << std::endl;

        if (strstr(buffer, "CONNECT") != nullptr) {
            std::string response = "HTTP/1.1 200 Connection Established\r\n\r\n";
            send(clientSocket, response.c_str(), response.length(), 0);

            SSL* clientSSL = SSL_new(ctx);
            SSL_set_fd(clientSSL, clientSocket);

            std::string host = "www.baidu.com";
            std::string port = "443";
            SOCKET serverSocket = ConnectToServer(host, port);

            SSL_CTX* clientCtx = CreateSSLContext();
            SSL* serverSSL = CreateSSL(clientCtx, serverSocket);

            if (SSL_accept(clientSSL) <= 0 || SSL_connect(serverSSL) <= 0) {
                std::cerr << "SSL handshake failed.\n";
                ERR_print_errors_fp(stderr);
                SSL_free(clientSSL);
                SSL_free(serverSSL);
                SSL_CTX_free(clientCtx);
                closesocket(serverSocket);
                closesocket(clientSocket);
                return;
            }

            // Monitor traffic and send response back to the browser
            SendHTTPSRequest(serverSSL, host);
            ReceiveHTTPSResponse(serverSSL, clientSSL);

            TunnelData(clientSSL, serverSSL);
        }
        else {
            std::cerr << "Received non-CONNECT request.\n";
        }
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

    SSL_CTX* ctx = CreateContext("localhost");
    if (!ctx) {
        std::cerr << "SSL context creation failed.\n";
        return 1;
    }

    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "Failed to create server socket.\n";
        return 1;
    }

    sockaddr_in serverAddr = {};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddr.sin_port = htons(8080);

    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR ||
        listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Network setup failed.\n";
        closesocket(serverSocket);
        return 1;
    }

    std::cout << "Server listening on port 8080...\n";
    while (true) {
        SOCKET clientSocket = accept(serverSocket, nullptr, nullptr);
        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "Accept failed.\n";
            continue;
        }
        std::thread(ClientHandler, clientSocket, ctx).detach();
    }

    closesocket(serverSocket);
    SSL_CTX_free(ctx);
    CleanupSSL();
    WSACleanup();

    return 0;
}
