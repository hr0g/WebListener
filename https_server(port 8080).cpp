#include <iostream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

using namespace std;

const int PORT = 8080;
const char* CERT_FILE = "cert.pem";
const char* KEY_FILE = "key.pem";

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX* create_ssl_context() {
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        cerr << "无法创建SSL上下文" << endl;
        ERR_print_errors_fp(stderr);
    }
    return ctx;
}

void configure_ssl_context(SSL_CTX* ctx) {
    SSL_CTX_set_ecdh_auto(ctx, 1);
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

SOCKET create_server_socket() {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        cerr << "无法创建套接字: " << WSAGetLastError() << endl;
        exit(EXIT_FAILURE);
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(sock, (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        cerr << "绑定失败: " << WSAGetLastError() << endl;
        closesocket(sock);
        exit(EXIT_FAILURE);
    }

    if (listen(sock, 10) == SOCKET_ERROR) {
        cerr << "监听失败: " << WSAGetLastError() << endl;
        closesocket(sock);
        exit(EXIT_FAILURE);
    }

    return sock;
}

void handle_client(SSL* ssl) {
    char buf[4096];
    int bytes = SSL_read(ssl, buf, sizeof(buf));
    if (bytes > 0) {
        buf[bytes] = '\0';
        cout << "收到请求:\n" << buf << endl;

        // 构造HTTP响应
        const char* response =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Connection: close\r\n\r\n"
            "<html><body><h1>Hello from SSL Server!</h1></body></html>";

        SSL_write(ssl, response, strlen(response));
    }
}

int main() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    init_openssl();

    SSL_CTX* ctx = create_ssl_context();
    configure_ssl_context(ctx);
    SOCKET server_sock = create_server_socket();

    cout << "服务器正在监听端口 " << PORT << "..." << endl;

    while (true) {
        sockaddr_in client_addr{};
        int addr_len = sizeof(client_addr);
        SOCKET client_sock = accept(server_sock, (sockaddr*)&client_addr, &addr_len);
        if (client_sock == INVALID_SOCKET) {
            cerr << "接受连接失败: " << WSAGetLastError() << endl;
            continue;
        }

        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_sock);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        }
        else {
            handle_client(ssl);
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        closesocket(client_sock);
    }

    closesocket(server_sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    WSACleanup();
    return 0;
}
