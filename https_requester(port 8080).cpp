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

// 初始化OpenSSL
void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// 清理OpenSSL资源
void cleanup_openssl() {
    EVP_cleanup();
}

// 创建SSL上下文
SSL_CTX* create_ssl_context() {
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        cerr << "无法创建SSL上下文" << endl;
        ERR_print_errors_fp(stderr);
    }
    return ctx;
}

// 建立SSL连接
SSL* connect_ssl(SSL_CTX* ctx, const char* hostname, SOCKET sock) {
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    // 设置SNI扩展
    SSL_set_tlsext_host_name(ssl, hostname);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
    return ssl;
}



// 接收HTTP响应
string receive_http_response(SSL* ssl) {
    const int BUFFER_SIZE = 918200;
    char buffer[BUFFER_SIZE];
    string response;

    int bytes;
    do {
        bytes = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            response.append(buffer);
        }
    } while (bytes > 0);

    return response;
}

// 发送HTTP请求
void react(SSL* ssl, string request) {
    // 发送搜索请求
    SSL_write(ssl, request.c_str(), request.length());

    // 接收响应数据
    string response = receive_http_response(ssl);

    // 打印响应头
    size_t header_end = response.find("\r\n\r\n");
    if (header_end != string::npos) {
        cout << "=== 响应头 ===" << endl;
        cout << response.substr(0, header_end) << endl;
    }

    // 打印响应体（HTML内容）
    if (header_end != string::npos && response.length() > header_end + 4) {
        cout << "\n=== 网页内容 ===" << endl;
        cout << response.substr(header_end + 4) << endl;
    }
}

int main() {
    // 初始化Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cerr << "WSAStartup失败" << endl;
        return 1;
    }

    // 初始化OpenSSL
    init_openssl();
    SSL_CTX* ctx = create_ssl_context();

    // 配置SSL上下文
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr); // 跳过证书验证（仅用于测试）
    SSL_CTX_set_options(ctx, SSL_OP_ALL);

    // 创建TCP套接字
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        cerr << "无法创建套接字" << endl;
        return 1;
    }

    // 解析主机地址
    const char* hostname = "127.0.0.1";
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(8080);

    addrinfo hints{}, * result;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, "8080", &hints, &result) != 0) { // 直接指定端口号为 8080
        cerr << "DNS解析失败" << endl;
        closesocket(sock);
        return 1;
    }

    memcpy(&server_addr, result->ai_addr, sizeof(server_addr));
    freeaddrinfo(result);

    // 建立TCP连接
    if (connect(sock, (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        cerr << "连接服务器失败" << endl;
        closesocket(sock);
        return 1;
    }

    // 建立SSL连接
    SSL* ssl = connect_ssl(ctx, hostname, sock);
    if (!ssl) {
        closesocket(sock);
        SSL_CTX_free(ctx);
        return 1;
    }

    string request = "GET / HTTP/1.1\r\n"
        "Host: " + (string)hostname + "\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
        "Connection: close\r\n\r\n";

    react(ssl, request);

    // 清理资源
    SSL_shutdown(ssl);
    SSL_free(ssl);
    closesocket(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    WSACleanup();

    return 0;
}
