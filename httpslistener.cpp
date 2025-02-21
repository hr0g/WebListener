#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/rand.h>
#include <zlib.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

using namespace std;

const int PROXY_PORT = 8080;
const char* ROOT_CERT = "root-cert.pem";
const char* ROOT_KEY = "root-key.pem";

SSL_CTX* ssl_ctx;
X509_NAME* root_issuer_name = nullptr;
vector<unique_ptr<mutex>> openssl_locks;

// PREGENERATED PRINTABLE CHARACTER TABLE
bool is_printable[256] = { false };

void init_print_table() {
    for (int i = 0; i < 256; ++i) {
        is_printable[i] = isprint(i) || i == '\n' || i == '\r';
    }
}

enum ContentEncoding {
    ENCODING_RAW,
    ENCODING_GZIP,
    ENCODING_BROTLI,
    ENCODING_DEFLATE
};

void openssl_locking_callback(int mode, int n, const char* file, int line) {
    if (mode & CRYPTO_LOCK) {
        openssl_locks[n]->lock();
    }
    else {
        openssl_locks[n]->unlock();
    }
}

void init_openssl_thread_safety() {
    CRYPTO_set_locking_callback(openssl_locking_callback);
    CRYPTO_THREADID_set_callback([](CRYPTO_THREADID* id) {
        CRYPTO_THREADID_set_numeric(id, GetCurrentThreadId());
        });

    const int num_locks = CRYPTO_num_locks();
    openssl_locks.clear();
    for (int i = 0; i < num_locks; ++i) {
        openssl_locks.emplace_back(make_unique<mutex>());
    }
}

void add_extension(X509* cert, int nid, const char* value) {
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, nullptr, nullptr, X509V3_CTX_TEST);

    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }
}

X509* generate_cert(EVP_PKEY* root_key, const string& host, EVP_PKEY** out_pkey) {
    X509* new_cert = X509_new();
    if (!new_cert) return nullptr;

    unsigned char serial_bytes[16];
    if (RAND_bytes(serial_bytes, sizeof(serial_bytes)) != 1) {
        X509_free(new_cert);
        return nullptr;
    }
    BIGNUM* bn = BN_bin2bn(serial_bytes, sizeof(serial_bytes), nullptr);
    ASN1_INTEGER_set(X509_get_serialNumber(new_cert), (long)bn);
    BN_free(bn);

    X509_gmtime_adj(X509_get_notBefore(new_cert), 0);
    X509_gmtime_adj(X509_get_notAfter(new_cert), 30 * 86400);

    X509_NAME* name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        (const unsigned char*)host.c_str(), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
        (const unsigned char*)"Secure Proxy", -1, -1, 0);
    X509_set_subject_name(new_cert, name);
    X509_set_issuer_name(new_cert, root_issuer_name);
    X509_NAME_free(name);

    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
        EVP_PKEY_generate(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        X509_free(new_cert);
        return nullptr;
    }
    EVP_PKEY_CTX_free(ctx);
    X509_set_pubkey(new_cert, pkey);

    size_t dot_pos = host.find('.');
    string san = "DNS:" + host;
    if (dot_pos != string::npos && dot_pos < host.length() - 1) {
        string base_domain = host.substr(dot_pos + 1);
        san += ", DNS:*." + base_domain;
    }
    add_extension(new_cert, NID_subject_alt_name, san.c_str());
    add_extension(new_cert, NID_basic_constraints, "critical,CA:FALSE");
    add_extension(new_cert, NID_key_usage, "critical,digitalSignature,keyEncipherment");
    add_extension(new_cert, NID_ext_key_usage, "serverAuth,clientAuth");
    add_extension(new_cert, NID_authority_key_identifier, "keyid");

    if (!X509_sign(new_cert, root_key, EVP_sha256())) {
        X509_free(new_cert);
        EVP_PKEY_free(pkey);
        return nullptr;
    }

    *out_pkey = pkey;
    return new_cert;
}

string decode_content(const char* data, size_t len, ContentEncoding encoding) {
    if (encoding == ENCODING_RAW) return string(data, len);

    if (encoding == ENCODING_GZIP) {
        z_stream zs;
        memset(&zs, 0, sizeof(zs));
        if (inflateInit2(&zs, 16 + MAX_WBITS) != Z_OK) return "";

        zs.next_in = (Bytef*)data;
        zs.avail_in = len;

        char buffer[4096];
        string result;
        int ret;
        do {
            zs.next_out = (Bytef*)buffer;
            zs.avail_out = sizeof(buffer);
            ret = inflate(&zs, Z_NO_FLUSH);
            if (result.size() < zs.total_out)
                result.append(buffer, zs.total_out - result.size());
        } while (ret == Z_OK);

        inflateEnd(&zs);
        return result;
    }

    return "[Unsupported Encoding]";
}

void forward_data(SSL* src, SSL* dst, const string& tag) {
    char buf[4096];
    int bytes;
    ContentEncoding encoding = ENCODING_RAW;
    bool is_binary = false;
    string headers;

    while ((bytes = SSL_read(src, buf, sizeof(buf))) > 0) {
        if (tag.find("server->client") != string::npos && headers.empty()) {
            headers.append(buf, bytes);
            size_t header_end = headers.find("\r\n\r\n");
            if (header_end != string::npos) {
                size_t ce_pos = headers.find("Content-Encoding: ");
                if (ce_pos != string::npos) {
                    string ce_value = headers.substr(ce_pos + 18,
                        headers.find("\r\n", ce_pos) - ce_pos - 18);
                    if (ce_value.find("gzip") != string::npos) {
                        encoding = ENCODING_GZIP;
                    }
                }

                size_t ct_pos = headers.find("Content-Type: ");
                if (ct_pos != string::npos) {
                    string ct_value = headers.substr(ct_pos + 14,
                        headers.find("\r\n", ct_pos) - ct_pos - 14);
                    if (ct_value.find("image") != string::npos ||
                        ct_value.find("octet-stream") != string::npos) {
                        is_binary = true;
                    }
                }
            }
        }

        string decoded;
        if (is_binary) {
            decoded = "[Binary Data]";
        }
        else {
            decoded = decode_content(buf, bytes, encoding);

            string clean_text;
            for (size_t i = 0; i < decoded.size(); ++i) {
                unsigned char uc = static_cast<unsigned char>(decoded[i]);
                if (is_printable[uc]) {
                    clean_text += decoded[i];
                }
                else {
                    clean_text += '.';
                }
            }
            decoded = clean_text;
        }

        cout << "============ DECRYPTED CONTENT (" << tag << ") ============\n"
            << decoded << "\n\n";

        SSL_write(dst, buf, bytes);
    }
    SSL_shutdown(src);
    SSL_shutdown(dst);
}

void handle_https(SOCKET client_sock, const string& host) {
    SSL* client_ssl = nullptr;
    X509* fake_cert = nullptr;
    EVP_PKEY* fake_pkey = nullptr;
    SOCKET server_sock = INVALID_SOCKET;
    SSL_CTX* server_ctx = nullptr;
    SSL* server_ssl = nullptr;
    addrinfo* res = nullptr;

    client_ssl = SSL_new(ssl_ctx);
    SSL_set_fd(client_ssl, client_sock);

    EVP_PKEY* root_key = SSL_CTX_get0_privatekey(ssl_ctx);
    fake_cert = generate_cert(root_key, host, &fake_pkey);

    if (!fake_cert || SSL_use_certificate(client_ssl, fake_cert) <= 0 ||
        SSL_use_PrivateKey(client_ssl, fake_pkey) <= 0 ||
        !SSL_check_private_key(client_ssl))
    {
        cerr << "证书初始化失败: " << ERR_error_string(ERR_get_error(), nullptr) << endl;
        if (server_ssl) SSL_free(server_ssl);
        if (server_ctx) SSL_CTX_free(server_ctx);
        if (server_sock != INVALID_SOCKET) closesocket(server_sock);
        if (client_ssl) SSL_free(client_ssl);
        if (fake_cert) X509_free(fake_cert);
        if (fake_pkey) EVP_PKEY_free(fake_pkey);
        if (res) freeaddrinfo(res);
        closesocket(client_sock);
    }

    STACK_OF(X509)* chain = sk_X509_new_null();
    X509* root_cert = SSL_CTX_get0_certificate(ssl_ctx);
    sk_X509_push(chain, X509_dup(root_cert));
    SSL_set1_chain(client_ssl, chain);
    sk_X509_pop_free(chain, X509_free);

    if (SSL_accept(client_ssl) <= 0) {
        cerr << "SSL HANDSHAKE FAILED: " << ERR_error_string(ERR_get_error(), nullptr) << endl;
        if (server_ssl) SSL_free(server_ssl);
        if (server_ctx) SSL_CTX_free(server_ctx);
        if (server_sock != INVALID_SOCKET) closesocket(server_sock);
        if (client_ssl) SSL_free(client_ssl);
        if (fake_cert) X509_free(fake_cert);
        if (fake_pkey) EVP_PKEY_free(fake_pkey);
        if (res) freeaddrinfo(res);
        closesocket(client_sock);
    }

    addrinfo hints{};
    hints.ai_family = AF_INET;
    if (getaddrinfo(host.c_str(), "443", &hints, &res) != 0) {
        cerr << "DNS RESOLUTION FAILED" << endl;
        if (server_ssl) SSL_free(server_ssl);
        if (server_ctx) SSL_CTX_free(server_ctx);
        if (server_sock != INVALID_SOCKET) closesocket(server_sock);
        if (client_ssl) SSL_free(client_ssl);
        if (fake_cert) X509_free(fake_cert);
        if (fake_pkey) EVP_PKEY_free(fake_pkey);
        if (res) freeaddrinfo(res);
        closesocket(client_sock);
    }

    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(server_sock, res->ai_addr, (int)res->ai_addrlen) == SOCKET_ERROR) {
        cerr << "SERVER CONNECTION FAILED" << endl;
        if (server_ssl) SSL_free(server_ssl);
        if (server_ctx) SSL_CTX_free(server_ctx);
        if (server_sock != INVALID_SOCKET) closesocket(server_sock);
        if (client_ssl) SSL_free(client_ssl);
        if (fake_cert) X509_free(fake_cert);
        if (fake_pkey) EVP_PKEY_free(fake_pkey);
        if (res) freeaddrinfo(res);
        closesocket(client_sock);
    }

    server_ctx = SSL_CTX_new(TLS_client_method());
    server_ssl = SSL_new(server_ctx);
    SSL_set_fd(server_ssl, server_sock);
    SSL_set_tlsext_host_name(server_ssl, host.c_str());

    if (SSL_connect(server_ssl) <= 0) {
        cerr << "SERVER SSL CONNECTION FAILED: " << ERR_error_string(ERR_get_error(), nullptr) << endl;
        if (server_ssl) SSL_free(server_ssl);
        if (server_ctx) SSL_CTX_free(server_ctx);
        if (server_sock != INVALID_SOCKET) closesocket(server_sock);
        if (client_ssl) SSL_free(client_ssl);
        if (fake_cert) X509_free(fake_cert);
        if (fake_pkey) EVP_PKEY_free(fake_pkey);
        if (res) freeaddrinfo(res);
        closesocket(client_sock);
    }

    thread(forward_data, client_ssl, server_ssl, "client->server").detach();
    thread(forward_data, server_ssl, client_ssl, "server->client").detach();

    client_ssl = server_ssl = nullptr;
    server_ctx = nullptr;
    server_sock = INVALID_SOCKET;
    freeaddrinfo(res);
    return;

cleanup:
    if (server_ssl) SSL_free(server_ssl);
    if (server_ctx) SSL_CTX_free(server_ctx);
    if (server_sock != INVALID_SOCKET) closesocket(server_sock);
    if (client_ssl) SSL_free(client_ssl);
    if (fake_cert) X509_free(fake_cert);
    if (fake_pkey) EVP_PKEY_free(fake_pkey);
    if (res) freeaddrinfo(res);
    closesocket(client_sock);
}

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    ssl_ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ssl_ctx,
        SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
        SSL_OP_NO_COMPRESSION | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

    if (SSL_CTX_use_certificate_chain_file(ssl_ctx, ROOT_CERT) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ssl_ctx, ROOT_KEY, SSL_FILETYPE_PEM) <= 0 ||
        !SSL_CTX_check_private_key(ssl_ctx))
    {
        cerr << "LOADING ROOT-CERT FAILED: " << ERR_error_string(ERR_get_error(), nullptr) << endl;
        exit(EXIT_FAILURE);
    }

    X509* root_cert = SSL_CTX_get0_certificate(ssl_ctx);
    root_issuer_name = X509_get_subject_name(root_cert);
    SSL_CTX_set_verify_depth(ssl_ctx, 4);

    const char* ciphers =
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "DHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-CHACHA20-POLY1305";
    SSL_CTX_set_cipher_list(ssl_ctx, ciphers);

    SSL_CTX_set_ecdh_auto(ssl_ctx, 1);
    SSL_CTX_set_dh_auto(ssl_ctx, 1);
}

int main() {
    init_print_table();

    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    init_openssl_thread_safety();
    init_openssl();

    SOCKET proxy_sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in proxy_addr{};
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_addr.s_addr = INADDR_ANY;
    proxy_addr.sin_port = htons(PROXY_PORT);

    bind(proxy_sock, (sockaddr*)&proxy_addr, sizeof(proxy_addr));
    listen(proxy_sock, SOMAXCONN);

    cout << "PROXY LISTENING ON (PORT:" << PROXY_PORT << ")" << endl;

    while (true) {
        sockaddr_in client_addr{};
        int addr_len = sizeof(client_addr);
        SOCKET client_sock = accept(proxy_sock, (sockaddr*)&client_addr, &addr_len);

        char buf[4096];
        int bytes = recv(client_sock, buf, sizeof(buf), 0);
        if (bytes <= 0) {
            closesocket(client_sock);
            continue;
        }

        string request(buf, bytes);
        string host;
        size_t host_start = request.find("Host: ");
        if (host_start != string::npos) {
            host_start += 6;
            size_t host_end = request.find("\r\n", host_start);
            if (host_end != string::npos) {
                string host_line = request.substr(host_start, host_end - host_start);
                size_t colon_pos = host_line.find(':');
                host = (colon_pos != string::npos) ?
                    host_line.substr(0, colon_pos) : host_line;
            }
        }

        if (host.empty()) {
            const char* response = "HTTP/1.1 400 Bad Request\r\n\r\nMissing Host Header";
            send(client_sock, response, strlen(response), 0);
            closesocket(client_sock);
            continue;
        }

        const char* established = "HTTP/1.1 200 Connection Established\r\n\r\n";
        send(client_sock, established, strlen(established), 0);
        thread(handle_https, client_sock, host).detach();
    }

    closesocket(proxy_sock);
    WSACleanup();
    EVP_cleanup();
    return 0;
}