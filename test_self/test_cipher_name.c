
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <internal/statem.h>
#include <unistd.h> // For read and write functions on Unix
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>



void print_ctx_cipher(const SSL_CTX *ctx)
{

    //STACK_OF(SSL_CIPHER) *ciphers = SSL_get_ciphers(ssl);
    STACK_OF(SSL_CIPHER) *ciphers = SSL_CTX_get_ciphers(ctx);
    int count = sk_SSL_CIPHER_num(ciphers);

    printf("ctx ciphers : %d\n", count);
    for (int i = 0; i < count && i<6; i++) {
        const SSL_CIPHER *cipher = sk_SSL_CIPHER_value(ciphers, i);
        printf("%s\n", SSL_CIPHER_get_name(cipher));
    }
}

void print_ssl_cipher(const SSL *ssl)
{

    STACK_OF(SSL_CIPHER) *ciphers = SSL_get_ciphers(ssl);
    //STACK_OF(SSL_CIPHER) *ciphers = SSL_CTX_get_ciphers(ctx);
    int count = sk_SSL_CIPHER_num(ciphers);

    printf("ssl ciphers： %d\n", count);
    for (int i = 0; i < count && i<6; i++) {
        const SSL_CIPHER *cipher = sk_SSL_CIPHER_value(ciphers, i);
        printf("%s\n", SSL_CIPHER_get_name(cipher));
    }
}

int main() {

    int nRet = -1;
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();


    {
        SSL_CTX *ctx = SSL_CTX_new(TLS_method());
        if (ctx == NULL) {
            ERR_print_errors_fp(stderr);
            return 1;
        }
        // Set cipher list to include SM2 related ciphers
        if (SSL_CTX_set_cipher_list(ctx, "TLS_SM4_CBC_SM3")) {
            printf("TLS_method SSL_CTX_set_cipher_list TLS_SM4_CBC_SM3 ciphers set successfully.\n");
        } else {
            printf("TLS_method SSL_CTX_set_cipher_list TLS_SM4_CBC_SM3 ciphers set Failed.\n");
            ERR_print_errors_fp(stderr);
        }
        print_ctx_cipher(ctx);
        // Set cipher list to include SM2 related ciphers
        if (SSL_CTX_set_cipher_list(ctx, "SM2-SM4-CBC-SM3")) {
            printf("TLS_method SSL_CTX_set_cipher_list SM2-SM4-CBC-SM3 ciphers set successfully.\n");
        } else {
            printf("TLS_method SSL_CTX_set_cipher_list SM2-SM4-CBC-SM3 ciphers set Failed.\n");
            ERR_print_errors_fp(stderr);
        }
        print_ctx_cipher(ctx);
        // 创建一个SSL对象
        SSL *ssl = SSL_new(ctx);
        if (!ssl) {
            //std::cout << "Error creating SSL object." << std::endl;
            //ERR_print_errors_fp(stderr);
            return 1;
        }
        //TLS_AES_256_GCM_SHA384 
        //SSL_set_cipher_list仅支持STL1.1/2 ECDHE-RSA-AES256-GCM-SHA384
        if ((nRet=SSL_set_cipher_list(ssl, "SM2-SM4-CBC-SM3")) == 0)
        {
            ERR_print_errors_fp(stderr);
            printf("TLS_method SSL_set_cipher_list SM2-SM4-CBC-SM3 ciphers set failed.\n");
        }
        else
        {
            printf("TLS_method SSL_set_cipher_list SM2-SM4-CBC-SM3 ciphers set successfully.\n");
        }
        print_ssl_cipher(ssl);
        if ((nRet=SSL_set_cipher_list(ssl, "TLS_SM4_CBC_SM3")) == 0)
        {
            ERR_print_errors_fp(stderr);
            printf("TLS_method SSL_set_cipher_list TLS_SM4_CBC_SM3 ciphers set failed.\n");
        }
        else
        {
            printf("TLS_method SSL_set_cipher_list TLS_SM4_CBC_SM3 ciphers set successfully.\n");
        }
        print_ssl_cipher(ssl);

        char* pszdata = (char *)SSL_get_cipher(ssl);
        // Cleanup
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    }

    {
        struct ssl_ctx_st *ctx = SSL_CTX_new(SSLv23_method());
        //SSL_CTX *ctx = SSL_CTX_new(TLS_method());
        if (ctx == NULL) {
            ERR_print_errors_fp(stderr);
            return 1;
        }
        // Set cipher list to include SM2 related ciphers
        if (SSL_CTX_set_cipher_list(ctx, "TLS_SM4_CBC_SM3")) {
            printf("SSLv23_method SSL_CTX_set_cipher_list TLS_SM4_CBC_SM3 ciphers set successfully.\n");
        } else {
            printf("SSLv23_method SSL_CTX_set_cipher_list TLS_SM4_CBC_SM3 ciphers set Failed.\n");
            ERR_print_errors_fp(stderr);
        }
        print_ctx_cipher(ctx);
        // Set cipher list to include SM2 related ciphers
        if (SSL_CTX_set_cipher_list(ctx, "SM2-SM4-CBC-SM3")) {
            printf("SSLv23_method SSL_CTX_set_cipher_list SM2-SM4-CBC-SM3 ciphers set successfully.\n");
        } else {
            printf("SSLv23_method SSL_CTX_set_cipher_list SM2-SM4-CBC-SM3 ciphers set Failed.\n");
            ERR_print_errors_fp(stderr);
        }
        print_ctx_cipher(ctx);
        // 创建一个SSL对象
        SSL *ssl = SSL_new(ctx);
        if (!ssl) {
            //std::cout << "Error creating SSL object." << std::endl;
            //ERR_print_errors_fp(stderr);
            return 1;
        }
        //TLS_AES_256_GCM_SHA384 
        //SSL_set_cipher_list仅支持STL1.1/2 ECDHE-RSA-AES256-GCM-SHA384
        if ((nRet=SSL_set_cipher_list(ssl, "SM2-SM4-CBC-SM3")) == 0)
        {
            ERR_print_errors_fp(stderr);
            printf("SSLv23_method SSL_set_cipher_list SM2-SM4-CBC-SM3 ciphers set failed.\n");
        }
        else
        {
            printf("SSLv23_method SSL_set_cipher_list SM2-SM4-CBC-SM3 ciphers set successfully.\n");
        }
        print_ssl_cipher(ssl);
        if ((nRet=SSL_set_cipher_list(ssl, "TLS_SM4_CBC_SM3")) == 0)
        {
            ERR_print_errors_fp(stderr);
            printf("SSLv23_method SSL_set_cipher_list TLS_SM4_CBC_SM3 ciphers set failed.\n");
        }
        else
        {
            printf("SSLv23_method SSL_set_cipher_list TLS_SM4_CBC_SM3 ciphers set successfully.\n");
        }
        print_ssl_cipher(ssl);
        char* pszdata = (char *)SSL_get_cipher(ssl);
        // Cleanup
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    }

    // 创建SSL方法
    const SSL_METHOD *method = TLS_client_method();

    // 创建SSL上下文
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        //std::cout << "Error creating SSL context." << std::endl;
        //ERR_print_errors_fp(stderr);
        return 1;
    }

    // 设置自定义套件
    nRet = SSL_CTX_set_ciphersuites(ctx, "TLS_SM4_CBC_SM3");
    if (nRet == 0)
    {
        ERR_print_errors_fp(stderr);
        printf("TLS_client_method() SSL_CTX_set_ciphersuites set TLS_SM4_CBC_SM3 failed.\n");
    }
    else
    {
        printf("TLS_client_method() SSL_CTX_set_ciphersuites set TLS_SM4_CBC_SM3 successfully.\n");
    }
    print_ctx_cipher(ctx);
    nRet = SSL_CTX_set_ciphersuites(ctx, "SM2-SM4-CBC-SM3");
    if (nRet == 0)
    {
        ERR_print_errors_fp(stderr);
        printf("TLS_client_method() SSL_CTX_set_ciphersuites set SM2-SM4-CBC-SM3 faild.\n");
    }
    else
    {
        printf("TLS_client_method() SSL_CTX_set_ciphersuites set SM2-SM4-CBC-SM3 successfully.\n");
    }
    print_ctx_cipher(ctx);
    // 创建一个SSL对象
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        //std::cout << "Error creating SSL object." << std::endl;
        //ERR_print_errors_fp(stderr);
        return 1;
    }
    //TODO测试算法
    //TLS_AES_256_GCM_SHA384 
    //SSL_set_cipher_list仅支持STL1.1/2 ECDHE-RSA-AES256-GCM-SHA384
    if ((nRet=SSL_set_cipher_list(ssl, "SM2-SM4-CBC-SM3")) == 0)
    {
        ERR_print_errors_fp(stderr);
        printf("TLS_client_method SSL_set_cipher_list SM2-SM4-CBC-SM3 ciphers set failed.\n");
    }
    else
    {
        printf("TLS_client_method SSL_set_cipher_list SM2-SM4-CBC-SM3 ciphers set successfully.\n");
    }
    print_ssl_cipher(ssl);
    if ((nRet=SSL_set_cipher_list(ssl, "TLS_SM4_CBC_SM3")) == 0)
    {
        ERR_print_errors_fp(stderr);
        printf("TLS_client_method SSL_set_cipher_list TLS_SM4_CBC_SM3 ciphers set failed.\n");
    }
    else
    {
        printf("TLS_client_method SSL_set_cipher_list TLS_SM4_CBC_SM3 ciphers set successfully.\n");
    }
    print_ctx_cipher(ctx);
    

    
    // 创建一个套接字连接
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        //std::cout << "Error creating socket." << std::endl;
        return 1;
    }

    // 设置服务器地址和端口
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(443); // HTTPS默认端口
    inet_pton(AF_INET, "www.baidu.com", &server_addr.sin_addr);

    // 连接到服务器
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        //std::cout << "Error connecting to the server." << std::endl;
        return 1;
    }

    // 将套接字设置为SSL对象的BIO
    BIO *bio = BIO_new_socket(sock, BIO_NOCLOSE);
    SSL_set_bio(ssl, bio, bio);

    // 进行TLS握手
    if (SSL_connect(ssl) == -1) {
        //std::cout << "Error during TLS handshake." << std::endl;
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // 发送请求
    const char *request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    SSL_write(ssl, request, strlen(request));

    // 接收响应
    char buffer[4096];
    int bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        //std::cout << "Received response:\n" << buffer << std::endl;
    }

    // 清理资源
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sock);

    return 0;
}