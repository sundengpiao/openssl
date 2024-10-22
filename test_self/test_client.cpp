#include <openssl/ssl.h>
#include <openssl/err.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <internal/sockets.h>

#define PORT 443
//#define PORT 5555
#define VPN_HOST    "127.0.0.1"
//#define VPN_HOST    "192.168.186.133"
#define BUFFER_SIZE 1024

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
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD *method;
    SSL_CTX *ctx;
    int client;
    char buffer[BUFFER_SIZE];
    int bytes;

    method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    client = socket(AF_INET, SOCK_STREAM, 0);
    if (client < 0) {
        perror("Socket creation error");
        exit(1);
    }

    print_ctx_cipher(ctx);
    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(PORT);
    inet_pton(AF_INET, VPN_HOST, &servaddr.sin_addr);

    if (connect(client, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("Connection failed");
        exit(1);
    }

    char* pszSSL_cipher = NULL;
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client);
    print_ssl_cipher(ssl);
    if (0 == SSL_set_cipher_list(ssl, "SM2-SM4-CCM-SM3"))
    {
        perror("SSL set cipher list failed");
    }
    else
    {
        printf("SSL set SM2-SM4-CCM-SM3 cipher list success!");
        print_ssl_cipher(ssl);
    }
    // if (0 == SSL_set_cipher_list(ssl, "TLS_AES_256_GCM_SHA384"))
    // {
    //     ERR_print_errors_fp(stderr);ls
    //     perror("SSL set cipher list failed");
    // }
    print_ssl_cipher(ssl);
    
    // 进行 SSL 握手
    int ret = SSL_connect(ssl);
    if (ret != 1) {
        // 获取错误码
        int error_code = SSL_get_error(ssl, ret);
        int sockerr = get_last_socket_error();
        switch (error_code) {
            case SSL_ERROR_ZERO_RETURN:
                printf("Connection was closed gracefully by peer.\n");
                break;
            case SSL_ERROR_WANT_READ:
                printf("The operation did not complete (read).\n");
                break;
            case SSL_ERROR_WANT_WRITE:
                printf("The operation did not complete (write).\n");
                break;
            case SSL_ERROR_WANT_CONNECT:
                printf("A connect() call did not complete.\n");
                break;
            case SSL_ERROR_SYSCALL:
                printf("A system call error occurred.\n");
                break;
            case SSL_ERROR_SSL:
                // 获取具体的 SSL 错误码;
                if (error_code == SSL_AD_INTERNAL_ERROR) {
                    printf("Internal error occurred.\n");
                } else {
                    printf("SSL error occurred: %u\n", error_code);
                }
                break;
            default:
                printf("An unknown error occurred.\n");
                break;
        }
        //失败退出
        exit(-1);
    } else {
        printf("SSL connection established successfully.\n");
    }
    pszSSL_cipher = (char *)SSL_get_cipher(ssl);
    printf("current cipher: %s\n", pszSSL_cipher);
    printf("Enter data to send: ");
    fgets(buffer, BUFFER_SIZE, stdin);  // 读取一行字符
    buffer[strcspn(buffer, "\n")] = 0;      // 去除换行符123456
    //std::cin.getline(buffer, BUFFER_SIZE);

    SSL_write(ssl, buffer, strlen(buffer));

    while ((bytes = SSL_read(ssl, buffer, BUFFER_SIZE - 1)) > 0) {
        buffer[bytes] = '\0';
        printf("Received: %s\n",buffer);
    }

    SSL_free(ssl);
    close(client);
    SSL_CTX_free(ctx);

    return 0;
}