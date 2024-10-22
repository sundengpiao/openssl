#include <openssl/ssl.h>
#include <openssl/err.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PORT 443
#define BUFFER_SIZE 1024

int main() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_METHOD *method;
    SSL_CTX *ctx;
    int server, client;
    char buffer[BUFFER_SIZE];
    int bytes;

    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    // Load the certificate and private key for the server.
    // Replace "server.crt" and "server.key" with your actual certificate and key files.
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate public key\n");
        exit(1);
    }

    server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) {
        perror("Socket creation error");
        exit(1);
    }

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(1);
    }

    if (listen(server, 3) < 0) {
        perror("Listen failed");
        exit(1);
    }

    printf("Listening on port %d...\n", PORT);

    client = accept(server, (struct sockaddr *)NULL, NULL);
    if (client < 0) {
        perror("Accept failed");
        exit(1);
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client);

    if (SSL_accept(ssl) == -1) {
        perror("SSL accept failed");
        exit(1);
    }

    while ((bytes = SSL_read(ssl, buffer, BUFFER_SIZE - 1)) > 0) {
        buffer[bytes] = '\0';
        //std::cout << "Received: " << buffer << std::endl;
        SSL_write(ssl, buffer, bytes);
    }

    SSL_free(ssl);
    close(client);
    close(server);
    SSL_CTX_free(ctx);

    return 0;
}