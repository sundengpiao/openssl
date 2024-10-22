#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <internal/statem.h>

#define PORT 443
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


static int get_optional_pkey_id(const char *pkey_name)
{
    const EVP_PKEY_ASN1_METHOD *ameth;
    ENGINE *tmpeng = NULL;
    int pkey_id = 0;
    ameth = EVP_PKEY_asn1_find_str(&tmpeng, pkey_name, -1);
    if (ameth) {
        if (EVP_PKEY_asn1_get0_info(&pkey_id, NULL, NULL, NULL, NULL,
                                    ameth) <= 0)
            pkey_id = 0;
    }
    //tls_engine_finish(tmpeng);
    return pkey_id;
}

void handle_openssl_errors() {
    char errbuf[120];
    ERR_load_crypto_strings();
    while ((long) ERR_peek_error()) {
        ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
        fprintf(stderr, "%s\n", errbuf);
    }
    ERR_free_strings();
}

int main() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD *method;
    SSL_CTX *ctx;
    int server, client;
    char buffer[BUFFER_SIZE];
    int bytes;

    // {
    //     EVP_PKEY *pkey = NULL;
    //     EC_KEY *ec_key = NULL;
    //     unsigned char *plaintext = (unsigned char *)"This is a test message.";
    //     size_t plaintext_len = strlen((char *)plaintext);
    //     unsigned char *ciphertext = NULL;
    //     size_t ciphertext_len = 0;
    //     unsigned char *decryptedtext = NULL;
    //     size_t decryptedtext_len = 0;

    //     // Initialize OpenSSL library
    //     OPENSSL_init_crypto(0, NULL);

    //     // Generate SM2 key pair
    //     ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    //     //ec_key = OSSL_EcKey_from_curve_name("sm2p256v1");
    //     if (!EC_KEY_generate_key(ec_key)) {
    //         fprintf(stderr, "Failed to generate SM2 key pair.\n");
    //         goto cleanup;
    //     }

    //     // Convert EC_KEY to EVP_PKEY
    //     pkey = EVP_PKEY_new();
    //     if (!EVP_PKEY_assign_EC_KEY(pkey, ec_key)) {
    //         fprintf(stderr, "Failed to assign EC_KEY to EVP_PKEY.\n");
    //         goto cleanup;
    //     }

    //     // Encrypt plaintext using SM2 public key
    //     ciphertext_len = EVP_PKEY_size(pkey);
    //     ciphertext = (unsigned char *)malloc(ciphertext_len + 1);
    //     if (!EVP_PKEY_encrypt(pkey, ciphertext, &ciphertext_len, plaintext, plaintext_len)) {
    //         fprintf(stderr, "Failed to encrypt plaintext.\n");
    //         goto cleanup;
    //     }

    //     // Decrypt ciphertext using SM2 private key
    //     decryptedtext_len = plaintext_len;
    //     decryptedtext = (unsigned char *)malloc(decryptedtext_len + 1);
    //     if (!EVP_PKEY_decrypt(pkey, decryptedtext, &decryptedtext_len, ciphertext, ciphertext_len)) {
    //         fprintf(stderr, "Failed to decrypt ciphertext.\n");
    //         goto cleanup;
    //     }

    //     // Verify decryption
    //     if (memcmp(plaintext, decryptedtext, plaintext_len) != 0) {
    //         fprintf(stderr, "Decryption verification failed.\n");
    //         goto cleanup;
    //     }

    //     printf("Encryption and decryption successful.\n");

    // cleanup:
    //     free(ciphertext);
    //     free(decryptedtext);
    //     EVP_PKEY_free(pkey);
    //     EC_KEY_free(ec_key);
    // }
    
    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    // Load the certificate and private key for the server.
    // Replace "server.crt" and "server.key" with your actual certificate and key files.
    if (SSL_CTX_use_certificate_file(ctx, "server.cer", SSL_FILETYPE_PEM) <= 0) {
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
    //print_ctx_cipher(ctx);
    char *pszSSL_cipher = NULL;
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
    // pszSSL_cipher = (char *)SSL_get_cipher(ssl);
    //const EVP_CIPHER *cipher = EVP_sm4();
    //get_optional_pkey_id(SN_sm4_gcm);
    // get_optional_pkey_id(SN_sm3);
    // get_optional_pkey_id(SN_sm2);
    // get_optional_pkey_id(SN_SM2_with_SM3);
    // get_optional_pkey_id(SN_sm3WithRSAEncryption);
    // get_optional_pkey_id(SN_rsa);
    
    int ret = SSL_accept(ssl);
    if (ret != 1) {
        // 获取错误码
        int error_code = SSL_get_error(ssl, ret);
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
                // 获取具体的 SSL 错误码
                printf("SSL error occurred: %d\n", error_code);
                
                break;
            default:
                printf("An unknown error occurred.\n");
                break;
        }
    } else {
        printf("SSL connection established successfully.\n");
    }
    pszSSL_cipher = (char *)SSL_get_cipher(ssl);
    printf("current cipher:%s\n", pszSSL_cipher);
    
    while ((bytes = SSL_read(ssl, buffer, BUFFER_SIZE - 1)) > 0) {
        buffer[bytes] = '\0';
        printf("Received: %s\n", buffer);
        SSL_write(ssl, buffer, bytes);
    }

    SSL_free(ssl);
    close(client);
    close(server);
    SSL_CTX_free(ctx);

    return 0;
}