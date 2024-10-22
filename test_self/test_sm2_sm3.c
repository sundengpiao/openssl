#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

// 函数用于打印 OpenSSL 错误信息
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
    
    EC_KEY *ec_key = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    unsigned char *plaintext = (unsigned char *)"This is a test message.";
    size_t plaintext_len = strlen((char *)plaintext);
    unsigned char *signature = NULL;
    size_t signature_len = 0;
    unsigned char *verified_signature = NULL;
    size_t verified_signature_len = 0;

    // 初始化 OpenSSL 库
    OpenSSL_add_all_algorithms();
    OPENSSL_init_crypto(0, NULL);

    // Generate SM2 key pair
    ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    //ec_key = OSSL_EcKey_from_curve_name("sm2p256v1");
    if (!EC_KEY_generate_key(ec_key)) {
        fprintf(stderr, "Failed to generate SM2 key pair.\n");
        goto cleanup;
    }
    pkey = EVP_PKEY_new();
    if (!EVP_PKEY_assign_EC_KEY(pkey, ec_key)) {
        fprintf(stderr, "Failed to assign EC_KEY to EVP_PKEY.\n");
        goto cleanup;
    }

    // // Convert EC_KEY to EVP_PKEY
    // pkey = EVP_PKEY_new();
    // if (!EVP_PKEY_assign_EC_KEY(pkey, ec_key)) {
    //     fprintf(stderr, "Failed to assign EC_KEY to EVP_PKEY.\n");
    //     goto cleanup;
    // }

    // // 生成 ECDSA 密钥对
    // pkey = EVP_PKEY_new();
    // if (!pkey) {
    //     fprintf(stderr, "Failed to create EVP_PKEY.\n");
    //     handle_openssl_errors();
    //     goto cleanup;
    // }
    // FILE *file;
    // if (!(file = fopen("sm2_key.pem", "r"))) {
    // //if (!(file = fopen("ecdsa_key.pem", "r"))) {
    //     fprintf(stderr, "Failed to open file.\n");
    //     // 适当添加错误处理或退出程序的代码
    //     return -1; // 假设这是一个合适的返回值
    // }
    // if (!PEM_read_PrivateKey(file, &pkey, NULL, NULL)) {
    //     fprintf(stderr, "Failed to read private key.\n");
    //     handle_openssl_errors();
    //     goto cleanup;
    // }
    //     // 操作结束后关闭文件
    // fclose(file);

    // 创建 MD_CTX 上下文
    md_ctx = EVP_MD_CTX_create();
    if (!md_ctx) {
        fprintf(stderr, "Failed to create MD_CTX.\n");
        handle_openssl_errors();
        goto cleanup;
    }

    // 签名数据sm3
    if (1 != EVP_DigestSignInit(md_ctx, NULL, EVP_sm3(), NULL, pkey)) {
        fprintf(stderr, "Failed to initialize digest sign.\n");
        handle_openssl_errors();
        goto cleanup;
    }

    if (1 != EVP_DigestSignUpdate(md_ctx, plaintext, plaintext_len)) {
        fprintf(stderr, "Failed to update digest sign.\n");
        handle_openssl_errors();
        goto cleanup;
    }

    signature_len = EVP_PKEY_size(pkey);
    signature = (unsigned char *)malloc(signature_len);
    if (!signature) {
        fprintf(stderr, "Failed to allocate memory for signature.\n");
        goto cleanup;
    }

    if (1 != EVP_DigestSignFinal(md_ctx, signature, &signature_len)) {
        fprintf(stderr, "Failed to finalize digest sign.\n");
        handle_openssl_errors();
        goto cleanup;
    }

    // 验证签名
    if (1 != EVP_DigestVerifyInit(md_ctx, NULL, EVP_sm3(), NULL, pkey)) {
        fprintf(stderr, "Failed to initialize digest verify.\n");
        handle_openssl_errors();
        goto cleanup;
    }

    if (1 != EVP_DigestVerifyUpdate(md_ctx, plaintext, plaintext_len)) {
        fprintf(stderr, "Failed to update digest verify.\n");
        handle_openssl_errors();
        goto cleanup;
    }

    if (1 != EVP_DigestVerifyFinal(md_ctx, signature, signature_len)) {
        fprintf(stderr, "Verification failed.\n");
        goto cleanup;
    }

    printf("Signature verification successful.\n");

cleanup:
    free(signature);
    EVP_MD_CTX_destroy(md_ctx);
    EC_KEY_free(ec_key);
    EVP_PKEY_free(pkey);
    return 0;
}