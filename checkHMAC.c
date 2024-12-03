#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/core_names.h>

void init_OpenSSL() {
    // Load the human-readable error strings for libcrypto
    ERR_load_crypto_strings();

    // Load the necessary digest algorithms
    OpenSSL_add_all_algorithms();
}

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    //abort();
}

size_t readCiphertextFromFile(const char *filename, char ** buffer) {
    FILE* fptr2;
    fptr2 = fopen(filename, "rb");
    if(fptr2 == NULL) {
        printf("Cannot open file for reading.\n");
        exit(1);
    }
    fseek(fptr2, 0, SEEK_END);
    size_t encryptedSize = ftell(fptr2);
    fseek(fptr2, 0, SEEK_SET);
    *buffer = malloc(encryptedSize);
    fread(*buffer, 1, encryptedSize, fptr2);
    fclose(fptr2);
    return encryptedSize;
}

unsigned char* create_hmac(const unsigned char *key, int key_len, const unsigned char *data, int data_len, size_t *hmac_len) {
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[2];
    unsigned char *hmac = NULL;

    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac) handleErrors();

    ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) handleErrors();

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA512", 0);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(ctx, key, key_len, params) <= 0) handleErrors();
    if (EVP_MAC_update(ctx, data, data_len) <= 0) handleErrors();

    hmac = (unsigned char*)malloc(EVP_MAC_CTX_get_mac_size(ctx));
    if (!hmac) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    if (EVP_MAC_final(ctx, hmac, hmac_len, EVP_MAC_CTX_get_mac_size(ctx)) <= 0) handleErrors();

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);

    return hmac;
}

EVP_PKEY* read_and_deserialize_private_key(const char* filename) {
    char* key;
    size_t keySize = readCiphertextFromFile(filename, &key);
    //print_hex("read ciphertext: ", encryptedKey.buffer, encryptedKey.size);
    char * pem_key = OPENSSL_secure_malloc(keySize);
    memcpy(pem_key, key, keySize);
    BIO *bio = BIO_new_mem_buf(pem_key, -1);
    if (!bio) handleErrors();

    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey) handleErrors();

    BIO_free(bio);
    return pkey;
}

int sign_message(EVP_PKEY *ec_key, const unsigned char *message, size_t message_len, 
                 unsigned char **signature, size_t *signature_len) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) handleErrors();

    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, ec_key) <= 0)
        handleErrors();

    // Compute the signature
    if (EVP_DigestSign(mdctx, NULL, signature_len, message, message_len) <= 0)
        handleErrors();

    *signature = (unsigned char *)OPENSSL_malloc(*signature_len);
    if (!*signature) handleErrors();

    if (EVP_DigestSign(mdctx, *signature, signature_len, message, message_len) <= 0)
        handleErrors();

    EVP_MD_CTX_free(mdctx);
    return 1;
}

void base64_encode(const unsigned char *input, int length, char **output) {
    BIO *bio, *b64;
    BUF_MEM *buffer_ptr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, input, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &buffer_ptr);

    *output = malloc(buffer_ptr->length);

    memcpy(*output, buffer_ptr->data, buffer_ptr->length);
    //output[buffer_ptr->length - 1] = '\0';  // NULL terminate the string

    BIO_free_all(bio);
}

int main(int argc, char *argv[]) {
    init_OpenSSL();
    
    unsigned char request[256];
    fgets(request, sizeof(request), stdin);

    char *derived_key;
    size_t derived_size = readCiphertextFromFile("connectionKey.pem", &derived_key);
    
    char history[64] = "alperen";
    size_t hmac_len;
    unsigned char* hmac = create_hmac(derived_key, derived_size, (unsigned char*) history, strlen(history), &hmac_len);

    char msg[32];
    size_t msg_len = 0;
    if(strcmp(request, hmac) == 0) {
        snprintf(msg, sizeof(msg), "HMACs match");
        msg_len = strlen(msg);
    }
    else {
        snprintf(msg, sizeof(msg), "HMACs do not match");
        msg_len = strlen(msg);
    };


    EVP_PKEY* static_priv_key = read_and_deserialize_private_key("ec_key.pem");
    unsigned char *msg_signature = NULL;
    size_t msg_signature_len = 0;
    if (sign_message(static_priv_key, msg, msg_len, &msg_signature, &msg_signature_len)) {
        //printf("Salt signed successfully.\n");
        // Clean up
        //OPENSSL_free(msg_signature);
    } else {
        fprintf(stderr, "Error signing salt.\n");
    }

    char *base64_signature;  // Adjust size as needed
    base64_encode(msg_signature, msg_signature_len, &base64_signature);

    char *base64_msg;  // Adjust size as needed
    base64_encode(msg, msg_len, &base64_msg);

    printf("{\"response\": \"%s\", \"signature\": \"%s\"}", msg, base64_signature);

    return 0;
}