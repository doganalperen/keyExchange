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

unsigned char* generate_random_salt(size_t length) {
    unsigned char *salt = malloc(length);
    if (salt == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    if (RAND_bytes(salt, length) != 1) {
        handleErrors();
    }

    return salt;
}

size_t readCiphertextFromFile(const char *filename, char ** buffer) {
    FILE* fptr2;
    fptr2 = fopen(filename, "rb");
    if(fptr2 == NULL) {
        fprintf(stderr, "Cannot open file for reading.\n");
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

void saveCiphertextToFile(const char *filename, unsigned char *encryptedData, size_t secret_len) {
    FILE* fptr;
    fptr = fopen(filename, "wb");
    if(fptr == NULL) {
        fprintf(stderr, "Cannot open file for writing.\n");
        exit(1);
    }
    //print_hex("save ciphertext: ", encryptedData->buffer, encryptedData->size);
    fwrite(encryptedData, secret_len, 1, fptr);
    fclose(fptr);
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

void derive_from_master_secret(unsigned char* secret, size_t secret_len, unsigned char* salt, size_t salt_len, unsigned char** derived_key, size_t key_len) {
    // Buffer for the derived key
    *derived_key = OPENSSL_secure_malloc(key_len);
    EVP_KDF *kdf;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[5], *p = params;

    if ((kdf = EVP_KDF_fetch(NULL, "hkdf", NULL)) == NULL) {
        fprintf(stderr, "EVP_KDF_fetch");
    }
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);    // The kctx keeps a reference so this is safe
    if (kctx == NULL) {
        fprintf(stderr, "EVP_KDF_CTX_new");
    }

    // Build up the parameters for the derivation 
    *p++ = OSSL_PARAM_construct_utf8_string("digest", "sha512", (size_t)7);
    *p++ = OSSL_PARAM_construct_octet_string("salt", salt, salt_len);
    *p++ = OSSL_PARAM_construct_octet_string("key", secret, secret_len);
    *p++ = OSSL_PARAM_construct_octet_string("info", "label", (size_t)5);
    *p = OSSL_PARAM_construct_end();
    if (EVP_KDF_CTX_set_params(kctx, params) <= 0) {
        fprintf(stderr, "EVP_KDF_CTX_set_params");
    }

    // Do the derivation 
    if (EVP_KDF_derive(kctx, *derived_key, key_len, NULL) <= 0) {
        fprintf(stderr, "EVP_KDF_derive");
    }
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
    
    int salt_len = 16;
    unsigned char* salt = generate_random_salt(salt_len);
    salt_len = 16;
    
    EVP_PKEY* static_priv_key = read_and_deserialize_private_key("ec_key.pem");
    unsigned char *salt_signature = NULL;
    size_t salt_signature_len = 0;
    if (sign_message(static_priv_key, salt, salt_len, &salt_signature, &salt_signature_len)) {
        //printf("Salt signed successfully.\n");
        // Clean up
        //OPENSSL_free(salt_signature);
    } else {
        fprintf(stderr, "Error signing salt.\n");
    }

    char *base64_signature;  // Adjust size as needed
    base64_encode(salt_signature, salt_signature_len, &base64_signature);

    char *base64_salt;  // Adjust size as needed
    base64_encode(salt, salt_len, &base64_salt);
    

    printf("{\"salt\": \"%s\", \"signature\": \"%s\"}", base64_salt, base64_signature);

    char* shared;
    size_t shared_size = readCiphertextFromFile("sharedSecret.pem", &shared);

    size_t derived_len = 64;
    unsigned char* derived_key = NULL;
    derive_from_master_secret(shared, shared_size, salt, salt_len, &derived_key, derived_len);
    saveCiphertextToFile("connectionKey.pem", derived_key, derived_len);

    return 0;
}