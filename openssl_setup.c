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

EVP_PKEY *generate_EC_key_pair() {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (pctx == NULL) handleErrors();
    if (EVP_PKEY_keygen_init(pctx) <= 0) handleErrors();
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp224r1) <= 0) handleErrors();
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) handleErrors();

    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

X509_REQ* generate_csr(EVP_PKEY *pkey, const char *cn) {
    X509_REQ *csr = X509_REQ_new();
    if (!csr) handleErrors();

    X509_REQ_set_pubkey(csr, pkey);

    X509_NAME *name = X509_REQ_get_subject_name(csr);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)cn, -1, -1, 0);

    if (X509_REQ_sign(csr, pkey, EVP_sha256()) == 0) handleErrors();

    return csr;
}

void saveCiphertextToFile(const char *filename, char *ciphertext) {
    FILE* fptr;
    fptr = fopen(filename, "wb");
    if(fptr == NULL) {
        printf("Cannot open file for writing.\n");
        exit(1);
    }
    fwrite(ciphertext, strlen(ciphertext), 1, fptr);
    fclose(fptr);
}

void serialize_and_save_private_key(EVP_PKEY *pkey, const char* filename) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) handleErrors();

    if (PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL) <= 0) handleErrors();

    char *pem_key = NULL;
    long pem_len = BIO_get_mem_data(bio, &pem_key);
    char *serialized_key = (char*)OPENSSL_secure_malloc(pem_len + 1);
    if (!serialized_key) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    memcpy(serialized_key, pem_key, pem_len);
    serialized_key[pem_len] = '\0';

    BIO_free(bio);
    saveCiphertextToFile(filename, serialized_key);
}

int save_csr_to_file(X509_REQ *csr, const char *filename) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        perror("fopen");
        return 0;
    }

    int ret = PEM_write_X509_REQ(fp, csr);
    fclose(fp);
    return ret;
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

X509* sign_csr(X509_REQ *csr, X509 *ca_cert, EVP_PKEY *ca_key, int days) {
    X509 *cert = X509_new();
    if (!cert) handleErrors();

    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), (long)60*60*24*days);

    X509_set_subject_name(cert, X509_REQ_get_subject_name(csr));
    X509_set_issuer_name(cert, X509_get_subject_name(ca_cert));

    EVP_PKEY *req_pubkey = X509_REQ_get_pubkey(csr);
    X509_set_pubkey(cert, req_pubkey);
    EVP_PKEY_free(req_pubkey);

    if (X509_sign(cert, ca_key, EVP_sha256()) == 0) handleErrors();

    return cert;
}

int save_cert_to_file(const X509 *cert, const char *filename) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        perror("fopen");
        return 0;
    }

    int ret = PEM_write_X509(fp, cert);
    fclose(fp);
    return ret;
}

void createCertificate() {
    // Create a static EC key pair
        EVP_PKEY *static_pkey = generate_EC_key_pair();
        if(static_pkey == NULL) printf("Static EC Key pair not generated\n");

        X509_REQ *csr = generate_csr(static_pkey, "EC User");

        // Save EC key and CSR to disk
        serialize_and_save_private_key(static_pkey, "ec_key.pem");
        if (!save_csr_to_file(csr, "ec_csr.pem")) handleErrors();

        EVP_PKEY* root_key = read_and_deserialize_private_key("ca.key");

        FILE *root_cert_file = fopen("ca.crt", "rb");
        if (!root_cert_file) {
            perror("fopen");
            exit(EXIT_FAILURE);
        }
        X509 *root_cert = PEM_read_X509(root_cert_file, NULL, NULL, NULL);
        fclose(root_cert_file);

        

        // Sign CSR with root key to create EC certificate
        X509 *ec_cert = sign_csr(csr, root_cert, root_key, 365);

        // Save EC certificate to disk
        if (!save_cert_to_file(ec_cert, "ec_cert.pem")) printf("Savecert failed\n");

        EVP_PKEY_free(root_key);
        X509_free(root_cert);
        X509_REQ_free(csr);
        X509_free(ec_cert);
}

int main(int argc, char *argv[]) {
    init_OpenSSL();

    createCertificate();

    return 0;
}