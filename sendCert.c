#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>

void init_OpenSSL() {
    // Load the human-readable error strings for libcrypto
    ERR_load_crypto_strings();

    // Load the necessary digest algorithms
    OpenSSL_add_all_algorithms();
}

int main(int argc, char *argv[]) {
    init_OpenSSL();

    FILE *fp = fopen("ec_cert.pem", "rb");
    if (!fp) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    X509 *static_pkey_cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!static_pkey_cert) printf("Static Public Key Certificate Read Failed\n");

    BIO *bio_mem = BIO_new(BIO_s_mem());
    if (!bio_mem) {
        fprintf(stderr, "Error creating BIO\n");
        X509_free(static_pkey_cert);
        return 1;
    }

    // Write the certificate to the BIO in PEM format
    if (!PEM_write_bio_X509(bio_mem, static_pkey_cert)) {
        fprintf(stderr, "Error writing certificate to BIO\n");
        BIO_free(bio_mem);
        X509_free(static_pkey_cert);
        return 1;
    }

    // Get the length of the PEM data
    int pem_len = BIO_pending(bio_mem);

    // Allocate memory for the PEM string
    unsigned char *pem_data = (unsigned char *)malloc(pem_len + 1);
    if (!pem_data) {
        fprintf(stderr, "Error allocating memory for PEM data\n");
        BIO_free(bio_mem);
        X509_free(static_pkey_cert);
        return 1;
    }

    // Read the PEM data from the BIO into the buffer
    if (BIO_read(bio_mem, pem_data, (int)pem_len) <= 0) {
        fprintf(stderr, "Error reading PEM data\n");
        free(pem_data);
        BIO_free(bio_mem);
        X509_free(static_pkey_cert);
        return 1;
    }


    
    printf("{\"cert\": \"%s\", \"cert_len\": \"%d\"}", pem_data, pem_len);
    //printf("%s", pem_data);

    return 0;
}