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

void saveCiphertextToFile(const char *filename, unsigned char *encryptedData, size_t secret_len) {
    FILE* fptr;
    fptr = fopen(filename, "wb");
    if(fptr == NULL) {
        printf("Cannot open file for writing.\n");
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
        fprintf(stderr, "Error Initiating DigestSign\n");

    // Compute the signature
    if (EVP_DigestSign(mdctx, NULL, signature_len, message, message_len) <= 0)
        fprintf(stderr, "Error Computing Signature Length\n");

    *signature = (unsigned char *)OPENSSL_malloc(*signature_len);
    if (!*signature) fprintf(stderr, "Error Allocating Space For Signature\n");

    if (EVP_DigestSign(mdctx, *signature, signature_len, message, message_len) <= 0)
        fprintf(stderr, "Error Generating Signature\n");

    EVP_MD_CTX_free(mdctx);
    return 1;
}

unsigned char* compute_ecdh_shared_secret(EVP_PKEY *local_key, EVP_PKEY *peer_key, size_t *secret_len) {
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *secret = NULL;

    // Create the context for the key derivation
    ctx = EVP_PKEY_CTX_new(local_key, NULL);
    if (ctx == NULL) handleErrors();

    // Initialize the derivation
    if (EVP_PKEY_derive_init(ctx) <= 0) handleErrors();

    // Provide the peer public key
    if (EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0) handleErrors();

    // Determine the buffer length for the shared secret
    if (EVP_PKEY_derive(ctx, NULL, secret_len) <= 0) handleErrors();

    // Allocate memory for the shared secret
    secret = OPENSSL_malloc(*secret_len);
    if (secret == NULL) handleErrors();

    // Derive the shared secret
    if (EVP_PKEY_derive(ctx, secret, secret_len) <= 0) handleErrors();

    // Clean up
    EVP_PKEY_CTX_free(ctx);

    return secret;
}

void print_hex(const unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

/*void base64_encode(const unsigned char *input, int length, char **output) {
    BIO *bio, *b64;
    BUF_MEM *buffer_ptr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    //BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &buffer_ptr);

    *output = malloc(buffer_ptr->length);

    memcpy(*output, buffer_ptr->data, buffer_ptr->length);
    output[buffer_ptr->length - 1] = '\0';  // NULL terminate the string

    fprintf(stderr, "Base64 length: %lu\n", buffer_ptr->length);

    BIO_free_all(bio);
}*/

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};


char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length) {

    *output_length = 4 * ((input_length + 2) / 3);
    *output_length = *output_length + (*output_length / 64);

    char *encoded_data = malloc(*output_length);
    if (encoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
        if(j%64 == 0) {
            encoded_data[j++] = '\n';
        }
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    return encoded_data;
}


int main(int argc, char *argv[]) {
    init_OpenSSL();
    
    unsigned char request[1024];
    size_t peer_pubkey_len = fread(request, 1, sizeof(request), stdin);

    const unsigned char *p = request;
    EVP_PKEY *pkey_peer = d2i_PUBKEY(NULL, &p, peer_pubkey_len);
    if(pkey_peer == NULL) {
        fprintf(stderr, "Deserialization failed\n");
        return 1;
    }

    /*unsigned char peer_pubkey_buf[2048];  // Buffer to hold the public key
    size_t peer_pubkey_len = fread(peer_pubkey_buf, 1, sizeof(peer_pubkey_buf), stdin);
    
    if (peer_pubkey_len <= 0) {
        fprintf(stderr, "Failed to read public key\n");
        return 1;
    }

    // Load the EC public key from PEM format
    BIO *bio = BIO_new_mem_buf(peer_pubkey_buf, (int)peer_pubkey_len);
    if (!bio) {
        fprintf(stderr, "Failed to create BIO\n");
        return 1;
    }

    EVP_PKEY *pkey_peer = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!pkey_peer) {
        fprintf(stderr, "Failed to load EC public key\n");
        return 1;
    }*/

    EVP_PKEY *pkey = generate_EC_key_pair();
    if(pkey == NULL) printf("EC Key pair not generated\n");

    BIO *bio_mem = NULL;
    char *pem_key = NULL;
    // Create a memory BIO to capture the PEM output
    bio_mem = BIO_new(BIO_s_mem());
    if (!bio_mem) {
        fprintf(stderr, "Failed to create memory BIO\n");
    }

    // Write the public key to the memory BIO in PEM format
    if (!PEM_write_bio_PUBKEY(bio_mem, pkey)) {
        fprintf(stderr, "Failed to write public key in PEM format\n");
    }

    // Extract the PEM data into a string
    size_t pem_len = BIO_get_mem_data(bio_mem, &pem_key);
    if (pem_len <= 0 || !pem_key) {
        fprintf(stderr, "Failed to extract PEM data\n");
    }
    unsigned char *signature = NULL;
    size_t signature_len = 0;
    EVP_PKEY* static_priv_key = read_and_deserialize_private_key("ec_key.pem");
    if (sign_message(static_priv_key, pem_key, pem_len, &signature, &signature_len)) {
        //fprintf(stderr, "Signature generated successfully\n");
    } else {
        fprintf(stderr, "Error signing ephemeral public key.\n");
    }

    unsigned char *secret = NULL;
    size_t secret_len;
    //fprintf(stderr, "DEBUG1\n");
    secret = compute_ecdh_shared_secret(pkey, pkey_peer, &secret_len);
    saveCiphertextToFile("sharedSecret.pem", secret, secret_len);
    /*unsigned char *pubkey_buf_hex = malloc(pubkey_len * 2);
    for(size_t i = 0; i < pubkey_len; i=i+2){
        snprintf(pubkey_buf_hex+i, 3, "%02x", pubkey_buf[i]);
    }*/
    /*unsigned char *signature_hex = malloc(signature_len * 2);
    for(size_t i = 0; i < signature_len; i=i+2){
        snprintf(signature_hex+i, 3, "%02x", signature[i]);
    }*/

    /*char *base64_signature;  // Adjust size as needed
    base64_encode(signature, signature_len, &base64_signature);

    char *base64_pem_key;  // Adjust size as needed
    base64_encode(pem_key, pem_len, &base64_pem_key);*/

    size_t base64_signarure_len = 0;
    char* base64_signature = base64_encode(signature, signature_len, &base64_signarure_len);

    size_t base64_pem_len = 0;
    char* base64_pem_key = base64_encode(pem_key, pem_len, &base64_pem_len);

    printf("{\"eph_public\": \"%s\", \"signature\": \"%s\"}", base64_pem_key, base64_signature);
    //fprintf(stderr, "DEBUG:Signature Len: %lu\n", signature_len);
    //fprintf(stderr, "DEBUG:Base64 Signature Len: %lu\n", strlen(base64_signature));
    //fprintf(stderr, "{\"eph_public\": \"%s\", \"signature\": \"%s\"}\n", pem_key, base64_signature);
    //char trial[512];
    //snprintf(trial, sizeof(trial), "{\"eph_public\": \"%s\", \"signature\": \"%s\"}", base64_pem_key, base64_signature);
    //fprintf(stderr, "\n\n%u\n", (unsigned int)trial[339]);
    return 0;
}