// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <string.h>
#include <sys/socket.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <openenclave/host.h>

#define GET_REQUEST "GET / HTTP/1.0\r\n\r\n"
#define CLIENT_REQUEST_PAYLOAD_SIZE 18
#define SERVER_RESPONSE_PAYLOAD_SIZE 194

int create_socket(char* server_name, char* server_port);

// This is the identity validation callback. An TLS connecting party (client or
// server) can verify the passed in "identity" information to decide whether to
// accept an connection reqest
oe_result_t enclave_identity_verifier(oe_identity_t* identity, void* arg)
{
    oe_result_t result = OE_VERIFY_FAILED;

    (void)arg;
    printf("enclave_identity_verifier is called with parsed report:\n");

    // // Check the enclave's security version
    // OE_TRACE_INFO(
    //     "identity.security_version = %d\n", identity->security_version);
    // if (identity->security_version < 1)
    // {
    //     OE_TRACE_ERROR(
    //         "identity.security_version check failed (%d)\n",
    //         identity->security_version);
    //     goto done;
    // }

    // // Dump an enclave's unique ID, signer ID and Product ID. They are
    // // MRENCLAVE, MRSIGNER and ISVPRODID for SGX enclaves.  In a real
    // scenario,
    // // custom id checking should be done here
    // OE_TRACE_INFO("identity->signer_id :\n");
    // for (int i = 0; i < OE_UNIQUE_ID_SIZE; i++)
    //     OE_TRACE_INFO("0x%0x ", (uint8_t)identity->signer_id[i]);

    // OE_TRACE_INFO("\nidentity->signer_id :\n");
    // for (int i = 0; i < OE_SIGNER_ID_SIZE; i++)
    //     OE_TRACE_INFO("0x%0x ", (uint8_t)identity->signer_id[i]);

    // OE_TRACE_INFO("\nidentity->product_id :\n");
    // for (int i = 0; i < OE_PRODUCT_ID_SIZE; i++)
    //     OE_TRACE_INFO("0x%0x ", (uint8_t)identity->product_id[i]);

    result = OE_OK;
done:
    return result;
}

// The return value of verify_callback controls the strategy of the further
// verification process. If verify_callback returns 0, the verification process
// is immediately stopped with "verification failed" state and A verification
// failure alert is sent to the peer and the TLS/SSL handshake is terminated. If
// verify_callback returns 1, the verification process is continued.
int verify_callback(int preverify_ok, X509_STORE_CTX* ctx)
{
    int ret = 1;
    int der_len = 8000;
    unsigned char* der = NULL;
    unsigned char* buff = NULL;
    oe_result_t result = OE_FAILURE;
    X509* crt = NULL;

    // a self-signed certificate is expected
    crt = X509_STORE_CTX_get_current_cert(ctx);
    if (preverify_ok == 0)
    {
        int err = X509_STORE_CTX_get_error(ctx);
        if (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
        {
            printf("X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT\n");
        }
    }

    // convert a cert into a buffer in DER format
    der_len = i2d_X509(crt, NULL);
    printf("der_len=%d\n", der_len);
    buff = (unsigned char*)malloc(der_len);
    if (buff == NULL)
    {
        printf("malloc failed (der_len=%d)\n", der_len);
        goto done;
    }
    printf("i2d_X509 (buff=%p)\n", buff);
    der = buff;

    der_len = i2d_X509(crt, &buff);
    if (der_len < 0)
    {
        printf("i2d_X509 failed(der_len=%d)\n", der_len);
        goto done;
    }

    // Note: i2d_X509() updates the pointer to the buffer so that following the
    // call to i2d_X509(), buff is pointing to the "end" of the data buffer
    // pointed by buff That is, buff = buff + der_len;
    printf(
        "der=%p buff=%p buff moved by %d offset\n",
        der,
        buff,
        (int)(buff - der));

#if 1
    {
        // output the whole cer in DER format
        FILE* file = fopen("./cert.der", "wb");
        fwrite(der, 1, der_len, file);
        fclose(file);
    }
#endif

    // verify tls certificate
    result = oe_verify_tls_cert(der, der_len, enclave_identity_verifier, NULL);
    if (result != OE_OK)
    {
        printf("result=%s\n", oe_result_str(result));
        ret = 0;
        goto done;
    }

done:
    printf(
        "Verifying SGX certificate extensions ... %s\n",
        ret ? "Success" : "Fail");
    return ret;
}

int parse_arguments(
    int argc,
    char** argv,
    char** server_name,
    char** server_port)
{
    int ret = 1;
    const char* option = NULL;
    int param_len = 0;

    if (argc != 3)
        goto print_usage;

    option = "-server:";
    param_len = strlen(option);
    if (strncmp(argv[1], option, param_len) != 0)
        goto print_usage;
    *server_name = (char*)(argv[1] + param_len);

    option = "-port:";
    param_len = strlen(option);
    if (strncmp(argv[2], option, param_len) != 0)
        goto print_usage;
    *server_port = (char*)(argv[2] + param_len);

    printf("server_name=[%s] server_port=[%s]\n", *server_port, *server_port);
    ret = 0;
    goto done;

print_usage:
    printf("Usage: %s -server:<name> -port:<port>\n", argv[0]);
done:
    return ret;
}

// Communicate with TLS server
int communicate_with_server(SSL* ssl)
{
    unsigned char buf[1024];
    int ret = 1;
    int error = 0;
    int len = 0;

    // Write an GET request to the server
    printf("Write to server-->:");
    //	len = sprintf((char *)buf, GET_REQUEST);
    len = snprintf((char*)buf, sizeof(buf) - 1, GET_REQUEST);
    while ((ret = SSL_write(ssl, buf, (size_t)len)) <= 0)
    {
        error = SSL_get_error(ssl, ret);
        if (error == SSL_ERROR_WANT_WRITE)
            continue;
        printf("Failed! SSL_write returned %d\n", error);
        goto done;
    }

    len = ret;
    printf("%d bytes written\n%s", len, (char*)buf);

    // Read the HTTP response from server
    printf("<-- Read from server:\n");
    do
    {
        len = sizeof(buf) - 1;
        memset(buf, 0, sizeof(buf));
        ret = SSL_read(ssl, buf, (size_t)len);
        if (ret <= 0)
        {
            int error = SSL_get_error(ssl, ret);
            if (error == SSL_ERROR_WANT_READ)
                continue;

            printf("Failed! SSL_read returned error=%d\n", error);
            break;
        }

        len = ret;
        printf(" %d bytes read\n%s", len, (char*)buf);
        if (len != SERVER_RESPONSE_PAYLOAD_SIZE) // hard-coded to match server
        {
            printf(
                "ERROR: expected reading %d bytes but only got %d bytes\n",
                SERVER_RESPONSE_PAYLOAD_SIZE,
                len);
            ret = 1;
            goto done;
        }
        else
        {
            printf("Client done reading server data\n");
            ret = 0;
            break;
        }
    } while (1);

    ret = 0;
done:
    return ret;
}

int create_socket(char* server_name, char* server_port)
{
    int sockfd = -1;
    char* addr_ptr = NULL;
    int port = 0;
    struct hostent* host = NULL;
    struct sockaddr_in dest_addr;

    if ((host = gethostbyname(server_name)) == NULL)
    {
        printf("Error: Cannot resolve hostname %s.\n", server_name);
        goto done;
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        printf("Error: Cannot create socket %d.\n", errno);
        goto done;
    }

    port = atoi(server_port);
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    dest_addr.sin_addr.s_addr = *(long*)(host->h_addr);

    memset(&(dest_addr.sin_zero), '\0', 8);
    addr_ptr = inet_ntoa(dest_addr.sin_addr);

    if (connect(
            sockfd, (struct sockaddr*)&dest_addr, sizeof(struct sockaddr)) ==
        -1)
    {
        printf(
            "Error: Cannot connect to host %s [%s] on port %s.\n",
            server_name,
            addr_ptr,
            server_port);
        printf("Error: Cannot create socket %d.\n", errno);
        // close(sockfd); //TODO: need to close this socket
        sockfd = -1;
        goto done;
    }
done:
    return sockfd;
}

int main(int argc, char** argv)
{
    X509* cert = NULL;
    SSL_CTX* ctx = NULL;
    SSL* ssl = NULL;
    int serversocket = 0;
    int ret = 1;
    char* server_name = NULL;
    char* server_port = NULL;
    int error = 0;

    error = parse_arguments(argc, argv, &server_name, &server_port);
    if (error)
    {
        printf("parse input parmeter failed (%d)!\n", error);
        goto done;
    }

    // initialize openssl library and register algorithms
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    SSL_load_error_strings();

    if (SSL_library_init() < 0)
    {
        printf("Could not initialize the OpenSSL library !\n");
        goto done;
    }

    if ((ctx = SSL_CTX_new(TLS_client_method())) == NULL)
    {
        printf("Unable to create a new SSL context from TLS_client_method\n");
        goto done;
    }

    // exclude SSLv2, SSLv3 ,TLS 1.0 and TLS 1.1
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_1);

    // specify the verify_callback for custom verfication
    SSL_CTX_set_verify(
        ctx,
        SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
        &verify_callback);

    if ((ssl = SSL_new(ctx)) == NULL)
    {
        printf("Unable to create a new SSL connection state object\n");
        goto done;
    }

    serversocket = create_socket(server_name, server_port);
    if (serversocket == -1)
    {
        printf(
            "create a socket and initate a TCP connect to server: %s:%s "
            "(errno=%d)\n",
            server_name,
            server_port,
            errno);
        goto done;
    }

    // setup ssl socket and initiate TLS connection with TLS server
    SSL_set_fd(ssl, serversocket);
    if ((error = SSL_connect(ssl)) != 1)
    {
        printf(
            "Error: Could not establish an SSL session ret2=%d "
            "SSL_get_error()=%d\n",
            error,
            SSL_get_error(ssl, error));
        goto done;
    }
    // TODO: print TLS version
    printf("Successfully establish TLS channel\n");

    // start the client server communication
    if ((error = communicate_with_server(ssl)) != 0)
    {
        printf("Failed: communicate_with_server (ret=%d)\n", error);
        goto done;
    }

    // Free the structures we don't need anymore
    SSL_free(ssl);
    // close(server); //TODO: Need to close()
    X509_free(cert);
    SSL_CTX_free(ctx);
    printf(
        "Finished SSL/TLS connection with server:%s:%s\n",
        server_name,
        server_port);

    ret = 0;
done:
    return (ret);
}