// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <string.h>
#include "../common/common.h"
#include "../common/tls_server_enc_pubkey.h"

// Compute the sha256 hash of given data.
static int Sha256(const uint8_t* data, size_t data_size, uint8_t sha256[32])
{
    int ret = 0;
    SHA256_CTX ctx;

    ret = SHA256_Init(&ctx);
    if (!ret)
        goto done;

    ret = SHA256_Update(&ctx, data, data_size);
    if (!ret)
        goto done;

    ret = SHA256_Final(sha256, &ctx);
    if (!ret)
        goto done;

    ret = 0;
done:
    return ret;
}

bool verify_mrsigner_openssl(
    char* pem_key_buffer,
    size_t pem_key_buffer_len,
    uint8_t* signer_id_buf,
    size_t signer_id_buf_size)
{
    unsigned char* modulus = NULL;
    const BIGNUM* modulus_bn = NULL;
    char* modulus_raw = NULL;
    size_t modulus_size = 0;
    int res = 0;
    bool ret = false;
    unsigned char* hashed_mrsigner = NULL;
    BIO* bufio = NULL;
    RSA* rsa = NULL;
    int len = 0;
    EVP_PKEY* evp_key = NULL;
    int tmp_size = 0;

    printf(TLS_CLIENT "Verify connecting server's identity\n");
    hashed_mrsigner = (unsigned char*)malloc(signer_id_buf_size);
    if (hashed_mrsigner == NULL)
    {
        printf(TLS_CLIENT "Out of memory\n");
        goto done;
    }
    printf(TLS_CLIENT "signer_id_buf_size=[%lu]\n", signer_id_buf_size);
    printf(TLS_CLIENT "public key buffer size[%lu]\n", pem_key_buffer_len);
    printf(TLS_CLIENT "public key\n[%s]\n", pem_key_buffer);

    // convert a public key in buffer format into a rsa key
    bufio = BIO_new(BIO_s_mem());
    len = BIO_write(bufio, pem_key_buffer, pem_key_buffer_len);
    if (len != pem_key_buffer_len)
    {
        printf(TLS_CLIENT "BIO_write error\n");
        goto done;
    }
    // export rsa key
    evp_key = PEM_read_bio_PUBKEY(bufio, NULL, NULL, NULL);
    rsa = EVP_PKEY_get1_RSA(evp_key);

    // retrieves the length of RSA modulus in bytes
    modulus_size = RSA_size(rsa);
    printf(TLS_CLIENT "modulus_size=%zu\n", modulus_size);
    RSA_get0_key(rsa, &modulus_bn, NULL, NULL);
    if (modulus_bn == NULL)
    {
        // set error
        goto done;
    }
    if (modulus_size != BN_num_bytes(modulus_bn))
    {
        printf(TLS_CLIENT "mismatched modulus size\n");
        goto done;
    }

    modulus = (unsigned char*)malloc(modulus_size);
    if (modulus == NULL)
    {
        printf(TLS_CLIENT "Out of memory\n");
        goto done;
    }

    tmp_size = BN_bn2bin(modulus_bn, modulus);
    if (tmp_size != modulus_size)
        goto done;

    // for (int i=0; i<modulus_byte_count; i++)
    // {
    //     printf("modulus[%d]= 0x%x\n", i, modulus[i]);
    // }

    // (* MRSIGNER stores a SHA256 in little endian implemented natively on x86
    // *) Reverse the modulus and compute sha256 on it.
    for (size_t i = 0; i < modulus_size / 2; i++)
    {
        uint8_t tmp = modulus[i];
        modulus[i] = modulus[modulus_size - 1 - i];
        modulus[modulus_size - 1 - i] = tmp;
    }

    //
    // Calculate the MRSIGNER value which is the SHA256 hash of the
    // little endian representation of the public key modulus. This value
    // is populated by the signer_id sub-field of a parsed oe_report_t's
    // identity field.
    if (Sha256((const uint8_t*)modulus, modulus_size, hashed_mrsigner) != 0)
        goto done;

    if (memcmp(hashed_mrsigner, signer_id_buf, signer_id_buf_size) != 0)
    {
        printf("mrsigner is not equal!\n");
        for (int i = 0; i < signer_id_buf_size; i++)
        {
            printf(
                "0x%x - 0x%x\n",
                (uint8_t)signer_id_buf[i],
                (uint8_t)hashed_mrsigner[i]);
        }
        goto done;
    }
    printf("signer id (MRSIGNER) was successfully validated\n");
    ret = true;
done:
    if (hashed_mrsigner)
        free(hashed_mrsigner);

    if (modulus != NULL)
        free(modulus);

    if (bufio)
        BIO_free(bufio);

    if (rsa)
        RSA_free(rsa);

    if (evp_key)
        EVP_PKEY_free(evp_key);

    return ret;
}
