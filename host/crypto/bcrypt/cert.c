// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

//#include <ctype.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/safecrt.h>
#include <openenclave/bits/safemath.h>
//#include <openenclave/internal/asn1.h>
#include <openenclave/internal/cert.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/pem.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>
//#include <pthread.h>
//#include <stdio.h>
#include <stdlib.h>
//#include <string.h>
//#include "crl.h"
//#include "ec.h"
//#include "init.h"
#include "bcrypt.h"
#include "rsa.h"

/*
**==============================================================================
**
** Local definitions:
**
**==============================================================================
*/

#define _OE_CERT_CHAIN_LENGTH_ANY 0

static const CERT_CHAIN_POLICY_PARA _OE_DEFAULT_CERT_CHAIN_POLICY = {
    .cbSize = sizeof(CERT_CHAIN_POLICY_PARA),
    .dwFlags = 0};

static const CERT_CHAIN_PARA _OE_DEFAULT_CERT_CHAIN_PARAMS = {
    .cbSize = sizeof(CERT_CHAIN_PARA)};

static const DWORD _OE_DEFAULT_CERT_CHAIN_FLAGS =
    CERT_CHAIN_CACHE_END_CERT | CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY |
    CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL;

inline oe_result_t _check_pem_args(const void* pem_data, size_t pem_size)
{
    oe_result_t result = OE_OK;

    /* Must have pem_size-1 non-zero characters followed by zero-terminator */
    if (!pem_data || !pem_size || pem_size > OE_INT_MAX ||
        strnlen((const char*)pem_data, pem_size) != pem_size - 1)
        OE_RAISE(OE_INVALID_PARAMETER);
done:
    return result;
}

oe_result_t _bcrypt_pem_to_der(
    const void* pem_data,
    size_t pem_size,
    BYTE** der_data,
    DWORD* der_size)
{
    oe_result_t result = OE_UNEXPECTED;
    BYTE* output = NULL;
    DWORD output_size = 0;

    if (der_data)
        *der_data = NULL;

    if (der_size)
        *der_size = 0;

    /* Check parameters */
    if (!der_data || !der_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(_check_pem_args(pem_data, pem_size));

    /* Strip base64 header/footers and convert from PEM format to DER format */
    if (!CryptStringToBinaryA(
            pem_data,
            0,
            CRYPT_STRING_BASE64HEADER,
            NULL,
            &output_size,
            NULL,
            NULL))
    {
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR,
            "CryptStringToBinaryA failed err=%#x\n",
            GetLastError());
    }

    output = (BYTE*)malloc(output_size);
    if (!output)
        OE_RAISE(OE_OUT_OF_MEMORY);

    if (!CryptStringToBinaryA(
            pem_data,
            0,
            CRYPT_STRING_BASE64HEADER,
            output,
            &output_size,
            NULL,
            NULL))
    {
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR,
            "CryptStringToBinaryA failed, err=%#x\n",
            GetLastError());
    }

    *der_size = output_size;
    *der_data = output;
    output = NULL;
    result = OE_OK;

done:
    if (output)
        free(output);

    return result;
}

oe_result_t _get_next_pem_cert(
    const void** pem_read_pos,
    size_t* pem_bytes_remaining,
    char** pem_cert,
    size_t* pem_cert_size)
{
    oe_result_t result = OE_UNEXPECTED;
    const char* cert_begin = NULL;
    const char* cert_end = NULL;
    char* found_pem = NULL;
    size_t found_pem_size = 0;
    const void* pem_data_end = NULL;

    if (pem_cert)
        *pem_cert = NULL;

    if (pem_cert_size)
        *pem_cert_size = 0;

    /* Check parameters */
    if (!pem_read_pos || !pem_bytes_remaining || !pem_cert || !pem_cert_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(_check_pem_args(*pem_read_pos, *pem_bytes_remaining));

    cert_begin = (unsigned char*)strstr(
        (const char*)*pem_read_pos, OE_PEM_BEGIN_CERTIFICATE);

    if (!cert_begin || *cert_begin == '\0')
        return (OE_NOT_FOUND);

    cert_end = (unsigned char*)strstr(
        (const char*)*pem_read_pos, OE_PEM_END_CERTIFICATE);

    if (!cert_end || *cert_begin == '\0' || cert_end <= cert_begin)
        return (OE_NOT_FOUND);

    // PEM cert footer must have at least newline or null-terminator in pem_data
    // buffer to be valid.
    OE_CHECK(
        oe_safe_add_u64(cert_end, OE_PEM_END_CERTIFICATE_LEN + 1, &cert_end));
    OE_CHECK(oe_safe_sub_u64(cert_end, cert_begin, &found_pem_size));

    found_pem = malloc(found_pem_size);
    if (!found_pem)
        OE_RAISE(OE_OUT_OF_MEMORY);

    OE_CHECK(
        oe_memcpy_s(found_pem, found_pem_size, cert_begin, found_pem_size - 1));
    found_pem[found_pem_size - 1] = '\0';

    // Note that pem_cert offset may not equal the starting read_pos,
    // so we infer the remaining_size from the new read_pos
    OE_CHECK(
        oe_safe_add_u64(*pem_read_pos, *pem_bytes_remaining, &pem_data_end));
    OE_CHECK(oe_safe_sub_u64(pem_data_end, cert_end, pem_bytes_remaining));

    *pem_read_pos = cert_end;
    *pem_cert = found_pem;
    *pem_cert_size = found_pem_size;

    result = OE_OK;

done:
    if (result != OE_OK && found_pem)
        free(found_pem);

    return result;
}

/* Randomly generated magic number */
#define OE_CERT_MAGIC 0xbc8e184285de4d2a

typedef struct _cert
{
    uint64_t magic;
    PCERT_CONTEXT cert;
} cert_t;

static void _cert_init(cert_t* impl, PCERT_CONTEXT cert)
{
    if (impl)
    {
        impl->magic = OE_CERT_MAGIC;
        impl->cert = cert;
    }
}

static bool _cert_is_valid(const cert_t* impl)
{
    return impl && (impl->magic == OE_CERT_MAGIC) && impl->cert;
}

static void _cert_clear(cert_t* impl)
{
    if (impl)
    {
        impl->magic = 0;
        impl->cert = NULL;
    }
}

/* Randomly generated magic number */
#define OE_CERT_CHAIN_MAGIC 0xa5ddf70fb28f4480

typedef struct _cert_chain
{
    uint64_t magic;
    PCERT_CHAIN_CONTEXT cert_chain;
    HCERTSTORE cert_store;
} cert_chain_t;

static void _cert_chain_init(
    cert_chain_t* impl,
    PCERT_CHAIN_CONTEXT cert_chain,
    HCERTSTORE cert_store)
{
    if (impl)
    {
        impl->magic = OE_CERT_CHAIN_MAGIC;
        impl->cert_chain = cert_chain;
        impl->cert_store = cert_store;
    }
}

static bool _cert_chain_is_valid(const cert_chain_t* impl)
{
    return impl && (impl->magic == OE_CERT_CHAIN_MAGIC) && impl->cert_chain &&
           impl->cert_store;
}

static void _cert_chain_clear(cert_chain_t* impl)
{
    if (impl)
    {
        impl->magic = 0;
        impl->cert_chain = NULL;
        impl->cert_store = NULL;
    }
}

// static STACK_OF(X509) * _read_cert_chain(const char* pem)
//{
//    STACK_OF(X509)* result = NULL;
//    STACK_OF(X509)* sk = NULL;
//    BIO* bio = NULL;
//    PCERT_CONTEXT cert = NULL;
//
//    // Check parameters:
//    if (!pem)
//        goto done;
//
//    // Create empty X509 stack:
//    if (!(sk = sk_X509_new_null()))
//        goto done;
//
//    while (*pem)
//    {
//        const char* end;
//
//        /* The PEM certificate must start with this */
//        if (strncmp(
//                pem, OE_PEM_CERT_HEADERIFICATE, OE_PEM_CERT_HEADERIFICATE_LEN)
//                !=
//            0)
//            goto done;
//
//        /* Find the end of this PEM certificate */
//        {
//            if (!(end = strstr(pem, OE_PEM_CERT_FOOTERIFICATE)))
//                goto done;
//
//            end += OE_PEM_CERT_FOOTERIFICATE_LEN;
//        }
//
//        /* Skip trailing spaces */
//        while (isspace(*end))
//            end++;
//
//        /* Create a BIO for this certificate */
//        if (!(bio = BIO_new_mem_buf(pem, (int)(end - pem))))
//            goto done;
//
//        /* Read BIO into X509 object */
//        if (!(cert = PEM_read_bio_X509(bio, NULL, 0, NULL)))
//            goto done;
//
//        // Push certificate onto stack:
//        {
//            if (!sk_X509_push(sk, cert))
//                goto done;
//
//            cert = NULL;
//        }
//
//        // Release the bio:
//        BIO_free(bio);
//        bio = NULL;
//
//        pem = end;
//    }
//
//    result = sk;
//    sk = NULL;
//
// done:
//
//    if (bio)
//        BIO_free(bio);
//
//    if (sk)
//        sk_X509_pop_free(sk, X509_free);
//
//    return result;
//}
//
///* Clone the certificate to clear any verification state */
// static PCERT_CONTEXT _clone_cert(PCERT_CONTEXT cert)
//{
//    PCERT_CONTEXT ret = NULL;
//    BIO* out = NULL;
//    BIO* in = NULL;
//    BUF_MEM* mem;
//
//    if (!cert)
//        goto done;
//
//    if (!(out = BIO_new(BIO_s_mem())))
//        goto done;
//
//    if (!PEM_write_bio_X509(out, cert))
//        goto done;
//
//    if (!BIO_get_mem_ptr(out, &mem))
//        goto done;
//
//    if (mem->length > OE_INT_MAX)
//        goto done;
//
//    if (!(in = BIO_new_mem_buf(mem->data, (int)mem->length)))
//        goto done;
//
//    ret = PEM_read_bio_X509(in, NULL, 0, NULL);
//
// done:
//
//    if (out)
//        BIO_free(out);
//
//    if (in)
//        BIO_free(in);
//
//    return ret;
//}
//
//#if OPENSSL_VERSION_NUMBER < 0x10100000L
///* Needed because some versions of OpenSSL do not support X509_up_ref() */
// static int X509_up_ref(PCERT_CONTEXT cert)
//{
//    if (!cert)
//        return 0;
//
//    CRYPTO_add(&cert->references, 1, CRYPTO_LOCK_X509);
//    return 1;
//}
//
///* Needed because some versions of OpenSSL do not support X509_CRL_up_ref() */
// static int X509_CRL_up_ref(X509_CRL* cert_crl)
//{
//    if (!cert_crl)
//        return 0;
//
//    CRYPTO_add(&cert_crl->references, 1, CRYPTO_LOCK_X509_CRL);
//    return 1;
//}
//
// static const STACK_OF(X509_EXTENSION) * X509_get0_extensions(const
// PCERT_CONTEXT x)
//{
//    if (!x->cert_info)
//    {
//        return NULL;
//    }
//    return x->cert_info->extensions;
//}
//
//#endif
//
// static oe_result_t _cert_chain_get_length(const cert_chain_t* impl, int*
// length)
//{
//    oe_result_t result = OE_UNEXPECTED;
//    int num;
//
//    *length = 0;
//
//    if ((num = sk_X509_num(impl->sk)) <= 0)
//        OE_RAISE(OE_FAILURE);
//
//    *length = num;
//
//    result = OE_OK;
//
// done:
//    return result;
//}
//
// static STACK_OF(X509) * _clone_chain(STACK_OF(X509) * chain)
//{
//    STACK_OF(X509)* sk = NULL;
//    int n = sk_X509_num(chain);
//
//    if (!(sk = sk_X509_new(NULL)))
//        return NULL;
//
//    for (int i = 0; i < n; i++)
//    {
//        PCERT_CONTEXT cert;
//
//        if (!(cert = sk_X509_value(chain, (int)i)))
//            return NULL;
//
//        if (!(cert = _clone_cert(cert)))
//            return NULL;
//
//        if (!sk_X509_push(sk, cert))
//            return NULL;
//    }
//
//    return sk;
//}
//
// static oe_result_t _verify_cert(PCERT_CONTEXT cert_, STACK_OF(X509) * chain_)
//{
//    oe_result_t result = OE_UNEXPECTED;
//    X509_STORE_CTX* ctx = NULL;
//    PCERT_CONTEXT cert = NULL;
//    STACK_OF(X509)* chain = NULL;
//
//    /* Clone the certificate to clear any cached verification state */
//    if (!(cert = _clone_cert(cert_)))
//        OE_RAISE(OE_FAILURE);
//
//    /* Clone the chain to clear any cached verification state */
//    if (!(chain = _clone_chain(chain_)))
//        OE_RAISE(OE_FAILURE);
//
//    /* Create a context for verification */
//    if (!(ctx = X509_STORE_CTX_new()))
//        OE_RAISE(OE_FAILURE);
//
//    /* Initialize the context that will be used to verify the certificate */
//    if (!X509_STORE_CTX_init(ctx, NULL, NULL, NULL))
//        OE_RAISE(OE_FAILURE);
//
//    /* Inject the certificate into the verification context */
//    X509_STORE_CTX_set_cert(ctx, cert);
//
//    /* Set the CA chain into the verification context */
//    X509_STORE_CTX_trusted_stack(ctx, chain);
//
//    /* Finally verify the certificate */
//    if (!X509_verify_cert(ctx))
//        OE_RAISE(OE_FAILURE);
//
//    result = OE_OK;
//
// done:
//
//    if (cert)
//        X509_free(cert);
//
//    if (chain)
//        sk_X509_pop_free(chain, X509_free);
//
//    if (ctx)
//        X509_STORE_CTX_free(ctx);
//
//    return result;
//}

// Find the last certificate in the chain and then verify that it's a
// self-signed certificate (a root certificate).
static PCERT_CONTEXT _find_root_cert(PCERT_CHAIN_CONTEXT chain)
{
    PCERT_CONTEXT root_cert = NULL;
    DWORD cert_count = 0;
    if (chain && chain->cChain > 0 && chain->rgpChain[0]->cElement > 0)
    {
        cert_count = chain->rgpChain[0]->cElement;

        /* Get the last certificate in the list */
        if (!(root_cert =
                  chain->rgpChain[0]->rgpElement[cert_count - 1]->pCertContext))
            return NULL;

        /* If the last certificate is not self-signed, then fail */
        {
            PCERT_NAME_BLOB subject = &root_cert->pCertInfo->Subject;
            PCERT_NAME_BLOB issuer = &root_cert->pCertInfo->Issuer;

            /* This assumes that the issuer & subject fields in the same cert
             * share a canonical encoding, like the mbedTLS impl does */
            if (!subject || !issuer || subject->cbData != issuer->cbData ||
                memcmp(subject->pbData, issuer->pbData, subject->cbData) != 0)
                return NULL;
        }
    }

    /* Return the root certificate */
    return root_cert;
}

/* Verify each certificate in the chain against its predecessor. */
static oe_result_t _bcrypt_get_cert_chain(
    PCCERT_CONTEXT cert_context,
    HCERTSTORE trusted_store,
    size_t expected_chain_length,
    PCERT_CHAIN_CONTEXT* cert_chain)
{
    oe_result_t result = OE_UNEXPECTED;
    PCERT_CHAIN_CONTEXT found_chain = NULL;

    if (cert_chain)
        *cert_chain = NULL;

    if (!cert_chain)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* CertGetCertificateChain can increment the refcount on cert_context
     * by >1 due to CERT_CHAIN_CACHE_END_CERT. Do not force close the store,
     * which will destroy the cached cert and corrupt future cert chaining
     * calls.
     */
    if (!CertGetCertificateChain(
            NULL,                           // use the default engine
            cert_context,                   // pointer to the end certificate
            NULL,                           // use the default time
            trusted_store,                  // search custom store
            &_OE_DEFAULT_CERT_CHAIN_PARAMS, // use default chain params
            _OE_DEFAULT_CERT_CHAIN_FLAGS,   // use specified chain flags
            NULL,                           // currently reserved
            &found_chain)) // return a pointer to the chain created
    {
        DWORD err = GetLastError();
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR, "CertGetCertificateChain failed, err=%#x\n", err);
    }

    if (found_chain && found_chain->cChain > 0 &&
        (expected_chain_length == _OE_CERT_CHAIN_LENGTH_ANY ||
         found_chain->rgpChain[0]->cElement == expected_chain_length))
    {
        *cert_chain = found_chain;
        found_chain = NULL;
        result = OE_OK;
    }
    else
        result = OE_NOT_FOUND;

done:
    if (found_chain)
        CertFreeCertificateChain(found_chain);

    return result;
}

static oe_result_t _verify_whole_chain(PCCERT_CHAIN_CONTEXT cert_chain)
{
    oe_result_t result = OE_UNEXPECTED;
    CERT_CHAIN_POLICY_STATUS policy_status = {
        .cbSize = sizeof(CERT_CHAIN_POLICY_STATUS)};

    if (!_find_root_cert(cert_chain))
        OE_RAISE_MSG(OE_VERIFY_FAILED, "No root certificate found\n", NULL);

    // Sanity check; CertGetCertificateChain shouldn't produce
    // chains that violates basic constraints anyway.
    if (!CertVerifyCertificateChainPolicy(
            CERT_CHAIN_POLICY_BASIC_CONSTRAINTS,
            cert_chain,
            &_OE_DEFAULT_CERT_CHAIN_POLICY,
            &policy_status))
    {
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR,
            "CertVerifyCertificateChainPolicy could not check policy\n",
            NULL);
    }

    // TODO: Map verification errors to oe errors
    if (policy_status.dwError != ERROR_SUCCESS)
    {
        OE_RAISE_MSG(
            OE_VERIFY_FAILED,
            "CertVerifyCertificateChainPolicy failed, err=%#x\n",
            policy_status.dwError);
    }

    // TODO: Check the CERT_CHAIN_POLICY_STATUS on the
    result = OE_OK;

done:
    return result;
}

/*
**==============================================================================
**
** Public functions
**
**==============================================================================
*/

/* Used by tests/crypto_crls_cert_chains */
oe_result_t oe_cert_read_pem(
    oe_cert_t* cert,
    const void* pem_data,
    size_t pem_size)
{
    oe_result_t result = OE_UNEXPECTED;
    cert_t* impl = (cert_t*)cert;
    BYTE* der_data = NULL;
    DWORD der_size = 0;
    PCERT_CONTEXT cert_context = NULL;

    /* Zero-initialize the implementation */
    if (impl)
        impl->magic = 0;

    OE_CHECK(_bcrypt_pem_to_der(pem_data, pem_size, &der_data, &der_size));

    /* Create the CERT_CONTEXT from DER data */
    cert_context = CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, der_data, der_size);

    if (!cert_context)
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR,
            "CertCreateCertificateContext failed, err=%#x\n",
            GetLastError());

    /* Initialize the wrapper cert_context structure */
    _cert_init(impl, cert_context);
    cert_context = NULL;
    result = OE_OK;

done:
    if (cert_context)
        CertFreeCertificateContext(cert_context);

    if (der_data)
        free(der_data);

    return result;
}

oe_result_t oe_cert_read_der(
    oe_cert_t* cert,
    const void* der_data,
    size_t der_size)
{
    return OE_UNSUPPORTED;
    //    oe_result_t result = OE_UNEXPECTED;
    //    Cert* impl = (Cert*)cert;
    //    X509* x509 = NULL;
    //    unsigned char* p = NULL;
    //
    //    /* Zero-initialize the implementation */
    //    if (impl)
    //        impl->magic = 0;
    //
    //    /* Check parameters */
    //    if (!der_data || !der_size || der_size > OE_INT_MAX || !cert)
    //        OE_RAISE(OE_INVALID_PARAMETER);
    //
    //    /* Initialize OpenSSL (if not already initialized) */
    //    oe_initialize_openssl();
    //
    //    p = (unsigned char*)der_data;
    //
    //    /* Convert the PEM BIO into a certificate object */
    //    if (!(x509 = d2i_X509(NULL, (const unsigned char**)&p, (int)der_size)))
    //        OE_RAISE(OE_FAILURE);
    //
    //    _cert_init(impl, x509);
    //    x509 = NULL;
    //
    //    result = OE_OK;
    //
    //done:
    //
    //    X509_free(x509);
    //
    //    return result;
}

oe_result_t oe_cert_free(oe_cert_t* cert)
{
    oe_result_t result = OE_UNEXPECTED;
    cert_t* impl = (cert_t*)cert;

    /* Check parameters */
    if (!_cert_is_valid(impl))
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Free the certificate */
    CertFreeCertificateContext(impl->cert);
    _cert_clear(impl);

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_cert_chain_read_pem(
    oe_cert_chain_t* chain,
    const void* pem_data,
    size_t pem_size)
{
    oe_result_t result = OE_UNEXPECTED;
    cert_chain_t* impl = (cert_chain_t*)chain;
    PCCERT_CHAIN_CONTEXT cert_chain = NULL;
    CRYPT_DATA_BLOB der = {0};
    char* pem_cert = NULL;
    size_t pem_cert_size = 0;
    uint32_t found_certs = 0;

    PCCERT_CONTEXT cert_context = NULL;

    /* Zero-initialize the implementation */
    if (impl)
        impl->magic = 0;

    /* Check parameters */
    if (!pem_data || !pem_size || !chain)
        OE_RAISE(OE_INVALID_PARAMETER);

    // TODO: Refactor apart into:
    // - _bcrypt_load_pem_as_cert_store
    // - _bcrypt_get_cert_chain_from_store
    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, NULL, 0, NULL);
    if (!store)
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR, "CertOpenStore failed, err=%#x\n", GetLastError());

    oe_result_t find_result = OE_OK;
    size_t remaining_size = pem_size;
    const void* read_pos = pem_data;
    while (remaining_size >
           OE_PEM_BEGIN_CERTIFICATE_LEN + OE_PEM_END_CERTIFICATE_LEN)
    {
        find_result = _get_next_pem_cert(
            &read_pos, &remaining_size, &pem_cert, &pem_cert_size);
        if (find_result == OE_NOT_FOUND)
            break;
        else if (find_result != OE_OK)
            OE_RAISE(find_result);

        OE_CHECK(_bcrypt_pem_to_der(
            pem_cert, pem_cert_size, &der.pbData, &der.cbData));
        free(pem_cert);
        pem_cert = NULL;

        if (!CertAddEncodedCertificateToStore(
                store,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                der.pbData,
                der.cbData,
                CERT_STORE_ADD_REPLACE_EXISTING,
                NULL))
        {
            DWORD err = GetLastError();
            OE_RAISE_MSG(
                OE_CRYPTO_ERROR,
                "CertAddEncodedCertificateToStore failed, err=%#x\n",
                err);
        }

        free(der.pbData);
        der.pbData = NULL;
        der.cbData = 0;
    }

    // Trace: check if added certs matches found_certs consider adding a limit
    // check prior to this
    while (cert_context = CertEnumCertificatesInStore(store, cert_context))
    {
        found_certs++;
    }

    if (found_certs == 0)
        OE_RAISE_MSG(
            OE_INVALID_PARAMETER, "No certs read from pem_data\n", NULL);

    /* Without assuming an ordering of certificates added to the cert store,
     * try constructing a cert chain with each cert in the store as the leaf
     * cert until a cert chain is found that uses all certs in the store and
     * terminates in a self-signed (root) certificate.
     */
    while (cert_context = CertEnumCertificatesInStore(store, cert_context))
    {
        find_result = _bcrypt_get_cert_chain(
            cert_context, store, found_certs, &cert_chain);

        if (find_result == OE_OK)
        {
            break;
        }
        else if (find_result != OE_NOT_FOUND)
        {
            OE_RAISE(find_result);
        }
    }

    if (!cert_chain)
        OE_RAISE_MSG(
            OE_VERIFY_FAILED,
            "pem_data does not contain a valid cert chain\n",
            NULL);

    OE_CHECK(_verify_whole_chain(cert_chain));

    _cert_chain_init(impl, cert_chain, store);
    result = OE_OK;

done:
    if (pem_cert)
        free(pem_cert);

    if (der.pbData)
        free(der.pbData);

    if (cert_context)
        CertFreeCertificateContext(cert_context);

    if (result != OE_OK)
    {
        if (cert_chain)
            CertFreeCertificateChain(cert_chain);

        if (store)
            CertCloseStore(store, 0);
    }

    return result;
}

oe_result_t oe_cert_chain_free(oe_cert_chain_t* chain)
{
    oe_result_t result = OE_UNEXPECTED;
    cert_chain_t* impl = (cert_chain_t*)chain;

    /* Check the parameter */
    if (!_cert_chain_is_valid(impl))
        OE_RAISE(OE_INVALID_PARAMETER);

    CertFreeCertificateChain(impl->cert_chain);

    if (impl->cert_store)
        CertCloseStore(impl->cert_store, 0);

    /* Clear the implementation */
    _cert_chain_clear(impl);

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_cert_verify(
    oe_cert_t* cert,
    oe_cert_chain_t* chain,
    const oe_crl_t* const* crls,
    size_t num_crls)
{
    oe_result_t result = OE_UNEXPECTED;
    cert_t* cert_impl = (cert_t*)cert;
    cert_chain_t* chain_impl = (cert_chain_t*)chain;
    DWORD chain_count = 0;
    HCERTSTORE cert_store = NULL;
    PCCERT_CHAIN_CONTEXT cert_chain = NULL;

    /* Check for invalid cert parameter */
    if (!_cert_is_valid(cert_impl))
        OE_RAISE_MSG(OE_INVALID_PARAMETER, "Invalid cert parameter", NULL);

    /* Check for invalid chain parameter */
    if (!_cert_chain_is_valid(chain_impl))
        OE_RAISE_MSG(OE_INVALID_PARAMETER, "Invalid chain parameter", NULL);

    /* Create a store for the verification */
    cert_store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, NULL, 0, NULL);
    if (!cert_store)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "Failed to allocate X509 store", NULL);

    /* Add certs in chain to cert store */
    if (chain_impl->cert_chain->cChain > 0 &&
        chain_impl->cert_chain->rgpChain[0])
    {
        chain_count = chain_impl->cert_chain->rgpChain[0]->cElement;
    }
    else
    {
        OE_RAISE_MSG(
            OE_INVALID_PARAMETER,
            "Invalid chain parameter contains no certs",
            NULL);
    }

    for (int i = 0; i < chain_count; i++)
    {
        if (!CertAddCertificateContextToStore(
                cert_store,
                chain_impl->cert_chain->rgpChain[0]
                    ->rgpElement[i]
                    ->pCertContext,
                CERT_STORE_ADD_REPLACE_EXISTING,
                NULL))
        {
            OE_RAISE_MSG(
                OE_CRYPTO_ERROR,
                "CertAddCertificateContextToStore failed, err=%#x\n",
                GetLastError());
        }
    }

    /* Add CRLs to cert store */
    for (int j = 0; j < num_crls; j++)
    {
        if (!CertAddCRLContextToStore(
                cert_store, crls[j], CERT_STORE_ADD_REPLACE_EXISTING, NULL))
        {
            OE_RAISE_MSG(
                OE_CRYPTO_ERROR,
                "CertAddCRLContextToStore failed, err=%#x\n",
                GetLastError());
        }
    }

    result = _bcrypt_get_cert_chain(
        cert_impl->cert, cert_store, _OE_CERT_CHAIN_LENGTH_ANY, &cert_chain);

    if (result == OE_NOT_FOUND)
        OE_RAISE_MSG(
            OE_VERIFY_FAILED, "No valid cert chain could be found\n", NULL);

    OE_CHECK(_verify_whole_chain(cert_chain));

    result = OE_OK;

done:
    if (cert_chain)
        CertFreeCertificateChain(cert_chain);

    if (cert_store)
        CertCloseStore(cert_store, 0);

    return result;
}

/* Used by tests/crypto/rsa_tests */
oe_result_t oe_cert_get_rsa_public_key(
    const oe_cert_t* cert,
    oe_rsa_public_key_t* public_key)
{
    oe_result_t result = OE_UNEXPECTED;
    const cert_t* impl = (const cert_t*)cert;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BCRYPT_KEY_HANDLE pkey = NULL;

    /* Clear public key for all error pathways */
    if (public_key)
        oe_secure_zero_fill(public_key, sizeof(oe_rsa_public_key_t));

    /* Reject invalid parameters */
    if (!_cert_is_valid(impl) || !public_key)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get public key */
    status = CryptImportPublicKeyInfoEx2(
        X509_ASN_ENCODING,
        &impl->cert->pCertInfo->SubjectPublicKeyInfo,
        0,
        NULL,
        &pkey);

    if (!BCRYPT_SUCCESS(status))
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR,
            "CryptImportPublicKeyInfoEx2 failed, err=%#x\n",
            status);

    /* Initialize the RSA public key */
    oe_rsa_public_key_init(public_key, pkey);
    pkey = NULL;

    result = OE_OK;

done:
    if (pkey)
    {
        BCryptDestroyKey(pkey);
    }

    return result;
}

oe_result_t oe_cert_get_ec_public_key(
    const oe_cert_t* cert,
    oe_ec_public_key_t* public_key)
{
    return OE_UNSUPPORTED;
    //    oe_result_t result = OE_UNEXPECTED;
    //    const cert_t* impl = (const cert_t*)cert;
    //    EVP_PKEY* pkey = NULL;
    //
    //    /* Clear public key for all error pathways */
    //    if (public_key)
    //        oe_secure_zero_fill(public_key, sizeof(oe_ec_public_key_t));
    //
    //    /* Reject invalid parameters */
    //    if (!_cert_is_valid(impl) || !public_key)
    //        OE_RAISE(OE_INVALID_PARAMETER);
    //
    //    /* Get public key (increments reference count) */
    //    if (!(pkey = X509_get_pubkey(impl->cert)))
    //        OE_RAISE(OE_FAILURE);
    //
    //    /* If this is not an EC key */
    //    {
    //        EC_KEY* ec;
    //
    //        if (!(ec = EVP_PKEY_get1_EC_KEY(pkey)))
    //            OE_RAISE(OE_FAILURE);
    //
    //        EC_KEY_free(ec);
    //    }
    //
    //    /* Initialize the EC public key */
    //    oe_ec_public_key_init(public_key, pkey);
    //    pkey = NULL;
    //
    //    result = OE_OK;
    //
    // done:
    //
    //    if (pkey)
    //    {
    //        /* Decrement reference count (incremented above) */
    //        EVP_PKEY_free(pkey);
    //    }
    //
    //    return result;
}

/* Used by tests/crypto/ec_tests|rsa_tests */
oe_result_t oe_cert_chain_get_length(
    const oe_cert_chain_t* chain,
    size_t* length)
{
    oe_result_t result = OE_UNEXPECTED;
    const cert_chain_t* impl = (const cert_chain_t*)chain;

    /* Clear the length (for failed return case) */
    if (length)
        *length = 0;

    /* Reject invalid parameters */
    if (!_cert_chain_is_valid(impl) || !length)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get the number of certificates in the chain */
    if (impl->cert_chain->cChain == 0 || !impl->cert_chain->rgpChain ||
        impl->cert_chain->rgpChain[0]->cElement == 0)
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR, "No certs found in oe_cert_chain_t impl\n", NULL);

    *length = (size_t)impl->cert_chain->rgpChain[0]->cElement;
    result = OE_OK;

done:
    return result;
}

oe_result_t oe_cert_chain_get_cert(
    const oe_cert_chain_t* chain,
    size_t index,
    oe_cert_t* cert)
{
    oe_result_t result = OE_UNEXPECTED;
    const cert_chain_t* impl = (const cert_chain_t*)chain;
    size_t length;
    PCERT_CONTEXT found_cert = NULL;

    /* Clear the output certificate for all error pathways */
    if (cert)
        memset(cert, 0, sizeof(oe_cert_t));

    /* Reject invalid parameters */
    if (!cert)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get the length of the certificate chain, also validates chain arg */
    OE_CHECK(oe_cert_chain_get_length(chain, &length));

    /* Check for out of bounds */
    if (index >= length)
        OE_RAISE(OE_OUT_OF_BOUNDS);

    /* Check for overflow as int because that is the OpenSSL limit */
    if (index >= OE_INT_MAX)
        OE_RAISE(OE_INTEGER_OVERFLOW);

    found_cert = CertDuplicateCertificateContext(
        impl->cert_chain->rgpChain[0]->rgpElement[index]->pCertContext);

    if (!found_cert)
        OE_RAISE_MSG(OE_FAILURE, "Failed to get cert at valid index\n", NULL);

    _cert_init((cert_t*)cert, found_cert);
    result = OE_OK;

done:
    return result;
}

// TODO: identical to openssl impl, consolidate
oe_result_t oe_cert_chain_get_root_cert(
    const oe_cert_chain_t* chain,
    oe_cert_t* cert)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t length;

    OE_CHECK(oe_cert_chain_get_length(chain, &length));
    OE_CHECK(oe_cert_chain_get_cert(chain, length - 1, cert));
    result = OE_OK;

done:
    return result;
}

// TODO: identical to openssl impl, consolidate
oe_result_t oe_cert_chain_get_leaf_cert(
    const oe_cert_chain_t* chain,
    oe_cert_t* cert)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t length;

    OE_CHECK(oe_cert_chain_get_length(chain, &length));
    OE_CHECK(oe_cert_chain_get_cert(chain, 0, cert));
    result = OE_OK;

done:
    return result;
}

oe_result_t oe_cert_find_extension(
    const oe_cert_t* cert,
    const char* oid,
    uint8_t* data,
    size_t* size)
{
    return OE_UNSUPPORTED;
    //    oe_result_t result = OE_UNEXPECTED;
    //    const cert_t* impl = (const cert_t*)cert;
    //    const STACK_OF(X509_EXTENSION) * extensions;
    //    int num_extensions;
    //
    //    /* Reject invalid parameters */
    //    if (!_cert_is_valid(impl) || !oid || !size)
    //        OE_RAISE(OE_INVALID_PARAMETER);
    //
    //    /* Set a pointer to the stack of extensions (possibly NULL) */
    //    if (!(extensions = X509_get0_extensions(impl->cert)))
    //        OE_RAISE(OE_NOT_FOUND);
    //
    //    /* Get the number of extensions (possibly zero) */
    //    num_extensions = sk_X509_EXTENSION_num(extensions);
    //
    //    /* Find the certificate with this OID */
    //    for (int i = 0; i < num_extensions; i++)
    //    {
    //        X509_EXTENSION* ext;
    //        ASN1_OBJECT* obj;
    //        oe_oid_string_t ext_oid;
    //
    //        /* Get the i-th extension from the stack */
    //        if (!(ext = sk_X509_EXTENSION_value(extensions, i)))
    //            OE_RAISE(OE_FAILURE);
    //
    //        /* Get the OID */
    //        if (!(obj = X509_EXTENSION_get_object(ext)))
    //            OE_RAISE(OE_FAILURE);
    //
    //        /* Get the string name of the OID */
    //        if (!OBJ_obj2txt(ext_oid.buf, sizeof(ext_oid.buf), obj, 1))
    //            OE_RAISE(OE_FAILURE);
    //
    //        /* If found then get the data */
    //        if (strcmp(ext_oid.buf, oid) == 0)
    //        {
    //            ASN1_OCTET_STRING* str;
    //
    //            /* Get the data from the extension */
    //            if (!(str = X509_EXTENSION_get_data(ext)))
    //                OE_RAISE(OE_FAILURE);
    //
    //            /* If the caller's buffer is too small, raise error */
    //            if ((size_t)str->length > *size)
    //            {
    //                *size = (size_t)str->length;
    //                OE_RAISE(OE_BUFFER_TOO_SMALL);
    //            }
    //
    //            if (data)
    //            {
    //                OE_CHECK(
    //                    oe_memcpy_s(data, *size, str->data,
    //                    (size_t)str->length));
    //                *size = (size_t)str->length;
    //                result = OE_OK;
    //                goto done;
    //            }
    //        }
    //    }
    //
    //    result = OE_NOT_FOUND;
    //
    // done:
    //    return result;
}
