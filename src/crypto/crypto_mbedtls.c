#include "crypto_mbedtls.h"
#include "base64.h"
#include "math.h"

#include "mbedtls/pk.h"
#include <mbedtls/md.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

static int
hmac_sha(
    char* dst,
    const char* p,
    uint32_t plen,
    const byte* key,
    uint32_t keylen,
    JSMN_ALG alg)
{
    int err = -1;
    mbedtls_md_context_t ctx;
    mbedtls_md_type_t type;
    switch (alg) {
        case JSMN_ALG_HS256: 
            type = MBEDTLS_MD_SHA256; 
            break;
        case JSMN_ALG_HS384: 
            type = MBEDTLS_MD_SHA384; 
            break;
        case JSMN_ALG_HS512: 
            type = MBEDTLS_MD_SHA512; 
            break;
        default: 
            return err;
    };

    mbedtls_md_init(&ctx);
    err = mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(type), 1);
    if (err) goto ERROR;

    err = mbedtls_md_hmac_starts(&ctx, key, keylen);
    if (err) goto ERROR;

    err = mbedtls_md_hmac_update(&ctx, (const byte*)p, plen);
    if (err) goto ERROR;

    err = mbedtls_md_hmac_finish(&ctx, (byte*)dst);
    if (err) goto ERROR;

    err = 0;
ERROR:
    mbedtls_md_free(&ctx);
    return err;
}

static int 
rsa_sha(
    char* dst,
    const char* p,
    uint32_t plen,
    const byte* key,
    uint32_t keylen,
    JSMN_ALG alg)
{
    int err = -1;
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    size_t md_length = 0;
    mbedtls_md_type_t md_type;
    unsigned char hash[64] = { 0x00 };

    size_t signature_bytes_length = 0;

    switch (alg) 
    {
        case JSMN_ALG_RS256: 
            md_type = MBEDTLS_MD_SHA256;
            md_length = 32; 
            break;
        case JSMN_ALG_RS384: 
            md_type = MBEDTLS_MD_SHA384; 
            md_length = 48;
            break;
        case JSMN_ALG_RS512: 
            md_type = MBEDTLS_MD_SHA512; 
            md_length = 64;
            break;
        default: 
            return err;
    };

    mbedtls_pk_init(&pk);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    err = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)"mighty_mbedtls_pers.!#@", 23);
    if (err)
    {
        goto ERROR;
    }

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_type);

    /* Parse & load the key string into the mbedtls pk instance. */
    // NOTE: keylen here should include the NULL terminator
    err = mbedtls_pk_parse_key(&pk, key, keylen + 1, NULL, 0);
    if (err)
    {
        goto ERROR;
    }

    /* Ensure RSA functionality. */
    if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA) && !mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA_ALT))
    {
        goto ERROR;
    }

    /* Weak RSA keys are forbidden! */
    if (mbedtls_pk_get_bitlen(&pk) < 2048)
    {
        goto ERROR;
    }

    /* Hash the JWT header + payload. */
    err = mbedtls_md(md_info, (const byte*)p, plen, hash);
    if (err)
    {
        goto ERROR;
    }

    /* Sign the hash using the provided private key. */
    err = mbedtls_pk_sign(&pk, md_type, hash, md_length, (byte*)dst, &signature_bytes_length, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (err)
    {
        goto ERROR;
    }

    err = 0;
ERROR:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_pk_free(&pk);
    return err;
}

int
crypto_sign(
    char* dst,
    const char* p,
    uint32_t plen,
    const byte* key,
    uint32_t klen,
    JSMN_ALG alg)
{
    int ret = -1;
    switch (alg) {
        case JSMN_ALG_HS256:
        case JSMN_ALG_HS384:
        case JSMN_ALG_HS512: 
            ret = hmac_sha(dst, p, plen, key, klen, alg);
            break;
        case JSMN_ALG_RS256:
        case JSMN_ALG_RS384:
        case JSMN_ALG_RS512: 
            ret = rsa_sha(dst, p, plen, key, klen, alg);
            break;
        default: 
            break;
    }
    return ret;
}
