/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <string.h>
#include <glib.h>
#include <argon2.h>
#include "password-hash.h"
#include "seafile-crypt.h"
#include <openssl/rand.h>

#include "utils.h"
#include "log.h"

#define KEYGEN_ITERATION 1 << 19
#define KEYGEN_ITERATION2 1000
/* Should generate random salt for each repo. */
static unsigned char salt[8] = { 0xda, 0x90, 0x45, 0xc3, 0x06, 0xc7, 0xcc, 0x26 };

// pdkdf2
typedef struct Pdkdf2Params {
    int iteration;
    int iteration2;
} Pdkdf2Params;

static Pdkdf2Params *
parse_pdkdf2_sha256_params (const char *params_str)
{
    Pdkdf2Params *params = NULL;
    if (!params_str) {
        params = g_new0 (Pdkdf2Params, 1);
        params->iteration = KEYGEN_ITERATION;
        params->iteration2 = KEYGEN_ITERATION2;
        return params;
    }
    int iteration;
    iteration = atoi (params_str);
    if (iteration <= 0) {
        iteration = KEYGEN_ITERATION2;
    }

    params = g_new0 (Pdkdf2Params, 1);
    params->iteration = KEYGEN_ITERATION;
    params->iteration2 = iteration;
    return params;
}

int
pdkdf2_sha256_derive_key (const char *data_in, int in_len, int version,
                          const char *repo_salt,
                          Pdkdf2Params *params,
                          unsigned char *key, unsigned char *iv)
{
    int iteration = params->iteration;
    int iteration2 = params->iteration2;

    if (version >= 3) {
        unsigned char repo_salt_bin[32];
        hex_to_rawdata (repo_salt, repo_salt_bin, 32);

        PKCS5_PBKDF2_HMAC (data_in, in_len,
                           repo_salt_bin, sizeof(repo_salt_bin),
                           iteration2,
                           EVP_sha256(),
                           32, key);
        PKCS5_PBKDF2_HMAC ((char *)key, 32,
                           repo_salt_bin, sizeof(repo_salt_bin),
                           10,
                           EVP_sha256(),
                           16, iv);
        return 0;
    } else if (version == 2) {
        PKCS5_PBKDF2_HMAC (data_in, in_len,
                           salt, sizeof(salt),
                           iteration2,
                           EVP_sha256(),
                           32, key);
        PKCS5_PBKDF2_HMAC ((char *)key, 32,
                           salt, sizeof(salt),
                           10,
                           EVP_sha256(),
                           16, iv);
        return 0;
    } else if (version == 1)
        return EVP_BytesToKey (EVP_aes_128_cbc(), /* cipher mode */
                               EVP_sha1(),        /* message digest */
                               salt,              /* salt */
                               (unsigned char*)data_in,
                               in_len,
                               iteration,   /* iteration times */
                               key, /* the derived key */
                               iv); /* IV, initial vector */
    else
        return EVP_BytesToKey (EVP_aes_128_ecb(), /* cipher mode */
                               EVP_sha1(),        /* message digest */
                               NULL,              /* salt */
                               (unsigned char*)data_in,
                               in_len,
                               3,   /* iteration times */
                               key, /* the derived key */
                               iv); /* IV, initial vector */
}

// argon2id
typedef struct Argon2idParams{
    gint64 time_cost; 
    gint64 memory_cost;
    gint64 parallelism;
} Argon2idParams;

// The arguments to argon2 are separated by commas.
// Example arguments format:
// 2,102400,8
// The parameters are time_cost, memory_cost, parallelism from left to right.
static Argon2idParams *
parse_argon2id_params (const char *params_str)
{
    char **params;
    Argon2idParams *argon2_params = g_new0 (Argon2idParams, 1);
    if (params_str)
        params = g_strsplit (params_str, ",", 3);
    if (!params_str || g_strv_length(params) != 3) {
        if (params_str)
            g_strfreev (params);
        argon2_params->time_cost = 2; // 2-pass computation
        argon2_params->memory_cost = 102400; // 100 mebibytes memory usage
        argon2_params->parallelism = 8; // number of threads and lanes
        return argon2_params;
    }

    char *p = NULL;
    p = g_strstrip (params[0]);
    argon2_params->time_cost = atoll (p);
    if (argon2_params->time_cost <= 0) {
        argon2_params->time_cost = 2;
    }

    p = g_strstrip (params[1]);
    argon2_params->memory_cost = atoll (p);
    if (argon2_params->memory_cost <= 0) {
        argon2_params->memory_cost = 102400;
    }

    p = g_strstrip (params[2]);
    argon2_params->parallelism = atoll (p);
    if (argon2_params->parallelism <= 0) {
        argon2_params->parallelism = 8;
    }

    g_strfreev (params);
    return argon2_params;
}

int
argon2id_derive_key (const char *data_in, int in_len, int version,
                     const char *repo_salt,
                     Argon2idParams *params,
                     unsigned char *key, unsigned char *iv)
{
    if (version >= 3) {
        unsigned char repo_salt_bin[32];
        hex_to_rawdata (repo_salt, repo_salt_bin, 32);

        argon2id_hash_raw(params->time_cost, params->memory_cost, params->parallelism,
                          data_in, in_len,
                          repo_salt_bin, sizeof(repo_salt_bin),
                          key, 32);
        argon2id_hash_raw(params->time_cost, params->memory_cost, params->parallelism,
                          key, 32,
                          repo_salt_bin, sizeof(repo_salt_bin),
                          iv, 16);
    } else {
        argon2id_hash_raw(params->time_cost, params->memory_cost, params->parallelism,
                          data_in, in_len,
                          salt, sizeof(salt),
                          key, 32);
        argon2id_hash_raw(params->time_cost, params->memory_cost, params->parallelism,
                          key, 32,
                          salt, sizeof(salt),
                          iv, 16);
    }

    return 0;
}

void
pwd_hash_init (const char *algo, const char *params_str, PwdHashParams *params)
{
    if (g_strcmp0 (algo, PWD_HASH_PDKDF2) == 0) {
        params->algo = g_strdup (PWD_HASH_PDKDF2);
        if (params_str)
            params->params_str = g_strdup (params_str);
        else
            params->params_str = g_strdup ("1000");
    } else if (g_strcmp0 (algo, PWD_HASH_ARGON2ID) == 0) {
        params->algo = g_strdup (PWD_HASH_ARGON2ID);
        if (params_str)
            params->params_str = g_strdup (params_str);
        else
            params->params_str = g_strdup ("2,102400,8");
    } else {
        params->is_default = TRUE;
        params->algo = g_strdup (PWD_HASH_PDKDF2);
    }

    seaf_message ("password hash algorithms: %s, params: %s\n ", params->algo, params->params_str);
}


int
pwd_hash_derive_key (const char *data_in, int in_len, int version,
                     const char *repo_salt,
                     const char *algo, const char *params_str,
                     unsigned char *key, unsigned char *iv)
{
    int ret = 0;
    if (g_strcmp0 (algo, PWD_HASH_ARGON2ID) == 0) {
        Argon2idParams *algo_params = parse_argon2id_params (params_str);
        ret = argon2id_derive_key (data_in, in_len, version,
                                   repo_salt, algo_params, key, iv);
        g_free (algo_params);
        return ret;
    } else {
        Pdkdf2Params *algo_params = parse_pdkdf2_sha256_params (params_str);
        ret = pdkdf2_sha256_derive_key (data_in, in_len, version,
                                        repo_salt, algo_params, key, iv);
        g_free (algo_params);
        return ret;
    }
}
