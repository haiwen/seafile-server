/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"
#include <sys/stat.h>
#include <dirent.h>
#include "utils.h"
#include "seafile-session.h"
#include "seafile-error.h"
#include "user-mgr.h"
#include "seaf-db.h"
#include "seaf-utils.h"

#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#ifdef HAVE_LDAP
#ifndef WIN32
#define LDAP_DEPRECATED 1
#include <ldap.h>
#else
#include <winldap.h>
#include <winber.h>
#ifndef LDAP_OPT_SUCCESS
#define LDAP_OPT_SUCCESS LDAP_SUCCESS
#endif
#endif
#endif

#define DEFAULT_PASSWD_HASH_ITER 100000
#define SHA256_DIGEST_LENGTH 32
#define MAX_SALT_LENGTH 32

// Function prototypes
void rawdata_to_hex(const unsigned char *data, char *hex, int length);
void hex_to_rawdata(const char *hex, unsigned char *data, int length);
void OPENSSL_cleanse(void *ptr, size_t len);
static void hash_password_pbkdf2_sha256(const char *passwd, int iterations, char **db_passwd);
static gboolean validate_passwd_pbkdf2_sha256(const char *passwd, const char *db_passwd);

// Utility functions for conversion and cleansing
void rawdata_to_hex(const unsigned char *data, char *hex, int length) {
    for (int i = 0; i < length; i++) {
        sprintf(hex + (i * 2), "%02x", data[i]);
    }
    hex[length * 2] = '\0';
}

void hex_to_rawdata(const char *hex, unsigned char *data, int length) {
    for (int i = 0; i < length; i++) {
        sscanf(hex + (i * 2), "%02x", &data[i]);
    }
}

void OPENSSL_cleanse(void *ptr, size_t len) {
    volatile unsigned char *p = ptr;
    while (len--) {
        *p++ = 0;
    }
}

// Hash password using PBKDF2 with SHA-256
static void hash_password_pbkdf2_sha256(const char *passwd, int iterations, char **db_passwd) {
    unsigned char sha[SHA256_DIGEST_LENGTH];
    unsigned char salt[MAX_SALT_LENGTH];
    char hashed_passwd[SHA256_DIGEST_LENGTH * 2 + 1];
    char salt_str[MAX_SALT_LENGTH * 2 + 1];

    // Generate secure random salt
    if (!RAND_bytes(salt, sizeof(salt))) {
        fprintf(stderr, "Error generating random salt.\n");
        exit(EXIT_FAILURE);
    }

    // Perform PBKDF2 hashing
    PKCS5_PBKDF2_HMAC(passwd, strlen(passwd),
                      salt, sizeof(salt),
                      iterations,
                      EVP_sha256(),
                      sizeof(sha), sha);

    // Convert raw data to hexadecimal strings
    rawdata_to_hex(sha, hashed_passwd, SHA256_DIGEST_LENGTH);
    rawdata_to_hex(salt, salt_str, MAX_SALT_LENGTH);

    // Encode into one string (similar to Django's format)
    GString *buf = g_string_new(NULL);
    g_string_printf(buf, "PBKDF2SHA256$%d$%s$%s", iterations, salt_str, hashed_passwd);
    *db_passwd = g_string_free(buf, FALSE);

    // Clear sensitive data
    OPENSSL_cleanse(sha, sizeof(sha));
    OPENSSL_cleanse(passwd, strlen(passwd));
}

// Validate password against stored hash
static gboolean validate_passwd_pbkdf2_sha256(const char *passwd, const char *db_passwd) {
    char **tokens;
    char *salt_str, *stored_hash;
    int iter;
    unsigned char sha[SHA256_DIGEST_LENGTH];
    unsigned char salt[MAX_SALT_LENGTH];
    char hashed_passwd[SHA256_DIGEST_LENGTH * 2 + 1];

    // Split stored password into components
    tokens = g_strsplit(db_passwd, "$", -1);
    if (!tokens || g_strv_length(tokens) != 4) {
        g_strfreev(tokens);
        fprintf(stderr, "Invalid stored password format.\n");
        return FALSE;
    }

    iter = atoi(tokens[1]);
    salt_str = tokens[2];
    stored_hash = tokens[3];

    // Convert salt from hex to raw data
    hex_to_rawdata(salt_str, salt, MAX_SALT_LENGTH);

    // Hash provided password with the same parameters
    PKCS5_PBKDF2_HMAC(passwd, strlen(passwd),
                      salt, sizeof(salt),
                      iter,
                      EVP_sha256(),
                      sizeof(sha), sha);

    // Convert hash to hex
    rawdata_to_hex(sha, hashed_passwd, SHA256_DIGEST_LENGTH);

    // Clear sensitive data
    OPENSSL_cleanse(sha, sizeof(sha));
    OPENSSL_cleanse(passwd, strlen(passwd));

    // Compare hashes
    gboolean result = (strcmp(stored_hash, hashed_passwd) == 0);

    g_strfreev(tokens);
    return result;
}

// Add more functions here as necessary
// Integration points for database interactions, user management, etc.

// Example usage (testing purposes)
int main() {
    char *db_passwd = NULL;
    const char *password = "SecurePassword123";
    const char *stored_password;

    // Hash password
    hash_password_pbkdf2_sha256(password, DEFAULT_PASSWD_HASH_ITER, &db_passwd);

    // Validate password
    gboolean is_valid = validate_passwd_pbkdf2_sha256(password, db_passwd);

    printf("Stored Password: %s\n", db_passwd);
    printf("Password Validation: %s\n", is_valid ? "Valid" : "Invalid");

    g_free(db_passwd);
    return 0;
}
