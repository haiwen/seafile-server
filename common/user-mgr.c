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

#define DEBUG_FLAG  CCNET_DEBUG_PEER
#include "log.h"

#define DEFAULT_SAVING_INTERVAL_MSEC 30000

#define DEFAULT_MAX_CONNECTIONS 100

G_DEFINE_TYPE (CcnetUserManager, ccnet_user_manager, G_TYPE_OBJECT);


#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), CCNET_TYPE_USER_MANAGER, CcnetUserManagerPriv))


static int open_db (CcnetUserManager *manager);

#ifdef HAVE_LDAP
static int try_load_ldap_settings (CcnetUserManager *manager);
#endif

struct CcnetUserManagerPriv {
    CcnetDB    *db;
    int         max_users;
};

static void
ccnet_user_manager_class_init (CcnetUserManagerClass *klass)
{

    g_type_class_add_private (klass, sizeof (CcnetUserManagerPriv));
}

static void
ccnet_user_manager_init (CcnetUserManager *manager)
{
    manager->priv = GET_PRIV(manager);
}

CcnetUserManager*
ccnet_user_manager_new (SeafileSession *session)
{
    CcnetUserManager* manager;

    manager = g_object_new (CCNET_TYPE_USER_MANAGER, NULL);
    manager->session = session;
    manager->user_hash = g_hash_table_new (g_str_hash, g_str_equal);

    return manager;
}

#define DEFAULT_PASSWD_HASH_ITER 10000

// return current active user number
static int
get_current_user_number (CcnetUserManager *manager)
{
    int total = 0, count;

    count = ccnet_user_manager_count_emailusers (manager, "DB");
    if (count < 0) {
        ccnet_warning ("Failed to get user number from DB.\n");
        return -1;
    }
    total += count;

#ifdef HAVE_LDAP
    if (manager->use_ldap) {
        count = ccnet_user_manager_count_emailusers (manager, "LDAP");
        if (count < 0) {
            ccnet_warning ("Failed to get user number from LDAP.\n");
            return -1;
        }
        total += count;
    }
#endif

    return total;
}

static gboolean
check_user_number (CcnetUserManager *manager, gboolean allow_equal)
{
    if (manager->priv->max_users == 0) {
        return TRUE;
    }

    int cur_num = get_current_user_number (manager);
    if (cur_num < 0) {
        return FALSE;
    }

    if ((allow_equal && cur_num > manager->priv->max_users) ||
        (!allow_equal && cur_num >= manager->priv->max_users)) {
        ccnet_warning ("The number of users exceeds limit, max %d, current %d\n",
                       manager->priv->max_users, cur_num);
        return FALSE;
    }

    return TRUE;
}

int
ccnet_user_manager_prepare (CcnetUserManager *manager)
{
    int ret;

#ifdef HAVE_LDAP
    if (try_load_ldap_settings (manager) < 0)
        return -1;
#endif

    manager->passwd_hash_iter = DEFAULT_PASSWD_HASH_ITER;

    manager->userdb_path = g_build_filename (manager->session->ccnet_dir,
                                             "user-db", NULL);
    ret = open_db(manager);
    if (ret < 0)
        return ret;

    if (!check_user_number (manager, TRUE)) {
        return -1;
    }

    return 0;
}

void
ccnet_user_manager_free (CcnetUserManager *manager)
{
    g_object_unref (manager);
}

void
ccnet_user_manager_start (CcnetUserManager *manager)
{

}

void ccnet_user_manager_on_exit (CcnetUserManager *manager)
{
}

void
ccnet_user_manager_set_max_users (CcnetUserManager *manager, gint64 max_users)
{
    manager->priv->max_users = max_users;
}

/* -------- LDAP related --------- */

#ifdef HAVE_LDAP


static int try_load_ldap_settings (CcnetUserManager *manager)
{
    GKeyFile *config = manager->session->ccnet_config;
    manager->ldap_host = ccnet_key_file_get_string (config, "LDAP", "HOST");
    if (!manager->ldap_host)
        return 0;

    manager->use_ldap = TRUE;

#ifdef WIN32
    manager->use_ssl = g_key_file_get_boolean (config, "LDAP", "USE_SSL", NULL);
#endif

    char *base_list = ccnet_key_file_get_string (config, "LDAP", "BASE");
    if (!base_list) {
        ccnet_warning ("LDAP: BASE not found in config file.\n");
        return -1;
    }
    manager->base_list = g_strsplit (base_list, ";", -1);

    manager->filter = ccnet_key_file_get_string (config, "LDAP", "FILTER");

    manager->user_dn = ccnet_key_file_get_string (config, "LDAP", "USER_DN");
    if (manager->user_dn) {
        manager->password = ccnet_key_file_get_string (config, "LDAP", "PASSWORD");
        if (!manager->password) {
            ccnet_warning ("LDAP: PASSWORD not found in config file.\n");
            return -1;
        }
    }
    /* Use anonymous if user_dn is not set. */

    manager->login_attr = ccnet_key_file_get_string (config, "LDAP", "LOGIN_ATTR");
    if (!manager->login_attr)
        manager->login_attr = g_strdup("mail");

    GError *error = NULL;
    manager->follow_referrals = g_key_file_get_boolean (config,
                                                        "LDAP", "FOLLOW_REFERRALS",
                                                        &error);
    if (error) {
        /* Default is follow referrals. */
        g_clear_error (&error);
        manager->follow_referrals = TRUE;
    }

    return 0;
}

static LDAP *ldap_init_and_bind (CcnetUserManager *manager,
                                 const char *host,
#ifdef WIN32
                                 gboolean use_ssl,
#endif
                                 const char *user_dn,
                                 const char *password)
{
    LDAP *ld;
    int res;
    int desired_version = LDAP_VERSION3;

#ifndef WIN32
    res = ldap_initialize (&ld, host);
    if (res != LDAP_SUCCESS) {
        ccnet_warning ("ldap_initialize failed: %s.\n", ldap_err2string(res));
        return NULL;
    }
#else
    char *host_copy = g_strdup (host);
    if (!use_ssl)
        ld = ldap_init (host_copy, LDAP_PORT);
    else
        ld = ldap_sslinit (host_copy, LDAP_SSL_PORT, 1);
    g_free (host_copy);
    if (!ld) {
        ccnet_warning ("ldap_init failed: %ul.\n", LdapGetLastError());
        return NULL;
    }
#endif

    /* set the LDAP version to be 3 */
    res = ldap_set_option (ld, LDAP_OPT_PROTOCOL_VERSION, &desired_version);
    if (res != LDAP_OPT_SUCCESS) {
        ccnet_warning ("ldap_set_option failed: %s.\n", ldap_err2string(res));
        return NULL;
    }

    res = ldap_set_option (ld, LDAP_OPT_REFERRALS,
                           manager->follow_referrals ? LDAP_OPT_ON : LDAP_OPT_OFF);
    if (res != LDAP_OPT_SUCCESS) {
        ccnet_warning ("ldap_set_option referrals failed: %s.\n",
                       ldap_err2string(res));
        return NULL;
    }

    if (user_dn) {
#ifndef WIN32
        res = ldap_bind_s (ld, user_dn, password, LDAP_AUTH_SIMPLE);
#else
        char *dn_copy = g_strdup(user_dn);
        char *password_copy = g_strdup(password);
        res = ldap_bind_s (ld, dn_copy, password_copy, LDAP_AUTH_SIMPLE);
        g_free (dn_copy);
        g_free (password_copy);
#endif
        if (res != LDAP_SUCCESS ) {
            ccnet_warning ("ldap_bind failed for user %s: %s.\n",
                           user_dn, ldap_err2string(res));
            ldap_unbind_s (ld);
            return NULL;
        }
    }

    return ld;
}

static gboolean
get_uid_cb (CcnetDBRow *row, void *data)
{
    int *id = data;
    *id = seaf_db_row_get_column_int (row, 0);
    return FALSE;
}

static int
add_ldapuser (CcnetDB *db,
              const char *email,
              const char *password,
              gboolean is_staff,
              gboolean is_active,
              const char *extra_attrs)
{
    int rc;
    int uid = -1;

    rc = seaf_db_statement_foreach_row (db,
                                         "SELECT id FROM LDAPUsers WHERE email = ?",
                                         get_uid_cb, &uid, 1, "string", email);

    if (rc < 0) {
        return rc;
    }

    if (rc == 1) {
        return uid;
    }

    if (extra_attrs)
        rc = seaf_db_statement_query (db,
                                       "INSERT INTO LDAPUsers (email, password, is_staff, "
                                       "is_active, extra_attrs) VALUES (?, ?, ?, ?, ?)",
                                       5, "string", email, "string", password, "int",
                                       is_staff, "int", is_active, "string", extra_attrs);
    else
        rc = seaf_db_statement_query (db,
                                       "INSERT INTO LDAPUsers (email, password, is_staff, "
                                       "is_active) VALUES (?, ?, ?, ?)", 4, "string", email,
                                       "string", password, "int", is_staff, "int", is_active);
    if (rc < 0) {
        return rc;
    }

    seaf_db_statement_foreach_row (db,
                                    "SELECT id FROM LDAPUsers WHERE email = ?",
                                    get_uid_cb, &uid, 1, "string", email);

    return uid;
}

static int ldap_verify_user_password (CcnetUserManager *manager,
                                      const char *uid,
                                      const char *password)
{
    LDAP *ld = NULL;
    int res;
    GString *filter;
    char *filter_str = NULL;
    char *attrs[2];
    LDAPMessage *msg = NULL, *entry;
    char *dn = NULL;
    int ret = 0;

    /* First search for the DN with the given uid. */

    ld = ldap_init_and_bind (manager,
                             manager->ldap_host,
#ifdef WIN32
                             manager->use_ssl,
#endif
                             manager->user_dn,
                             manager->password);
    if (!ld) {
        ccnet_warning ("Please check USER_DN and PASSWORD settings.\n");
        return -1;
    }

    filter = g_string_new (NULL);
    if (!manager->filter)
        g_string_printf (filter, "(%s=%s)", manager->login_attr, uid);
    else
        g_string_printf (filter, "(&(%s=%s) (%s))",
                         manager->login_attr, uid, manager->filter);
    filter_str = g_string_free (filter, FALSE);

    attrs[0] = manager->login_attr;
    attrs[1] = NULL;

    char **base;
    for (base = manager->base_list; *base; base++) {
        res = ldap_search_s (ld, *base, LDAP_SCOPE_SUBTREE,
                             filter_str, attrs, 0, &msg);
        if (res != LDAP_SUCCESS) {
            ccnet_warning ("ldap_search user '%s=%s' failed for base %s: %s.\n",
                           manager->login_attr, uid, *base, ldap_err2string(res));
            ccnet_warning ("Please check BASE setting in ccnet.conf.\n");
            ret = -1;
            ldap_msgfree (msg);
            goto out;
        }

        entry = ldap_first_entry (ld, msg);
        if (entry) {
            dn = ldap_get_dn (ld, entry);
            ldap_msgfree (msg);
            break;
        }

        ldap_msgfree (msg);
    }

    if (!dn) {
        ccnet_debug ("Cannot find user %s in LDAP.\n", uid);
        ret = -1;
        goto out;
    }

    /* Then bind the DN with password. */

    ldap_unbind_s (ld);

    ld = ldap_init_and_bind (manager,
                             manager->ldap_host,
#ifdef WIN32
                             manager->use_ssl,
#endif
                             dn, password);
    if (!ld) {
        ccnet_debug ("Password incorrect for %s in LDAP.\n", uid);
        ret = -1;
    }

out:
    ldap_memfree (dn);
    g_free (filter_str);
    if (ld) ldap_unbind_s (ld);
    return ret;
}

/*
 * @uid: user's uid, list all users if * is passed in.
 */
static GList *ldap_list_users (CcnetUserManager *manager, const char *uid,
                               int start, int limit)
{
    LDAP *ld = NULL;
    GList *ret = NULL;
    int res;
    GString *filter;
    char *filter_str;
    char *attrs[2];
    LDAPMessage *msg = NULL, *entry;

    ld = ldap_init_and_bind (manager,
                             manager->ldap_host,
#ifdef WIN32
                             manager->use_ssl,
#endif
                             manager->user_dn,
                             manager->password);
    if (!ld) {
        ccnet_warning ("Please check USER_DN and PASSWORD settings.\n");
        return NULL;
    }

    filter = g_string_new (NULL);
    if (!manager->filter)
        g_string_printf (filter, "(%s=%s)", manager->login_attr, uid);
    else
        g_string_printf (filter, "(&(%s=%s) (%s))",
                         manager->login_attr, uid, manager->filter);
    filter_str = g_string_free (filter, FALSE);

    attrs[0] = manager->login_attr;
    attrs[1] = NULL;

    int i = 0;
    if (start == -1)
        start = 0;

    char **base;
    for (base = manager->base_list; *base; ++base) {
        res = ldap_search_s (ld, *base, LDAP_SCOPE_SUBTREE,
                             filter_str, attrs, 0, &msg);
        if (res != LDAP_SUCCESS) {
            ccnet_warning ("ldap_search user '%s=%s' failed for base %s: %s.\n",
                           manager->login_attr, uid, *base, ldap_err2string(res));
            ccnet_warning ("Please check BASE setting in ccnet.conf.\n");
            ret = NULL;
            ldap_msgfree (msg);
            goto out;
        }

        for (entry = ldap_first_entry (ld, msg);
             entry != NULL;
             entry = ldap_next_entry (ld, entry), ++i) {
            char *attr;
            char **vals;
            BerElement *ber;
            CcnetEmailUser *user;

            if (i < start)
                continue;
            if (limit >= 0 && i >= start + limit) {
                ldap_msgfree (msg);
                goto out;
            }

            attr = ldap_first_attribute (ld, entry, &ber);
            vals = ldap_get_values (ld, entry, attr);

            char *email_l = g_ascii_strdown (vals[0], -1);
            user = g_object_new (CCNET_TYPE_EMAIL_USER,
                                 "id", 0,
                                 "email", email_l,
                                 "is_staff", FALSE,
                                 "is_active", TRUE,
                                 "ctime", (gint64)0,
                                 "source", "LDAP",
                                 "password", "!",
                                 NULL);
            g_free (email_l);
            ret = g_list_prepend (ret, user);

            ldap_memfree (attr);
            ldap_value_free (vals);
            ber_free (ber, 0);
        }

        ldap_msgfree (msg);
    }

out:
    g_free (filter_str);
    if (ld) ldap_unbind_s (ld);
    return ret;
}

#endif  /* HAVE_LDAP */

/* -------- DB Operations -------- */

static int check_db_table (SeafDB *db)
{
    char *sql;

    int db_type = seaf_db_type (db);
    if (db_type == SEAF_DB_TYPE_MYSQL) {
        sql = "CREATE TABLE IF NOT EXISTS EmailUser ("
            "id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT, "
            "email VARCHAR(255), passwd VARCHAR(256), "
            "is_staff BOOL NOT NULL, is_active BOOL NOT NULL, "
            "ctime BIGINT, reference_id VARCHAR(255),"
            "UNIQUE INDEX (email), UNIQUE INDEX (reference_id))"
            "ENGINE=INNODB";
        if (seaf_db_query (db, sql) < 0)
            return -1;
        sql = "CREATE TABLE IF NOT EXISTS Binding (id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT, "
            "email VARCHAR(255), peer_id CHAR(41),"
            "UNIQUE INDEX (peer_id), INDEX (email(20)))"
            "ENGINE=INNODB";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE TABLE IF NOT EXISTS UserRole ("
          "id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT, "
          "email VARCHAR(255), role VARCHAR(255), UNIQUE INDEX (email)) "
          "ENGINE=INNODB";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE TABLE IF NOT EXISTS LDAPUsers ("
          "id BIGINT PRIMARY KEY AUTO_INCREMENT, "
          "email VARCHAR(255) NOT NULL, password varchar(255) NOT NULL, "
          "is_staff BOOL NOT NULL, is_active BOOL NOT NULL, extra_attrs TEXT, "
          "reference_id VARCHAR(255), "
          "UNIQUE INDEX(email), UNIQUE INDEX (reference_id)) ENGINE=INNODB";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE TABLE IF NOT EXISTS LDAPConfig ( "
          "id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT, cfg_group VARCHAR(255) NOT NULL,"
          "cfg_key VARCHAR(255) NOT NULL, value VARCHAR(255), property INTEGER) ENGINE=INNODB";
        if (seaf_db_query (db, sql) < 0)
            return -1;

    } else if (db_type == SEAF_DB_TYPE_SQLITE) {
        sql = "CREATE TABLE IF NOT EXISTS EmailUser ("
            "id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,"
            "email TEXT, passwd TEXT, is_staff bool NOT NULL, "
            "is_active bool NOT NULL, ctime INTEGER, "
            "reference_id TEXT)";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE UNIQUE INDEX IF NOT EXISTS email_index on EmailUser (email)";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE UNIQUE INDEX IF NOT EXISTS reference_id_index on EmailUser (reference_id)";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE TABLE IF NOT EXISTS Binding (email TEXT, peer_id TEXT)";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE INDEX IF NOT EXISTS email_index on Binding (email)";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE UNIQUE INDEX IF NOT EXISTS peer_index on Binding (peer_id)";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE TABLE IF NOT EXISTS UserRole (email TEXT, role TEXT)";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE INDEX IF NOT EXISTS userrole_email_index on UserRole (email)";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE UNIQUE INDEX IF NOT EXISTS userrole_userrole_index on UserRole (email, role)";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE TABLE IF NOT EXISTS LDAPUsers ("
          "id INTEGER PRIMARY KEY AUTOINCREMENT, "
          "email TEXT NOT NULL, password TEXT NOT NULL, "
          "is_staff BOOL NOT NULL, is_active BOOL NOT NULL, extra_attrs TEXT, "
          "reference_id TEXT)";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE UNIQUE INDEX IF NOT EXISTS ldapusers_email_index on LDAPUsers(email)";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE UNIQUE INDEX IF NOT EXISTS ldapusers_reference_id_index on LDAPUsers(reference_id)";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE TABLE IF NOT EXISTS LDAPConfig (cfg_group VARCHAR(255) NOT NULL,"
          "cfg_key VARCHAR(255) NOT NULL, value VARCHAR(255), property INTEGER)";
        if (seaf_db_query (db, sql) < 0)
            return -1;

    } else if (db_type == SEAF_DB_TYPE_PGSQL) {
        sql = "CREATE TABLE IF NOT EXISTS EmailUser ("
            "id SERIAL PRIMARY KEY, "
            "email VARCHAR(255), passwd VARCHAR(256), "
            "is_staff INTEGER NOT NULL, is_active INTEGER NOT NULL, "
            "ctime BIGINT, reference_id VARCHAR(255), UNIQUE (email))";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        //if (!pgsql_index_exists (db, "emailuser_reference_id_idx")) {
        //    sql = "CREATE UNIQUE INDEX emailuser_reference_id_idx ON EmailUser (reference_id)";
        //    if (seaf_db_query (db, sql) < 0)
        //        return -1;
        //}

        sql = "CREATE TABLE IF NOT EXISTS Binding (email VARCHAR(255), peer_id CHAR(41),"
            "UNIQUE (peer_id))";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE TABLE IF NOT EXISTS UserRole (email VARCHAR(255), "
          " role VARCHAR(255), UNIQUE (email, role))";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        //if (!pgsql_index_exists (db, "userrole_email_idx")) {
        //    sql = "CREATE INDEX userrole_email_idx ON UserRole (email)";
        //    if (seaf_db_query (db, sql) < 0)
        //        return -1;
        //}

        sql = "CREATE TABLE IF NOT EXISTS LDAPUsers ("
          "id SERIAL PRIMARY KEY, "
          "email VARCHAR(255) NOT NULL, password VARCHAR(255) NOT NULL, "
          "is_staff SMALLINT NOT NULL, is_active SMALLINT NOT NULL, extra_attrs TEXT,"
          "reference_id VARCHAR(255))";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        //if (!pgsql_index_exists (db, "ldapusers_email_idx")) {
        //    sql = "CREATE UNIQUE INDEX ldapusers_email_idx ON LDAPUsers (email)";
        //    if (seaf_db_query (db, sql) < 0)
        //        return -1;
        //}

        //if (!pgsql_index_exists (db, "ldapusers_reference_id_idx")) {
        //    sql = "CREATE UNIQUE INDEX ldapusers_reference_id_idx ON LDAPUsers (reference_id)";
        //    if (seaf_db_query (db, sql) < 0)
        //        return -1;
        //}

        sql = "CREATE TABLE IF NOT EXISTS LDAPConfig (cfg_group VARCHAR(255) NOT NULL,"
          "cfg_key VARCHAR(255) NOT NULL, value VARCHAR(255), property INTEGER)";
        if (seaf_db_query (db, sql) < 0)
            return -1;
    }

    return 0;
}


static CcnetDB *
open_sqlite_db (CcnetUserManager *manager)
{
    CcnetDB *db = NULL;
    char *db_dir;
    char *db_path;

    db_dir = g_build_filename (manager->session->ccnet_dir, "PeerMgr", NULL);
    if (checkdir_with_mkdir(db_dir) < 0) {
        ccnet_error ("Cannot open db dir %s: %s\n", db_dir,
                     strerror(errno));
        return NULL;
    }
    g_free (db_dir);

    db_path = g_build_filename (manager->session->ccnet_dir, "PeerMgr",
                                "usermgr.db", NULL);
    db = seaf_db_new_sqlite (db_path, DEFAULT_MAX_CONNECTIONS);
    g_free (db_path);

    return db;
}

static int
open_db (CcnetUserManager *manager)
{
    CcnetDB *db = NULL;

    switch (seaf_db_type(manager->session->ccnet_db)) {
    /* To be compatible with the db file layout of 0.9.1 version,
     * we don't use conf-dir/ccnet.db for user and peer info, but
     * user conf-dir/PeerMgr/peermgr.db and conf-dir/PeerMgr/usermgr.db instead.
     */
    case SEAF_DB_TYPE_SQLITE:
        db = open_sqlite_db (manager);
        break;
    case SEAF_DB_TYPE_PGSQL:
    case SEAF_DB_TYPE_MYSQL:
        db = manager->session->ccnet_db;
        break;
    }

    if (!db)
        return -1;

    manager->priv->db = db;
    if ((manager->session->ccnet_create_tables || seaf_db_type(db) == SEAF_DB_TYPE_PGSQL)
        && check_db_table (db) < 0) {
        ccnet_warning ("Failed to create user db tables.\n");
        return -1;
    }
    return 0;
}


/* -------- EmailUser Management -------- */

/* This fixed salt is used in very early versions. It's kept for compatibility.
 * For the current password hashing algorithm, please see hash_password_pbkdf2_sha256()
 */
static unsigned char salt[8] = { 0xdb, 0x91, 0x45, 0xc3, 0x06, 0xc7, 0xcc, 0x26 };

static void
hash_password (const char *passwd, char *hashed_passwd)
{
    unsigned char sha1[20];
    SHA_CTX s;

    SHA1_Init (&s);
    SHA1_Update (&s, passwd, strlen(passwd));
    SHA1_Final (sha1, &s);
    rawdata_to_hex (sha1, hashed_passwd, 20);
}

static void
hash_password_salted (const char *passwd, char *hashed_passwd)
{
    unsigned char sha[SHA256_DIGEST_LENGTH];
    SHA256_CTX s;

    SHA256_Init (&s);
    SHA256_Update (&s, passwd, strlen(passwd));
    SHA256_Update (&s, salt, sizeof(salt));
    SHA256_Final (sha, &s);
    rawdata_to_hex (sha, hashed_passwd, SHA256_DIGEST_LENGTH);
}

static void
hash_password_pbkdf2_sha256 (const char *passwd,
                             int iterations,
                             char **db_passwd)
{
    guint8 sha[SHA256_DIGEST_LENGTH];
    guint8 salt[SHA256_DIGEST_LENGTH];
    char hashed_passwd[SHA256_DIGEST_LENGTH*2+1];
    char salt_str[SHA256_DIGEST_LENGTH*2+1];

    if (!RAND_bytes (salt, sizeof(salt))) {
        ccnet_warning ("Failed to generate salt "
                       "with RAND_bytes(), use RAND_pseudo_bytes().\n");
        RAND_pseudo_bytes (salt, sizeof(salt));
    }

    PKCS5_PBKDF2_HMAC (passwd, strlen(passwd),
                       salt, sizeof(salt),
                       iterations,
                       EVP_sha256(),
                       sizeof(sha), sha);

    rawdata_to_hex (sha, hashed_passwd, SHA256_DIGEST_LENGTH);

    rawdata_to_hex (salt, salt_str, SHA256_DIGEST_LENGTH);

    /* Encode password hash related information into one string, similar to Django. */
    GString *buf = g_string_new (NULL);
    g_string_printf (buf, "PBKDF2SHA256$%d$%s$%s",
                     iterations, salt_str, hashed_passwd);
    *db_passwd = g_string_free (buf, FALSE);
}

static gboolean
validate_passwd_pbkdf2_sha256 (const char *passwd, const char *db_passwd)
{
    char **tokens;
    char *salt_str, *hash;
    int iter;
    guint8 sha[SHA256_DIGEST_LENGTH];
    guint8 salt[SHA256_DIGEST_LENGTH];
    char hashed_passwd[SHA256_DIGEST_LENGTH*2+1];

    if (g_strcmp0 (db_passwd, "!") == 0)
        return FALSE;

    tokens = g_strsplit (db_passwd, "$", -1);
    if (!tokens || g_strv_length (tokens) != 4) {
        if (tokens)
            g_strfreev (tokens);
        ccnet_warning ("Invalide db passwd format %s.\n", db_passwd);
        return FALSE;
    }

    iter = atoi (tokens[1]);
    salt_str = tokens[2];
    hash = tokens[3];

    hex_to_rawdata (salt_str, salt, SHA256_DIGEST_LENGTH);

    PKCS5_PBKDF2_HMAC (passwd, strlen(passwd),
                       salt, sizeof(salt),
                       iter,
                       EVP_sha256(),
                       sizeof(sha), sha);
    rawdata_to_hex (sha, hashed_passwd, SHA256_DIGEST_LENGTH);

    gboolean ret = (strcmp (hash, hashed_passwd) == 0);

    g_strfreev (tokens);
    return ret;
}

static gboolean
validate_passwd (const char *passwd, const char *stored_passwd,
                 gboolean *need_upgrade)
{
    char hashed_passwd[SHA256_DIGEST_LENGTH * 2 + 1];
    int hash_len = strlen(stored_passwd);

    *need_upgrade = FALSE;

    if (hash_len == SHA256_DIGEST_LENGTH * 2) {
        hash_password_salted (passwd, hashed_passwd);
        *need_upgrade = TRUE;
    } else if (hash_len == SHA_DIGEST_LENGTH * 2) {
        hash_password (passwd, hashed_passwd);
        *need_upgrade = TRUE;
    } else {
        return validate_passwd_pbkdf2_sha256 (passwd, stored_passwd);
    }

    if (strcmp (hashed_passwd, stored_passwd) == 0)
        return TRUE;
    else
        return FALSE;
}

static int
update_user_passwd (CcnetUserManager *manager,
                    const char *email, const char *passwd)
{
    CcnetDB *db = manager->priv->db;
    char *db_passwd = NULL;
    int ret;

    hash_password_pbkdf2_sha256 (passwd, manager->passwd_hash_iter,
                                 &db_passwd);

    /* convert email to lower case for case insensitive lookup. */
    char *email_down = g_ascii_strdown (email, strlen(email));

    ret = seaf_db_statement_query (db,
                                    "UPDATE EmailUser SET passwd=? WHERE email=?",
                                    2, "string", db_passwd, "string", email_down);

    g_free (db_passwd);
    g_free (email_down);

    if (ret < 0)
        return ret;

    return 0;
}

int
ccnet_user_manager_add_emailuser (CcnetUserManager *manager,
                                  const char *email,
                                  const char *passwd,
                                  int is_staff, int is_active)
{
    CcnetDB *db = manager->priv->db;
    gint64 now = get_current_time();
    char *db_passwd = NULL;
    int ret;

    if (!check_user_number (manager, FALSE)) {
        return -1;
    }

    /* A user with unhashed "!" as password cannot be logged in.
     * Such users are created for book keeping, such as users from
     * Shibboleth.
     */
    if (g_strcmp0 (passwd, "!") != 0)
        hash_password_pbkdf2_sha256 (passwd, manager->passwd_hash_iter,
                                     &db_passwd);
    else
        db_passwd = g_strdup(passwd);

    /* convert email to lower case for case insensitive lookup. */
    char *email_down = g_ascii_strdown (email, strlen(email));

    ret = seaf_db_statement_query (db,
                                    "INSERT INTO EmailUser(email, passwd, is_staff, "
                                    "is_active, ctime) VALUES (?, ?, ?, ?, ?)",
                                    5, "string", email_down, "string", db_passwd,
                                    "int", is_staff, "int", is_active, "int64", now);

    g_free (db_passwd);
    g_free (email_down);

    if (ret < 0)
        return ret;

    return 0;
}

int
ccnet_user_manager_remove_emailuser (CcnetUserManager *manager,
                                     const char *source,
                                     const char *email)
{
    CcnetDB *db = manager->priv->db;
    int ret;

    seaf_db_statement_query (db,
                              "DELETE FROM UserRole WHERE email=?",
                              1, "string", email);

    if (strcmp (source, "DB") == 0) {
        ret = seaf_db_statement_query (db,
                                        "DELETE FROM EmailUser WHERE email=?",
                                        1, "string", email);
        return ret;
    }

#ifdef HAVE_LDAP
    if (strcmp (source, "LDAP") == 0 && manager->use_ldap) {
        ret = seaf_db_statement_query (db,
                                        "DELETE FROM LDAPUsers WHERE email=?",
                                        1, "string", email);
        return ret;
    }
#endif

    return -1;
}

static gboolean
get_password (CcnetDBRow *row, void *data)
{
    char **p_passwd = data;

    *p_passwd = g_strdup(seaf_db_row_get_column_text (row, 0));
    return FALSE;
}

int
ccnet_user_manager_validate_emailuser (CcnetUserManager *manager,
                                       const char *email,
                                       const char *passwd)
{
    CcnetDB *db = manager->priv->db;
    int ret = -1;
    char *sql;
    char *email_down;
    char *login_id;
    char *stored_passwd = NULL;
    gboolean need_upgrade = FALSE;

    /* Users with password "!" are for internal book keeping only. */
    if (g_strcmp0 (passwd, "!") == 0)
        return -1;

    login_id = ccnet_user_manager_get_login_id (manager, email);
    if (!login_id) {
        ccnet_warning ("Failed to get login_id for %s\n", email);
        return -1;
    }

#ifdef HAVE_LDAP
    if (manager->use_ldap) {
        if (ldap_verify_user_password (manager, login_id, passwd) == 0) {
            ret = 0;
            goto out;
        }
    }
#endif

    sql = "SELECT passwd FROM EmailUser WHERE email=?";
    if (seaf_db_statement_foreach_row (db, sql,
                                        get_password, &stored_passwd,
                                        1, "string", login_id) > 0) {
        if (validate_passwd (passwd, stored_passwd, &need_upgrade)) {
            if (need_upgrade)
                update_user_passwd (manager, login_id, passwd);
            ret = 0;
            goto out;
        } else {
            goto out;
        }
    }

    email_down = g_ascii_strdown (email, strlen(login_id));
    if (seaf_db_statement_foreach_row (db, sql,
                                        get_password, &stored_passwd,
                                        1, "string", email_down) > 0) {
        g_free (email_down);
        if (validate_passwd (passwd, stored_passwd, &need_upgrade)) {
            if (need_upgrade)
                update_user_passwd (manager, login_id, passwd);
            ret = 0;
            goto out;
        } else {
            goto out;
        }
    }
    g_free (email_down);

out:

    g_free (login_id);
    g_free (stored_passwd);

    return ret;
}

static gboolean
get_emailuser_cb (CcnetDBRow *row, void *data)
{
    CcnetEmailUser **p_emailuser = data;

    int id = seaf_db_row_get_column_int (row, 0);
    const char *email = (const char *)seaf_db_row_get_column_text (row, 1);
    int is_staff = seaf_db_row_get_column_int (row, 2);
    int is_active = seaf_db_row_get_column_int (row, 3);
    gint64 ctime = seaf_db_row_get_column_int64 (row, 4);
    const char *password = seaf_db_row_get_column_text (row, 5);
    const char *reference_id = seaf_db_row_get_column_text (row, 6);
    const char *role = seaf_db_row_get_column_text (row, 7);

    char *email_l = g_ascii_strdown (email, -1);
    *p_emailuser = g_object_new (CCNET_TYPE_EMAIL_USER,
                                 "id", id,
                                 "email", email_l,
                                 "is_staff", is_staff,
                                 "is_active", is_active,
                                 "ctime", ctime,
                                 "source", "DB",
                                 "password", password,
                                 "reference_id", reference_id,
                                 "role", role ? role : "",
                                 NULL);
    g_free (email_l);

    return FALSE;
}

static char*
ccnet_user_manager_get_role_emailuser (CcnetUserManager *manager,
                                     const char* email);

static gboolean
get_ldap_emailuser_cb (CcnetDBRow *row, void *data)
{
    CcnetEmailUser **p_emailuser = data;

    int id = seaf_db_row_get_column_int (row, 0);
    const char *email = (const char *)seaf_db_row_get_column_text (row, 1);
    int is_staff = seaf_db_row_get_column_int (row, 2);
    int is_active = seaf_db_row_get_column_int (row, 3);
    const char *reference_id = seaf_db_row_get_column_text (row, 4);
    const char *role = seaf_db_row_get_column_text (row, 5);

    *p_emailuser = g_object_new (CCNET_TYPE_EMAIL_USER,
                                 "id", id,
                                 "email", email,
                                 "is_staff", is_staff,
                                 "is_active", is_active,
                                 "ctime", (gint64)0,
                                 "source", "LDAPImport",
                                 "password", "!",
                                 "reference_id", reference_id,
                                 "role", role ? role : "",
                                 NULL);

    return FALSE;
}

static CcnetEmailUser*
get_emailuser (CcnetUserManager *manager,
               const char *email,
               gboolean import,
               GError **error)
{
    CcnetDB *db = manager->priv->db;
    char *sql;
    CcnetEmailUser *emailuser = NULL;
    char *email_down;
    int rc;

    sql = "SELECT e.id, e.email, is_staff, is_active, ctime, passwd, reference_id, role "
        " FROM EmailUser e LEFT JOIN UserRole ON e.email = UserRole.email "
        " WHERE e.email=?";
    rc = seaf_db_statement_foreach_row (db, sql, get_emailuser_cb, &emailuser,
                                         1, "string", email);
    if (rc > 0) {
        return emailuser;
    } else if (rc < 0) {
        if (error) {
            g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL, "Database error");
        }
        return NULL;
    }

    email_down = g_ascii_strdown (email, strlen(email));
    rc = seaf_db_statement_foreach_row (db, sql, get_emailuser_cb, &emailuser,
                                         1, "string", email_down);
    if (rc > 0) {
        g_free (email_down);
        return emailuser;
    } else if (rc < 0) {
        if (error) {
            g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL, "Database error");
        }
        g_free (email_down);
        return NULL;
    }

#ifdef HAVE_LDAP
    if (manager->use_ldap) {
        int ret = seaf_db_statement_foreach_row (db,
                                                  "SELECT l.id, l.email, is_staff, is_active, "
                                                  "reference_id, role "
                                                  "FROM LDAPUsers l LEFT JOIN UserRole ON "
                                                  "l.email = UserRole.email WHERE l.email = ?",
                                                  get_ldap_emailuser_cb,
                                                  &emailuser, 1, "string", email_down);
        if (ret < 0) {
            if (error) {
                g_set_error (error, CCNET_DOMAIN, CCNET_ERR_INTERNAL, "Database error");
            }
            ccnet_warning ("get ldapuser from db failed.\n");
            g_free (email_down);
            return NULL;
        }

        if (!emailuser) {
            GList *users, *ptr;

            users = ldap_list_users (manager, email, -1, -1);
            if (!users) {
                /* Only print warning if this function is called in login. */
                if (import)
                    ccnet_warning ("Cannot find user %s in LDAP.\n", email);
                g_free (email_down);
                return NULL;
            }
            emailuser = users->data;

            /* Free all except the first user. */
            for (ptr = users->next; ptr; ptr = ptr->next)
                g_object_unref (ptr->data);
            g_list_free (users);

            if (import) {
                if (!check_user_number (manager, FALSE)) {
                    g_free (email_down);
                    g_object_unref (emailuser);
                    return NULL;
                }

                // add user to LDAPUsers
                ret = add_ldapuser (manager->priv->db, email_down, "",
                                    FALSE, TRUE, NULL);
                if (ret < 0) {
                    ccnet_warning ("add ldapuser to db failed.\n");
                    g_free (email_down);
                    g_object_unref (emailuser);
                    return NULL;
                }

                g_object_set (emailuser, "id", ret, NULL);
            }
        }

        g_free (email_down);
        return emailuser;
    }
#endif

    g_free (email_down);

    return NULL;

}

CcnetEmailUser*
ccnet_user_manager_get_emailuser (CcnetUserManager *manager,
                                  const char *email,
                                  GError **error)
{
    return get_emailuser (manager, email, FALSE, error);
}

CcnetEmailUser*
ccnet_user_manager_get_emailuser_with_import (CcnetUserManager *manager,
                                              const char *email,
                                              GError **error)
{
    return get_emailuser (manager, email, TRUE, error);
}

CcnetEmailUser*
ccnet_user_manager_get_emailuser_by_id (CcnetUserManager *manager, int id)
{
    CcnetDB *db = manager->priv->db;
    char *sql;
    CcnetEmailUser *emailuser = NULL;

    sql = "SELECT e.id, e.email, is_staff, is_active, ctime, passwd, reference_id, role "
        " FROM EmailUser e LEFT JOIN UserRole ON e.email = UserRole.email "
        " WHERE e.id=?";
    if (seaf_db_statement_foreach_row (db, sql, get_emailuser_cb, &emailuser,
                                        1, "int", id) < 0)
        return NULL;

    return emailuser;
}

static gboolean
get_emailusers_cb (CcnetDBRow *row, void *data)
{
    GList **plist = data;
    CcnetEmailUser *emailuser;

    int id = seaf_db_row_get_column_int (row, 0);
    const char *email = (const char *)seaf_db_row_get_column_text (row, 1);
    int is_staff = seaf_db_row_get_column_int (row, 2);
    int is_active = seaf_db_row_get_column_int (row, 3);
    gint64 ctime = seaf_db_row_get_column_int64 (row, 4);
    const char *role = (const char *)seaf_db_row_get_column_text (row, 5);
    const char *password = seaf_db_row_get_column_text (row, 6);

    char *email_l = g_ascii_strdown (email, -1);
    emailuser = g_object_new (CCNET_TYPE_EMAIL_USER,
                              "id", id,
                              "email", email_l,
                              "is_staff", is_staff,
                              "is_active", is_active,
                              "ctime", ctime,
                              "role", role ? role : "",
                              "source", "DB",
                              "password", password,
                              NULL);
    g_free (email_l);

    *plist = g_list_prepend (*plist, emailuser);

    return TRUE;
}

static gboolean
get_ldap_emailusers_cb (CcnetDBRow *row, void *data)
{
    GList **plist = data;
    CcnetEmailUser *emailuser = NULL;

    int id = seaf_db_row_get_column_int (row, 0);
    const char *email = (const char *)seaf_db_row_get_column_text (row, 1);
    int is_staff = seaf_db_row_get_column_int (row, 2);
    int is_active = seaf_db_row_get_column_int (row, 3);
    const char *role = seaf_db_row_get_column_text (row, 4);

    emailuser = g_object_new (CCNET_TYPE_EMAIL_USER,
                              "id", id,
                              "email", email,
                              "is_staff", is_staff,
                              "is_active", is_active,
                              "ctime", (gint64)0,
                              "role", role ? role : "",
                              "source", "LDAPImport",
                              "password", "!",
                              NULL);
    if (!emailuser)
        return FALSE;

    *plist = g_list_prepend (*plist, emailuser);

    return TRUE;
}

GList*
ccnet_user_manager_get_emailusers (CcnetUserManager *manager,
                                   const char *source,
                                   int start, int limit,
                                   const char *status)
{
    CcnetDB *db = manager->priv->db;
    const char *status_condition = "";
    char *sql = NULL;
    GList *ret = NULL;
    int rc;

#ifdef HAVE_LDAP
    if (manager->use_ldap) {
        GList *users = NULL;

        if (g_strcmp0 (source, "LDAP") == 0) {
            users = ldap_list_users (manager, "*", start, limit);
            return g_list_reverse (users);
        } else if (g_strcmp0 (source, "LDAPImport") == 0) {
            if (start == -1 && limit == -1) {
                if (g_strcmp0(status, "active") == 0)
                    status_condition = "WHERE t1.is_active = 1";
                else if (g_strcmp0(status, "inactive") == 0)
                    status_condition = "WHERE t1.is_active = 0";

                sql = g_strdup_printf ("SELECT t1.id, t1.email, t1.is_staff, "
                                       "t1.is_active, t2.role "
                                       "FROM LDAPUsers t1 LEFT JOIN UserRole t2 "
                                       "ON t1.email = t2.email %s",
                                       status_condition);

                rc = seaf_db_statement_foreach_row (db,
                                                     sql,
                                                     get_ldap_emailusers_cb,
                                                     &users, 0);
                g_free (sql);
            } else {
                if (g_strcmp0(status, "active") == 0)
                    status_condition = "WHERE t1.is_active = 1";
                else if (g_strcmp0(status, "inactive") == 0)
                    status_condition = "WHERE t1.is_active = 0";

                sql = g_strdup_printf ("SELECT t1.id, t1.email, t1.is_staff, "
                                       "t1.is_active, t2.role "
                                       "FROM LDAPUsers t1 LEFT JOIN UserRole t2 "
                                       "ON t1.email = t2.email %s LIMIT ? OFFSET ?",
                                       status_condition);

                rc = seaf_db_statement_foreach_row (db,
                                                     sql,
                                                     get_ldap_emailusers_cb,
                                                     &users, 2, "int", limit, "int", start);
                g_free (sql);
            }

            if (rc < 0) {
                while (users) {
                    g_object_unref (users->data);
                    users = g_list_delete_link (users, users);
                }
                return NULL;
            }
            return g_list_reverse (users);
        }
    }
#endif

    if (g_strcmp0 (source, "DB") != 0)
        return NULL;

    if (start == -1 && limit == -1) {
        if (g_strcmp0(status, "active") == 0)
            status_condition = "WHERE t1.is_active = 1";
        else if (g_strcmp0(status, "inactive") == 0)
            status_condition = "WHERE t1.is_active = 0";

        sql = g_strdup_printf ("SELECT t1.id, t1.email, "
                               "t1.is_staff, t1.is_active, t1.ctime, "
                               "t2.role, t1.passwd FROM EmailUser t1 "
                               "LEFT JOIN UserRole t2 "
                               "ON t1.email = t2.email %s "
                               "WHERE t1.email NOT LIKE '%%@seafile_group'",
                               status_condition);

        rc = seaf_db_statement_foreach_row (db,
                                             sql,
                                             get_emailusers_cb, &ret,
                                             0);
        g_free (sql);
    } else {
        if (g_strcmp0(status, "active") == 0)
            status_condition = "WHERE t1.is_active = 1";
        else if (g_strcmp0(status, "inactive") == 0)
            status_condition = "WHERE t1.is_active = 0";

        sql = g_strdup_printf ("SELECT t1.id, t1.email, "
                               "t1.is_staff, t1.is_active, t1.ctime, "
                               "t2.role, t1.passwd FROM EmailUser t1 "
                               "LEFT JOIN UserRole t2 "
                               "ON t1.email = t2.email %s "
                               "WHERE t1.email NOT LIKE '%%@seafile_group' "
                               "ORDER BY t1.id LIMIT ? OFFSET ?",
                               status_condition);

        rc = seaf_db_statement_foreach_row (db,
                                             sql,
                                             get_emailusers_cb, &ret,
                                             2, "int", limit, "int", start);
        g_free (sql);
    }

    if (rc < 0) {
        while (ret != NULL) {
            g_object_unref (ret->data);
            ret = g_list_delete_link (ret, ret);
        }
        return NULL;
    }

    return g_list_reverse (ret);
}

GList*
ccnet_user_manager_search_emailusers (CcnetUserManager *manager,
                                      const char *source,
                                      const char *keyword,
                                      int start, int limit)
{
    CcnetDB *db = manager->priv->db;
    GList *ret = NULL;
    int rc;
    char *db_patt = g_strdup_printf ("%%%s%%", keyword);

#ifdef HAVE_LDAP
    if (manager->use_ldap) {
        if (strcmp (source, "LDAP") == 0) {
            if (start == -1 && limit == -1) {
                rc = seaf_db_statement_foreach_row (db,
                                                     "SELECT t1.id, t1.email, t1.is_staff, "
                                                     "t1.is_active, t2.role "
                                                     "FROM LDAPUsers t1 LEFT JOIN UserRole t2 "
                                                     "ON t1.email = t2.email WHERE t1.email LIKE ?",
                                                     get_ldap_emailusers_cb,
                                                     &ret, 1, "string", db_patt);
            } else {
                rc = seaf_db_statement_foreach_row (db,
                                                     "SELECT t1.id, t1.email, t1.is_staff, "
                                                     "t1.is_active, t2.role "
                                                     "FROM LDAPUsers t1 LEFT JOIN UserRole t2 "
                                                     "ON t1.email = t2.email WHERE t1.email LIKE ? "
                                                     "LIMIT ? OFFSET ?",
                                                     get_ldap_emailusers_cb,
                                                     &ret, 3, "string", db_patt,
                                                     "int", limit, "int", start);
            }

            g_free (db_patt);

            if (rc < 0) {
                while (ret) {
                    g_object_unref (ret->data);
                    ret = g_list_delete_link (ret, ret);
                }
                return NULL;
            }
            return g_list_reverse (ret);
        }
    }
#endif

    if (strcmp (source, "DB") != 0) {
        g_free (db_patt);
        return NULL;
    }

    if (start == -1 && limit == -1)
        rc = seaf_db_statement_foreach_row (db,
                                             "SELECT t1.id, t1.email, "
                                             "t1.is_staff, t1.is_active, t1.ctime, "
                                             "t2.role, t1.passwd FROM EmailUser t1 "
                                             "LEFT JOIN UserRole t2 "
                                             "ON t1.email = t2.email "
                                             "WHERE t1.Email LIKE ? "
                                             "AND t1.email NOT LIKE '%%@seafile_group' "
                                             "ORDER BY t1.id",
                                             get_emailusers_cb, &ret,
                                             1, "string", db_patt);
    else
        rc = seaf_db_statement_foreach_row (db,
                                             "SELECT t1.id, t1.email, "
                                             "t1.is_staff, t1.is_active, t1.ctime, "
                                             "t2.role, t1.passwd FROM EmailUser t1 "
                                             "LEFT JOIN UserRole t2 "
                                             "ON t1.email = t2.email "
                                             "WHERE t1.Email LIKE ? "
                                             "AND t1.email NOT LIKE '%%@seafile_group' "
                                             "ORDER BY t1.id LIMIT ? OFFSET ?",
                                             get_emailusers_cb, &ret,
                                             3, "string", db_patt,
                                             "int", limit, "int", start);
    g_free (db_patt);
    if (rc < 0) {
        while (ret != NULL) {
            g_object_unref (ret->data);
            ret = g_list_delete_link (ret, ret);
        }
        return NULL;
    }

    return g_list_reverse (ret);
}

GList*
ccnet_user_manager_search_ldapusers (CcnetUserManager *manager,
                                     const char *keyword,
                                     int start, int limit)
{
    GList *ret = NULL;

#ifdef HAVE_LDAP
    if (!manager->use_ldap) {
        return NULL;
    }

    char *ldap_patt = g_strdup_printf ("*%s*", keyword);

    ret = ldap_list_users (manager, ldap_patt, start, limit);

    g_free (ldap_patt);
#endif

    return ret;
}

gint64
ccnet_user_manager_count_emailusers (CcnetUserManager *manager, const char *source)
{
    CcnetDB* db = manager->priv->db;
    char sql[512];
    gint64 ret;

#ifdef HAVE_LDAP
    if (manager->use_ldap && g_strcmp0(source, "LDAP") == 0) {
        gint64 ret = seaf_db_get_int64 (db, "SELECT COUNT(id) FROM LDAPUsers WHERE is_active = 1");
        if (ret < 0)
            return -1;
        return ret;
    }
#endif

    if (g_strcmp0 (source, "DB") != 0)
        return -1;

    snprintf (sql, 512, "SELECT COUNT(id) FROM EmailUser WHERE is_active = 1");

    ret = seaf_db_get_int64 (db, sql);
    if (ret < 0)
        return -1;
    return ret;
}

gint64
ccnet_user_manager_count_inactive_emailusers (CcnetUserManager *manager, const char *source)
{
    CcnetDB* db = manager->priv->db;
    char sql[512];
    gint64 ret;

#ifdef HAVE_LDAP
    if (manager->use_ldap && g_strcmp0(source, "LDAP") == 0) {
        gint64 ret = seaf_db_get_int64 (db, "SELECT COUNT(id) FROM LDAPUsers WHERE is_active = 0");
        if (ret < 0)
            return -1;
        return ret;
    }
#endif

    if (g_strcmp0 (source, "DB") != 0)
        return -1;

    snprintf (sql, 512, "SELECT COUNT(id) FROM EmailUser WHERE is_active = 0");

    ret = seaf_db_get_int64 (db, sql);
    if (ret < 0)
        return -1;
    return ret;
}

#if 0
GList*
ccnet_user_manager_filter_emailusers_by_emails(CcnetUserManager *manager,
                                               const char *emails)
{
    CcnetDB *db = manager->priv->db;
    char *copy = g_strdup (emails), *saveptr;
    GList *ret = NULL;

#ifdef HAVE_LDAP
    if (manager->use_ldap)
        return NULL;            /* todo */
#endif

    GString *sql = g_string_new(NULL);

    g_string_append (sql, "SELECT * FROM EmailUser WHERE Email IN (");
    char *name = strtok_r (copy, ", ", &saveptr);
    while (name != NULL) {
        g_string_append_printf (sql, "'%s',", name);
        name = strtok_r (NULL, ", ", &saveptr);
    }
    g_string_erase (sql, sql->len-1, 1); /* remove last "," */
    g_string_append (sql, ")");

    if (seaf_db_foreach_selected_row (db, sql->str, get_emailusers_cb,
        &ret) < 0) {
        while (ret != NULL) {
            g_object_unref (ret->data);
            ret = g_list_delete_link (ret, ret);
        }
        return NULL;
    }

    g_free (copy);
    g_string_free (sql, TRUE);

    return g_list_reverse (ret);
}
#endif

int
ccnet_user_manager_update_emailuser (CcnetUserManager *manager,
                                     const char *source,
                                     int id, const char* passwd,
                                     int is_staff, int is_active)
{
    CcnetDB* db = manager->priv->db;
    char *db_passwd = NULL;

    // in case set user user1 to inactive, then add another active user user2,
    // if current user num already the max user num,
    // then reset user1 to active should fail
    if (is_active && !check_user_number (manager, FALSE)) {
        return -1;
    }

    if (strcmp (source, "DB") == 0) {
        if (g_strcmp0 (passwd, "!") == 0) {
            /* Don't update passwd if it starts with '!' */
            return seaf_db_statement_query (db, "UPDATE EmailUser SET is_staff=?, "
                                             "is_active=? WHERE id=?",
                                             3, "int", is_staff, "int", is_active,
                                             "int", id);
        } else {
            hash_password_pbkdf2_sha256 (passwd, manager->passwd_hash_iter, &db_passwd);

            return seaf_db_statement_query (db, "UPDATE EmailUser SET passwd=?, "
                                             "is_staff=?, is_active=? WHERE id=?",
                                             4, "string", db_passwd, "int", is_staff,
                                             "int", is_active, "int", id);
        }
    }

#ifdef HAVE_LDAP
    if (manager->use_ldap && strcmp (source, "LDAP") == 0) {
        return seaf_db_statement_query (db, "UPDATE LDAPUsers SET is_staff=?, "
                                         "is_active=? WHERE id=?",
                                         3, "int", is_staff, "int", is_active,
                                         "int", id);
    }
#endif

    return -1;
}

static gboolean
get_role_emailuser_cb (CcnetDBRow *row, void *data)
{
    *((char **)data) = g_strdup (seaf_db_row_get_column_text (row, 0));

    return FALSE;
}

static char*
ccnet_user_manager_get_role_emailuser (CcnetUserManager *manager,
                                     const char* email)
{

    CcnetDB *db = manager->priv->db;
    const char *sql;
    char* role;

    sql = "SELECT role FROM UserRole WHERE email=?";
    if (seaf_db_statement_foreach_row (db, sql, get_role_emailuser_cb, &role,
                                        1, "string", email) > 0)
        return role;

    return NULL;
}

int
ccnet_user_manager_update_role_emailuser (CcnetUserManager *manager,
                                     const char* email, const char* role)
{
    CcnetDB* db = manager->priv->db;
    char *old_role = ccnet_user_manager_get_role_emailuser (manager, email);
    if (old_role) {
        g_free (old_role);
        return seaf_db_statement_query (db, "UPDATE UserRole SET role=? "
                                         "WHERE email=?",
                                         2, "string", role, "string", email);
    } else
        return seaf_db_statement_query (db, "INSERT INTO UserRole(role, email)"
                                         " VALUES (?, ?)",
                                         2, "string", role, "string", email);
}

GList*
ccnet_user_manager_get_superusers(CcnetUserManager *manager)
{
    CcnetDB* db = manager->priv->db;
    GList *ret = NULL;
    char sql[512];

    snprintf (sql, 512,
              "SELECT t1.id, t1.email, "
              "t1.is_staff, t1.is_active, t1.ctime, "
              "t2.role, t1.passwd FROM EmailUser t1 "
              "LEFT JOIN UserRole t2 "
              "ON t1.email = t2.email "
              "WHERE is_staff = 1 AND t1.email NOT LIKE '%%@seafile_group';");

    if (seaf_db_foreach_selected_row (db, sql, get_emailusers_cb, &ret) < 0) {
        while (ret != NULL) {
            g_object_unref (ret->data);
            ret = g_list_delete_link (ret, ret);
        }
        return NULL;
    }

    if (seaf_db_foreach_selected_row (db,
                                       "SELECT t1.id, t1.email, "
                                       "t1.is_staff, t1.is_active, "
                                       "t2.role FROM LDAPUsers t1 "
                                       "LEFT JOIN UserRole t2 "
                                       "ON t1.email = t2.email "
                                       "WHERE is_staff = 1",
                                       get_ldap_emailusers_cb, &ret) < 0) {
        while (ret != NULL) {
            g_object_unref (ret->data);
            ret = g_list_delete_link (ret, ret);
        }
        return NULL;
    }

    return g_list_reverse (ret);
}

int
ccnet_user_manager_set_reference_id (CcnetUserManager *manager,
                                   const char *primary_id,
                                   const char *reference_id,
                                   GError **error)
{
    int rc;
    char *sql;
    gboolean exists, err;

#ifdef HAVE_LDAP
    if (manager->use_ldap) {
        sql = "SELECT email FROM LDAPUsers WHERE email = ?";
        exists = seaf_db_statement_exists (manager->priv->db, sql, &err,
                                            1, "string", primary_id);
        if (err)
            return -1;
        /* Make sure reference_id is unique */
        if (exists) {
            sql = "SELECT 1 FROM EmailUser e, LDAPUsers l "
                  "WHERE (e.reference_id=? AND e.email!=?) OR "
                  "(l.reference_id=? AND l.email!=?) OR "
                  "(e.email=? AND e.email!=?) OR (l.email=? AND l.email!=?)";
            exists = seaf_db_statement_exists (manager->priv->db, sql, &err,
                                                8, "string", reference_id,
                                                "string", primary_id,
                                                "string", reference_id,
                                                "string", primary_id,
                                                "string", reference_id,
                                                "string", primary_id,
                                                "string", reference_id,
                                                "string", primary_id);
            if (err)
                return -1;
            if (exists) {
                ccnet_warning ("Failed to set reference id, email '%s' exists\n", reference_id);
                return -1;
            }

            sql = "UPDATE LDAPUsers SET reference_id=? WHERE email=?";
            rc = seaf_db_statement_query (manager->priv->db, sql, 2,
                                           "string", reference_id, "string", primary_id);
            if (rc < 0){
                ccnet_warning ("Failed to set reference id for '%s'\n", primary_id);
            }
            return rc;
        }
    }
#endif

    sql = "SELECT email FROM EmailUser WHERE email = ?";
    exists = seaf_db_statement_exists (manager->priv->db, sql, &err,
                                        1, "string", primary_id);
    if (err)
        return -1;
    /* Make sure reference_id is unique */
    if (exists) {
        sql = "SELECT 1 FROM EmailUser e, LDAPUsers l "
              "WHERE (e.reference_id=? AND e.email!=?) OR "
              "(l.reference_id=? AND l.email!=?) OR "
              "(e.email=? AND e.email!=?) OR (l.email=? AND l.email!=?)";
        exists = seaf_db_statement_exists (manager->priv->db, sql, &err,
                                            8, "string", reference_id,
                                            "string", primary_id,
                                            "string", reference_id,
                                            "string", primary_id,
                                            "string", reference_id,
                                            "string", primary_id,
                                            "string", reference_id,
                                            "string", primary_id);
        if (err)
            return -1;
        if (exists) {
            ccnet_warning ("Failed to set reference id, email '%s' exists\n", reference_id);
            return -1;
        }

        sql = "UPDATE EmailUser SET reference_id=? WHERE email=?";
            rc = seaf_db_statement_query (manager->priv->db, sql, 2,
                                           "string", reference_id, "string", primary_id);
        if (rc < 0){
            ccnet_warning ("Failed to set reference id for %s\n", primary_id);
            return -1;
        }
        return rc;
    } else {
        ccnet_warning ("Failed to set reference id, Primary id '%s' not exists\n", primary_id);
        return -1;
    }
}

char *
ccnet_user_manager_get_primary_id (CcnetUserManager *manager, const char *email)
{
    char *sql;
    char *primary_id = NULL;

#ifdef HAVE_LDAP
    if (manager->use_ldap) {
        sql = "SELECT email FROM LDAPUsers WHERE reference_id=?";
        primary_id = seaf_db_statement_get_string (manager->priv->db, sql, 1, "string", email);
        if (primary_id)
            return primary_id;
    }
#endif

    sql = "SELECT email FROM EmailUser WHERE reference_id=?";
    primary_id = seaf_db_statement_get_string (manager->priv->db, sql, 1, "string", email);
    if (primary_id)
        return primary_id;
    else
        return NULL;
}

char *
ccnet_user_manager_get_login_id (CcnetUserManager *manager, const char *primary_id)
{
#ifdef HAVE_LDAP
    if (manager->use_ldap) {
        char *sql = "SELECT reference_id FROM LDAPUsers WHERE email=?";
        char *ldap_login_id = seaf_db_statement_get_string (manager->priv->db, sql, 1, "string", primary_id);

        if (ldap_login_id)
            return ldap_login_id;
    }
#endif
    return g_strdup (primary_id);
}

GList *
ccnet_user_manager_get_emailusers_in_list (CcnetUserManager *manager,
                                           const char *source,
                                           const char *user_list,
                                           GError **error)
{
    int i;
    const char *username;
    json_t *j_array = NULL, *j_obj;
    json_error_t j_error;
    GList *ret = NULL;
    const char *args[20];

    j_array = json_loadb (user_list, strlen(user_list), 0, &j_error);
    if (!j_array) {
        g_set_error (error, CCNET_DOMAIN, 0, "Bad args.");
        return NULL;
    }
    /* Query 20 users at most. */
    size_t user_num = json_array_size (j_array);
    if (user_num > 20) {
        g_set_error (error, CCNET_DOMAIN, 0, "Number of users exceeds 20.");
        json_decref (j_array);
        return NULL;
    }
    GString *sql = g_string_new ("");
    for (i = 0; i < 20; i++) {
        if (i < user_num) {
            j_obj = json_array_get (j_array, i);
            username = json_string_value(j_obj);
            args[i] = username;
        } else {
            args[i] = "";
        }
    }

#ifdef HAVE_LDAP
    if (manager->use_ldap) {
        if (strcmp (source, "LDAP") == 0) {
            g_string_printf (sql, "SELECT l.id, l.email, is_staff, is_active, role "
                                  "FROM LDAPUsers l LEFT JOIN UserRole r "
                                  "ON l.email = r.email "
                                  "WHERE l.email IN (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
            if (seaf_db_statement_foreach_row (manager->priv->db, sql->str, get_ldap_emailusers_cb, &ret, 20,
                                        "string", args[0], "string", args[1], "string", args[2],
                                        "string", args[3], "string", args[4], "string", args[5],
                                        "string", args[6], "string", args[7], "string", args[8],
                                        "string", args[9], "string", args[10], "string", args[11],
                                        "string", args[12], "string", args[13], "string", args[14],
                                        "string", args[15], "string", args[16], "string", args[17],
                                        "string", args[18], "string", args[19]) < 0)
                ccnet_warning("Failed to get users in list %s.\n", user_list);

            goto out;
        }
    }
#endif
    if (strcmp (source, "DB") != 0)
        goto out;

    g_string_printf (sql, "SELECT e.id, e.email, is_staff, is_active, ctime, "
                          "role, passwd FROM EmailUser e "
                          "LEFT JOIN UserRole r ON e.email = r.email "
                          "WHERE e.email IN (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");

    if (seaf_db_statement_foreach_row (manager->priv->db, sql->str, get_emailusers_cb, &ret, 20,
                                        "string", args[0], "string", args[1], "string", args[2],
                                        "string", args[3], "string", args[4], "string", args[5],
                                        "string", args[6], "string", args[7], "string", args[8],
                                        "string", args[9], "string", args[10], "string", args[11],
                                        "string", args[12], "string", args[13], "string", args[14],
                                        "string", args[15], "string", args[16], "string", args[17],
                                        "string", args[18], "string", args[19]) < 0)
        ccnet_warning("Failed to get users in list %s.\n", user_list);

out:
    json_decref (j_array);
    g_string_free (sql, TRUE);

    return ret;
}

int
ccnet_user_manager_update_emailuser_id (CcnetUserManager *manager,
                                        const char *old_email,
                                        const char *new_email,
                                        GError **error)
{
    int ret = -1;
    int rc;
    GString *sql = g_string_new ("");

    //1.update RepoOwner
    g_string_printf (sql, "UPDATE RepoOwner SET owner_id=? WHERE owner_id=?");
    rc = seaf_db_statement_query (seaf->db, sql->str, 2,
                                  "string", new_email,
                                  "string", old_email);
    if (rc < 0){
        ccnet_warning ("Failed to update repo owner\n");
        goto out;
    }

    //2.update SharedRepo
    g_string_printf (sql, "UPDATE SharedRepo SET from_email=? WHERE from_email=?");
    rc = seaf_db_statement_query (seaf->db, sql->str, 2,
                                  "string", new_email,
                                  "string", old_email);
    if (rc < 0){
        ccnet_warning ("Failed to update from_email\n");
        goto out;
    }

    g_string_printf (sql, "UPDATE SharedRepo SET to_email=? WHERE to_email=?");
    rc = seaf_db_statement_query (seaf->db, sql->str, 2,
                                  "string", new_email,
                                  "string", old_email);
    if (rc < 0){
        ccnet_warning ("Failed to update to_email\n");
        goto out;
    }

    //3.update GroupUser
    rc = ccnet_group_manager_update_group_user (seaf->group_mgr, old_email, new_email);
    if (rc < 0){
        ccnet_warning ("Failed to update group member\n");
        goto out;
    }

    //4.update RepoUserToken
    g_string_printf (sql, "UPDATE RepoUserToken SET email=? WHERE email=?");
    rc = seaf_db_statement_query (seaf->db, sql->str, 2,
                                  "string", new_email,
                                  "string", old_email);
    if (rc < 0){
        ccnet_warning ("Failed to update repo user token\n");
        goto out;
    }

    //5.uptede FolderUserPerm
    g_string_printf (sql, "UPDATE FolderUserPerm SET user=? WHERE user=?");
    rc = seaf_db_statement_query (seaf->db, sql->str, 2,
                                  "string", new_email,
                                  "string", old_email);
    if (rc < 0){
        ccnet_warning ("Failed to update user folder permission\n");
        goto out;
    }

    //6.update EmailUser
    g_string_printf (sql, "UPDATE EmailUser SET email=? WHERE email=?");
    rc = seaf_db_statement_query (manager->priv->db, sql->str, 2,
                                  "string", new_email,
                                  "string", old_email);
    if (rc < 0){
        ccnet_warning ("Failed to update email user\n");
        goto out;
    }

    g_string_printf (sql, "UPDATE LDAPUsers SET email=? WHERE email=?");
    rc = seaf_db_statement_query (manager->priv->db, sql->str, 2,
                                  "string", new_email,
                                  "string", old_email);
    if (rc < 0){
        ccnet_warning ("Failed to update LDAP user\n");
        goto out;
    }
    //7.update UserQuota
    g_string_printf (sql, "UPDATE UserQuota SET user=? WHERE user=?");
    rc = seaf_db_statement_query (seaf->db, sql->str, 2,
                                  "string", new_email,
                                  "string", old_email);
    if (rc < 0){
        ccnet_warning ("Failed to update user quota\n");
        goto out;
    }

    ret = 0;
out:
    g_string_free (sql, TRUE);
    return ret;
}
