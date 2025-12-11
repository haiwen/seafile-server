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

#define DEBUG_FLAG  CCNET_DEBUG_PEER
#include "log.h"

#define DEFAULT_SAVING_INTERVAL_MSEC 30000

#define DEFAULT_MAX_CONNECTIONS 100

G_DEFINE_TYPE (CcnetUserManager, ccnet_user_manager, G_TYPE_OBJECT);


#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), CCNET_TYPE_USER_MANAGER, CcnetUserManagerPriv))


static int open_db (CcnetUserManager *manager);

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

gint64
ccnet_user_manager_count_emailusers (CcnetUserManager *manager, const char *source)
{
    CcnetDB* db = manager->priv->db;
    char sql[512];
    gint64 ret;

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

    return g_list_reverse (ret);
}

char *
ccnet_user_manager_get_login_id (CcnetUserManager *manager, const char *primary_id)
{
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
