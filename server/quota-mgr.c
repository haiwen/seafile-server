/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"
#define DEBUG_FLAG SEAFILE_DEBUG_OTHER
#include "log.h"
#include "utils.h"

#include "seafile-session.h"
#include "seaf-db.h"
#include "quota-mgr.h"
#include "seaf-utils.h"

#define KB 1000L
#define MB 1000000L
#define GB 1000000000L
#define TB 1000000000000L

static gint64
get_default_quota (SeafCfgManager *mgr)
{
    char *quota_str;
    char *end;
    gint64 quota_int;
    gint64 multiplier = GB;
    gint64 quota;

    quota_str = seaf_cfg_manager_get_config_string (mgr, "quota", "default");
    if (!quota_str)
        return INFINITE_QUOTA;

    quota_int = strtoll (quota_str, &end, 10);
    if (quota_int == LLONG_MIN || quota_int == LLONG_MAX) {
        seaf_warning ("Default quota value out of range. Use unlimited.\n");
        quota = INFINITE_QUOTA;
        goto out;
    }

    if (*end != '\0') {
        if (strcasecmp(end, "kb") == 0 || strcasecmp(end, "k") == 0)
            multiplier = KB;
        else if (strcasecmp(end, "mb") == 0 || strcasecmp(end, "m") == 0)
            multiplier = MB;
        else if (strcasecmp(end, "gb") == 0 || strcasecmp(end, "g") == 0)
            multiplier = GB;
        else if (strcasecmp(end, "tb") == 0 || strcasecmp(end, "t") == 0)
            multiplier = TB;
        else {
            seaf_warning ("Invalid default quota format %s. Use unlimited.\n", quota_str);
            quota = INFINITE_QUOTA;
            goto out;
        }
    }

    quota = quota_int * multiplier;

out:
    g_free (quota_str);
    return quota;
}

SeafQuotaManager *
seaf_quota_manager_new (struct _SeafileSession *session)
{
    SeafQuotaManager *mgr = g_new0 (SeafQuotaManager, 1);
    if (!mgr)
        return NULL;
    mgr->session = session;

    mgr->calc_share_usage = g_key_file_get_boolean (session->config,
                                                    "quota", "calc_share_usage",
                                                    NULL);

    return mgr;
}

int
seaf_quota_manager_init (SeafQuotaManager *mgr)
{

    if (!mgr->session->create_tables && seaf_db_type (mgr->session->db) != SEAF_DB_TYPE_PGSQL)
        return 0;

    SeafDB *db = mgr->session->db;
    const char *sql;

    switch (seaf_db_type(db)) {
    case SEAF_DB_TYPE_PGSQL:
        sql = "CREATE TABLE IF NOT EXISTS UserQuota (\"user\" VARCHAR(255) PRIMARY KEY,"
            "quota BIGINT)";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE TABLE IF NOT EXISTS UserShareQuota (\"user\" VARCHAR(255) PRIMARY KEY,"
            "quota BIGINT)";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE TABLE IF NOT EXISTS OrgQuota (org_id INTEGER PRIMARY KEY,"
            "quota BIGINT)";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE TABLE IF NOT EXISTS OrgUserQuota (org_id INTEGER,"
            "\"user\" VARCHAR(255), quota BIGINT, PRIMARY KEY (org_id, \"user\"))";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        break;
    case SEAF_DB_TYPE_SQLITE:
        sql = "CREATE TABLE IF NOT EXISTS UserQuota (user VARCHAR(255) PRIMARY KEY,"
            "quota BIGINT)";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE TABLE IF NOT EXISTS UserShareQuota (user VARCHAR(255) PRIMARY KEY,"
            "quota BIGINT)";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE TABLE IF NOT EXISTS OrgQuota (org_id INTEGER PRIMARY KEY,"
            "quota BIGINT)";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE TABLE IF NOT EXISTS OrgUserQuota (org_id INTEGER,"
            "user VARCHAR(255), quota BIGINT, PRIMARY KEY (org_id, user))";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        break;
    case SEAF_DB_TYPE_MYSQL:
        sql = "CREATE TABLE IF NOT EXISTS UserQuota (id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT, "
            "user VARCHAR(255),"
            "quota BIGINT, UNIQUE INDEX(user)) ENGINE=INNODB";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE TABLE IF NOT EXISTS UserShareQuota (id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT, "
            "user VARCHAR(255),"
            "quota BIGINT, UNIQUE INDEX(user)) ENGINE=INNODB";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE TABLE IF NOT EXISTS OrgQuota (id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT, "
            "org_id INTEGER,"
            "quota BIGINT, UNIQUE INDEX(org_id)) ENGINE=INNODB";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE TABLE IF NOT EXISTS OrgUserQuota (id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT, "
            "org_id INTEGER,"
            "user VARCHAR(255), quota BIGINT, UNIQUE INDEX(org_id, user))"
            "ENGINE=INNODB";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        break;
    }

    return 0;
}

int
seaf_quota_manager_set_user_quota (SeafQuotaManager *mgr,
                                   const char *user,
                                   gint64 quota)
{
    SeafDB *db = mgr->session->db;
    if (seaf_db_type(db) == SEAF_DB_TYPE_PGSQL) {
        gboolean exists, err;
        int rc;

        exists = seaf_db_statement_exists (db,
                                           "SELECT 1 FROM UserQuota WHERE \"user\"=?",
                                           &err, 1, "string", user);
        if (err)
            return -1;

        if (exists)
            rc = seaf_db_statement_query (db,
                                          "UPDATE UserQuota SET quota=? "
                                          "WHERE \"user\"=?",
                                          2, "int64", quota, "string", user);
        else
            rc = seaf_db_statement_query (db,
                                          "INSERT INTO UserQuota (\"user\", quota) VALUES "
                                          "(?, ?)",
                                          2, "string", user, "int64", quota);
        return rc;
    } else {
        int rc;
        rc = seaf_db_statement_query (db,
                                      "REPLACE INTO UserQuota (user, quota) VALUES (?, ?)",
                                      2, "string", user, "int64", quota);
        return rc;
    }
}

gint64
seaf_quota_manager_get_user_quota (SeafQuotaManager *mgr,
                                   const char *user)
{
    char *sql;
    gint64 quota;

    if (seaf_db_type(mgr->session->db) != SEAF_DB_TYPE_PGSQL)
        sql = "SELECT quota FROM UserQuota WHERE user=?";
    else
        sql = "SELECT quota FROM UserQuota WHERE \"user\"=?";

    quota = seaf_db_statement_get_int64 (mgr->session->db, sql,
                                         1, "string", user);
    if (quota <= 0)
        quota = get_default_quota (seaf->cfg_mgr);

    return quota;
}

int
seaf_quota_manager_set_org_quota (SeafQuotaManager *mgr,
                                  int org_id,
                                  gint64 quota)
{
    SeafDB *db = mgr->session->db;

    if (seaf_db_type(db) == SEAF_DB_TYPE_PGSQL) {
        gboolean exists, err;
        int rc;

        exists = seaf_db_statement_exists (db,
                                           "SELECT 1 FROM OrgQuota WHERE org_id=?",
                                           &err, 1, "int", org_id);
        if (err)
            return -1;

        if (exists)
            rc = seaf_db_statement_query (db,
                                          "UPDATE OrgQuota SET quota=? WHERE org_id=?",
                                          2, "int64", quota, "int", org_id);
        else
            rc = seaf_db_statement_query (db,
                                          "INSERT INTO OrgQuota (org_id, quota) VALUES (?, ?)",
                                          2, "int", org_id, "int64", quota);
        return rc;
    } else {
        int rc = seaf_db_statement_query (db,
                                          "REPLACE INTO OrgQuota (org_id, quota) VALUES (?, ?)",
                                          2, "int", org_id, "int64", quota);
        return rc;
    }
}

gint64
seaf_quota_manager_get_org_quota (SeafQuotaManager *mgr,
                                  int org_id)
{
    char *sql;
    gint64 quota;

    sql = "SELECT quota FROM OrgQuota WHERE org_id=?";
    quota = seaf_db_statement_get_int64 (mgr->session->db, sql, 1, "int", org_id);
    if (quota <= 0)
        quota = get_default_quota (seaf->cfg_mgr);

    return quota;
}

int
seaf_quota_manager_set_org_user_quota (SeafQuotaManager *mgr,
                                       int org_id,
                                       const char *user,
                                       gint64 quota)
{
    SeafDB *db = mgr->session->db;
    int rc;

    if (seaf_db_type(db) == SEAF_DB_TYPE_PGSQL) {
        gboolean exists, err;

        exists = seaf_db_statement_exists (db,
                                           "SELECT 1 FROM OrgUserQuota "
                                           "WHERE org_id=? AND \"user\"=?",
                                           &err, 2, "int", org_id, "string", user);
        if (err)
            return -1;

        if (exists)
            rc = seaf_db_statement_query (db,
                                          "UPDATE OrgUserQuota SET quota=?"
                                          " WHERE org_id=? AND \"user\"=?",
                                          3, "int64", quota, "int", org_id,
                                          "string", user);
        else
            rc = seaf_db_statement_query (db,
                                          "INSERT INTO OrgUserQuota (org_id, \"user\", quota) VALUES "
                                          "(?, ?, ?)",
                                          3, "int", org_id, "string", user,
                                          "int64", quota);
        return rc;
    } else {
        rc = seaf_db_statement_query (db,
                                      "REPLACE INTO OrgUserQuota (org_id, user, quota) VALUES (?, ?, ?)",
                                      3, "int", org_id, "string", user, "int64", quota);
        return rc;
    }
}

gint64
seaf_quota_manager_get_org_user_quota (SeafQuotaManager *mgr,
                                       int org_id,
                                       const char *user)
{
    char *sql;
    gint64 quota;

    if (seaf_db_type(mgr->session->db) != SEAF_DB_TYPE_PGSQL)
        sql = "SELECT quota FROM OrgUserQuota WHERE org_id=? AND user=?";
    else
        sql = "SELECT quota FROM OrgUserQuota WHERE org_id=? AND \"user\"=?";

    quota = seaf_db_statement_get_int64 (mgr->session->db, sql,
                                         2, "int", org_id, "string", user);
    /* return org quota if per user quota is not set. */
    if (quota <= 0)
        quota = seaf_quota_manager_get_org_quota (mgr, org_id);

    return quota;
}

static void
count_group_members (GHashTable *user_hash, GList *members)
{
    GList *p;
    CcnetGroupUser *user;
    const char *user_name;
    int dummy;

    for (p = members; p; p = p->next) {
        user = p->data;
        user_name = ccnet_group_user_get_user_name (user);
        g_hash_table_insert (user_hash, g_strdup(user_name), &dummy);
        /* seaf_debug ("Shared to %s.\n", user_name); */
        g_object_unref (user);
    }

    g_list_free (members);
}

static gint
get_num_shared_to (const char *user, const char *repo_id)
{
    GHashTable *user_hash;
    int dummy;
    GList *personal = NULL, *groups = NULL, *members = NULL, *p;
    gint n_shared_to = -1;

    /* seaf_debug ("Computing share usage for repo %s.\n", repo_id); */

    /* If a repo is shared to both a user and a group, and that user is also
     * a member of the group, we don't want to count that user twice.
     * This also applies to two groups with overlapped members.
     * So we have to use a hash table to filter out duplicated users.
     */
    user_hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

    /* First count personal share */
    personal = seaf_share_manager_list_shared_to (seaf->share_mgr, user, repo_id);
    for (p = personal; p; p = p->next) {
        char *email = p->data;
        g_hash_table_insert (user_hash, g_strdup(email), &dummy);
        /* seaf_debug ("Shared to %s.\n", email); */
    }

    /* Then groups... */
    groups = seaf_repo_manager_get_groups_by_repo (seaf->repo_mgr,
                                                   repo_id, NULL);
    for (p = groups; p; p = p->next) {
        members = ccnet_group_manager_get_group_members (seaf->group_mgr, (int)(long)p->data, NULL);
        if (!members) {
            seaf_warning ("Cannot get member list for groupd %d.\n", (int)(long)p->data);
            goto out;
        }

        count_group_members (user_hash, members);
    }

    /* Remove myself if i'm in a group. */
    g_hash_table_remove (user_hash, user);

    n_shared_to = g_hash_table_size(user_hash);
    /* seaf_debug ("n_shared_to = %u.\n", n_shared_to); */

out:
    g_hash_table_destroy (user_hash);
    string_list_free (personal);
    g_list_free (groups);

    return n_shared_to;
}

int
seaf_quota_manager_check_quota_with_delta (SeafQuotaManager *mgr,
                                           const char *repo_id,
                                           gint64 delta)
{
    SeafVirtRepo *vinfo;
    const char *r_repo_id = repo_id;
    char *user = NULL;
    gint64 quota, usage;
    int ret = 0;

    /* If it's a virtual repo, check quota to origin repo. */
    vinfo = seaf_repo_manager_get_virtual_repo_info (seaf->repo_mgr, repo_id);
    if (vinfo)
        r_repo_id = vinfo->origin_repo_id;

    user = seaf_repo_manager_get_repo_owner (seaf->repo_mgr, r_repo_id);
    if (user != NULL) {
        if (g_strrstr (user, "dtable@seafile") != NULL)
            goto out;
        quota = seaf_quota_manager_get_user_quota (mgr, user);
    } else {
        seaf_warning ("Repo %s has no owner.\n", r_repo_id);
        ret = -1;
        goto out;
    }

    if (quota == INFINITE_QUOTA)
        goto out;

    usage = seaf_quota_manager_get_user_usage (mgr, user);
    if (usage < 0) {
        ret = -1;
        goto out;
    }

    if (delta != 0) {
        usage += delta;
    }
    if (usage >= quota) {
        ret = 1;
    }

out:
    seaf_virtual_repo_info_free (vinfo);
    g_free (user);
    return ret;
}

int
seaf_quota_manager_check_quota (SeafQuotaManager *mgr,
                                const char *repo_id)
{
    int ret = seaf_quota_manager_check_quota_with_delta (mgr, repo_id, 0);

    if (ret == 1) {
        return -1;
    }
    return ret;
}

gint64
seaf_quota_manager_get_user_usage (SeafQuotaManager *mgr, const char *user)
{
    char *sql;

    sql = "SELECT SUM(size) FROM "
        "RepoOwner o LEFT JOIN VirtualRepo v ON o.repo_id=v.repo_id, "
        "RepoSize WHERE "
        "owner_id=? AND o.repo_id=RepoSize.repo_id "
        "AND v.repo_id IS NULL";

    return seaf_db_statement_get_int64 (mgr->session->db, sql,
                                        1, "string", user);

    /* Add size of repos in trash. */
    /* sql = "SELECT size FROM RepoTrash WHERE owner_id = ?"; */
    /* if (seaf_db_statement_foreach_row (mgr->session->db, sql, */
    /*                                    get_total_size, &total, */
    /*                                    1, "string", user) < 0) */
    /*     return -1; */
}

static gint64
repo_share_usage (const char *user, const char *repo_id)
{
    gint n_shared_to = get_num_shared_to (user, repo_id);
    if (n_shared_to < 0) {
        return -1;
    } else if (n_shared_to == 0) {
        return 0;
    }

    gint64 size = seaf_repo_manager_get_repo_size (seaf->repo_mgr, repo_id);
    if (size < 0) {
        seaf_warning ("Cannot get size of repo %s.\n", repo_id);
        return -1;
    }

    /* share_usage = repo_size * n_shared_to */
    gint64 usage = size * n_shared_to;

    return usage;
}

gint64
seaf_quota_manager_get_user_share_usage (SeafQuotaManager *mgr,
                                         const char *user)
{
    GList *repos, *p;
    char *repo_id;
    gint64 total = 0, per_repo;

    repos = seaf_repo_manager_get_repo_ids_by_owner (seaf->repo_mgr, user);

    for (p = repos; p != NULL; p = p->next) {
        repo_id = p->data;
        per_repo = repo_share_usage (user, repo_id);
        if (per_repo < 0) {
            seaf_warning ("Failed to get repo %s share usage.\n", repo_id);
            string_list_free (repos);
            return -1;
        }

        total += per_repo;
    }

    string_list_free (repos);
    return total;
}

gint64
seaf_quota_manager_get_org_usage (SeafQuotaManager *mgr, int org_id)
{
    char *sql;

    sql = "SELECT SUM(size) FROM OrgRepo, RepoSize WHERE "
        "org_id=? AND OrgRepo.repo_id=RepoSize.repo_id";

    return seaf_db_statement_get_int64 (mgr->session->db, sql,
                                        1, "int", org_id);
}

gint64
seaf_quota_manager_get_org_user_usage (SeafQuotaManager *mgr,
                                       int org_id,
                                       const char *user)
{
    char *sql;

    sql = "SELECT SUM(size) FROM OrgRepo, RepoSize WHERE "
        "org_id=? AND user = ? AND OrgRepo.repo_id=RepoSize.repo_id";

    return seaf_db_statement_get_int64 (mgr->session->db, sql,
                                        2, "int", org_id, "string", user);
}

static gboolean
collect_user_and_usage (SeafDBRow *row, void *data)
{
    GList **p = data;
    const char *user;
    gint64 usage;

    user = seaf_db_row_get_column_text (row, 0);
    usage = seaf_db_row_get_column_int64 (row, 1);

    if (!user)
        return TRUE;

    SeafileUserQuotaUsage *user_usage= g_object_new (SEAFILE_TYPE_USER_QUOTA_USAGE,
                                                     "user", user,
                                                     "usage", usage,
                                                     NULL);
    if (!user_usage)
        return FALSE;

    *p = g_list_prepend (*p, user_usage);

    return TRUE;
}

GList *
seaf_repo_quota_manager_list_user_quota_usage (SeafQuotaManager *mgr)
{
    GList *ret = NULL;
    char *sql = NULL;

    sql = "SELECT owner_id,SUM(size) FROM "
          "RepoOwner o LEFT JOIN VirtualRepo v ON o.repo_id=v.repo_id, "
          "RepoSize WHERE "
          "o.repo_id=RepoSize.repo_id "
          "AND v.repo_id IS NULL "
          "GROUP BY owner_id";

    if (seaf_db_statement_foreach_row (mgr->session->db, sql,
                                       collect_user_and_usage,
                                       &ret, 0) < 0) {
        g_list_free_full (ret, g_object_unref);
        return NULL;
    }

    return g_list_reverse (ret);
}
