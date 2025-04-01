/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "seafile-session.h"
#include "seaf-db.h"
#include "group-mgr.h"
#include "org-mgr.h"
#include "seaf-utils.h"

#include "utils.h"
#include "log.h"

#define DEFAULT_MAX_CONNECTIONS 100

struct _CcnetGroupManagerPriv {
    CcnetDB	*db;
    const char *table_name;
};

static int open_db (CcnetGroupManager *manager);
static int check_db_table (CcnetGroupManager *manager, CcnetDB *db);

CcnetGroupManager* ccnet_group_manager_new (SeafileSession *session)
{
    CcnetGroupManager *manager = g_new0 (CcnetGroupManager, 1);

    manager->session = session;
    manager->priv = g_new0 (CcnetGroupManagerPriv, 1);

    return manager;
}

int
ccnet_group_manager_init (CcnetGroupManager *manager)
{
    return 0;
}

int
ccnet_group_manager_prepare (CcnetGroupManager *manager)
{
    const char *table_name = g_getenv("SEAFILE_MYSQL_DB_GROUP_TABLE_NAME");
    if (!table_name || g_strcmp0 (table_name, "") == 0)
        manager->priv->table_name = g_strdup ("Group");
    else
        manager->priv->table_name = g_strdup (table_name);

    return open_db(manager);
}

void ccnet_group_manager_start (CcnetGroupManager *manager)
{
}

static CcnetDB *
open_sqlite_db (CcnetGroupManager *manager)
{
    CcnetDB *db = NULL;
    char *db_dir;
    char *db_path;

    db_dir = g_build_filename (manager->session->ccnet_dir, "GroupMgr", NULL);
    if (checkdir_with_mkdir(db_dir) < 0) {
        ccnet_error ("Cannot open db dir %s: %s\n", db_dir,
                     strerror(errno));
        g_free (db_dir);
        return NULL;
    }
    g_free (db_dir);

    db_path = g_build_filename (manager->session->ccnet_dir, "GroupMgr",
                                "groupmgr.db", NULL);
    db = seaf_db_new_sqlite (db_path, DEFAULT_MAX_CONNECTIONS);

    g_free (db_path);

    return db;
}

static int
open_db (CcnetGroupManager *manager)
{
    CcnetDB *db = NULL;

    switch (seaf_db_type(manager->session->ccnet_db)) {
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
        && check_db_table (manager, db) < 0) {
        ccnet_warning ("Failed to create group db tables.\n");
        return -1;
    }

    return 0;
}

/* -------- Group Database Management ---------------- */

static int check_db_table (CcnetGroupManager *manager, CcnetDB *db)
{
    char *sql;
    GString *group_sql = g_string_new ("");
    const char *table_name = manager->priv->table_name;

    int db_type = seaf_db_type (db);
    if (db_type == SEAF_DB_TYPE_MYSQL) {
        g_string_printf (group_sql,
            "CREATE TABLE IF NOT EXISTS `%s` (`group_id` BIGINT "
            " PRIMARY KEY AUTO_INCREMENT, `group_name` VARCHAR(255),"
            " `creator_name` VARCHAR(255), `timestamp` BIGINT,"
            " `type` VARCHAR(32), `parent_group_id` INTEGER)"
            "ENGINE=INNODB", table_name);
        if (seaf_db_query (db, group_sql->str) < 0) {
            g_string_free (group_sql, TRUE);
            return -1;
        }

        sql = "CREATE TABLE IF NOT EXISTS `GroupUser` ( "
            "`id` BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT, `group_id` BIGINT,"
            " `user_name` VARCHAR(255), `is_staff` tinyint, UNIQUE INDEX"
            " (`group_id`, `user_name`), INDEX (`user_name`))"
            "ENGINE=INNODB";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE TABLE IF NOT EXISTS GroupDNPair ( "
            "id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT, group_id INTEGER,"
            " dn VARCHAR(255))ENGINE=INNODB";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE TABLE IF NOT EXISTS GroupStructure ( "
              "id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT, group_id INTEGER, "
              "path VARCHAR(1024), UNIQUE INDEX(group_id))ENGINE=INNODB";
        if (seaf_db_query (db, sql) < 0)
            return -1;
    } else if (db_type == SEAF_DB_TYPE_SQLITE) {
        g_string_printf (group_sql,
            "CREATE TABLE IF NOT EXISTS `%s` (`group_id` INTEGER"
            " PRIMARY KEY AUTOINCREMENT, `group_name` VARCHAR(255),"
            " `creator_name` VARCHAR(255), `timestamp` BIGINT,"
            " `type` VARCHAR(32), `parent_group_id` INTEGER)", table_name);
        if (seaf_db_query (db, group_sql->str) < 0) {
            g_string_free (group_sql, TRUE);
            return -1;
        }

        sql = "CREATE TABLE IF NOT EXISTS `GroupUser` (`group_id` INTEGER, "
            "`user_name` VARCHAR(255), `is_staff` tinyint)";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE UNIQUE INDEX IF NOT EXISTS groupid_username_indx on "
            "`GroupUser` (`group_id`, `user_name`)";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE INDEX IF NOT EXISTS username_indx on "
            "`GroupUser` (`user_name`)";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE TABLE IF NOT EXISTS GroupDNPair (group_id INTEGER,"
            " dn VARCHAR(255))";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE TABLE IF NOT EXISTS GroupStructure (group_id INTEGER PRIMARY KEY, "
              "path VARCHAR(1024))";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE INDEX IF NOT EXISTS path_indx on "
            "`GroupStructure` (`path`)";
        if (seaf_db_query (db, sql) < 0)
            return -1;

    } else if (db_type == SEAF_DB_TYPE_PGSQL) {
        g_string_printf (group_sql,
            "CREATE TABLE IF NOT EXISTS \"%s\" (group_id SERIAL"
            " PRIMARY KEY, group_name VARCHAR(255),"
            " creator_name VARCHAR(255), timestamp BIGINT,"
            " type VARCHAR(32), parent_group_id INTEGER)", table_name);
        if (seaf_db_query (db, group_sql->str) < 0) {
            g_string_free (group_sql, TRUE);
            return -1;
        }

        sql = "CREATE TABLE IF NOT EXISTS GroupUser (group_id INTEGER,"
            " user_name VARCHAR(255), is_staff smallint, UNIQUE "
            " (group_id, user_name))";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        //if (!pgsql_index_exists (db, "groupuser_username_idx")) {
        //    sql = "CREATE INDEX groupuser_username_idx ON GroupUser (user_name)";
        //    if (seaf_db_query (db, sql) < 0)
        //        return -1;
        //}

        sql = "CREATE TABLE IF NOT EXISTS GroupDNPair (group_id INTEGER,"
            " dn VARCHAR(255))";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE TABLE IF NOT EXISTS GroupStructure (group_id INTEGER PRIMARY KEY, "
              "path VARCHAR(1024))";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        //if (!pgsql_index_exists (db, "structure_path_idx")) {
        //    sql = "CREATE INDEX structure_path_idx ON GroupStructure (path)";
        //    if (seaf_db_query (db, sql) < 0)
        //        return -1;
        //}

    }
    g_string_free (group_sql, TRUE);

    return 0;
}

static gboolean
get_group_id_cb (CcnetDBRow *row, void *data)
{
    int *id = data;
    int group_id = seaf_db_row_get_column_int(row, 0);
    *id = group_id;

    return FALSE;
}

static gboolean
get_group_path_cb (CcnetDBRow *row, void *data)
{
    char **path = (char **)data;
    const char *group_path = seaf_db_row_get_column_text (row, 0);
    *path = g_strdup (group_path);

    return FALSE;
}

static int
create_group_common (CcnetGroupManager *mgr,
                     const char *group_name,
                     const char *user_name,
                     int parent_group_id,
                     GError **error)
{
    CcnetDB *db = mgr->priv->db;
    gint64 now = get_current_time();
    GString *sql = g_string_new ("");
    const char *table_name = mgr->priv->table_name;
    int group_id = -1;
    CcnetDBTrans *trans = seaf_db_begin_transaction (db);

    char *user_name_l = g_ascii_strdown (user_name, -1);
    
    if (seaf_db_type(db) == SEAF_DB_TYPE_PGSQL)
        g_string_printf (sql,
            "INSERT INTO \"%s\"(group_name, "
            "creator_name, timestamp, parent_group_id) VALUES(?, ?, ?, ?)", table_name);
    else
        g_string_printf (sql,
            "INSERT INTO `%s`(group_name, "
            "creator_name, timestamp, parent_group_id) VALUES(?, ?, ?, ?)", table_name);

    if (seaf_db_trans_query (trans, sql->str, 4,
                              "string", group_name, "string", user_name_l,
                              "int64", now, "int", parent_group_id) < 0)
        goto error;

    if (seaf_db_type(db) == SEAF_DB_TYPE_PGSQL)
        g_string_printf (sql,
            "SELECT group_id FROM \"%s\" WHERE "
            "group_name = ? AND creator_name = ? "
            "AND timestamp = ?", table_name);
    else
        g_string_printf (sql,
            "SELECT group_id FROM `%s` WHERE "
            "group_name = ? AND creator_name = ? "
            "AND timestamp = ?", table_name);

    seaf_db_trans_foreach_selected_row (trans, sql->str, get_group_id_cb,
                                         &group_id, 3, "string", group_name,
                                         "string", user_name_l, "int64", now);

    if (group_id < 0)
        goto error;

    if (g_strcmp0(user_name, "system admin") != 0) {
        g_string_printf (sql, "INSERT INTO GroupUser (group_id, user_name, is_staff) VALUES (?, ?, ?)");

        if (seaf_db_trans_query (trans, sql->str, 3,
                                  "int", group_id, "string", user_name_l,
                                  "int", 1) < 0)
            goto error;
    }

    if (parent_group_id == -1) {
        g_string_printf (sql, "INSERT INTO GroupStructure (group_id, path) VALUES (?,'%d')", group_id);
        if (seaf_db_trans_query (trans, sql->str, 1, "int", group_id) < 0)
            goto error;
    } else if (parent_group_id > 0) {
        g_string_printf (sql, "SELECT path FROM GroupStructure WHERE group_id=?");
        char *path = NULL;
        seaf_db_trans_foreach_selected_row (trans, sql->str, get_group_path_cb,
                                             &path, 1, "int", parent_group_id);
        if (!path)
            goto error;
        g_string_printf (sql, "INSERT INTO GroupStructure (group_id, path) VALUES (?, '%s, %d')", path, group_id);
        if (seaf_db_trans_query (trans, sql->str, 1, "int", group_id) < 0) {
            g_free (path);
            goto error;
        }
        g_free (path);
    }

    seaf_db_commit (trans);
    seaf_db_trans_close (trans);
    g_string_free (sql, TRUE);
    g_free (user_name_l);
    return group_id;

error:
    seaf_db_rollback (trans);
    seaf_db_trans_close (trans);
    g_set_error (error, CCNET_DOMAIN, 0, "Failed to create group");
    g_string_free (sql, TRUE);
    g_free (user_name_l);
    return -1;
}

int ccnet_group_manager_create_group (CcnetGroupManager *mgr,
                                      const char *group_name,
                                      const char *user_name,
                                      int parent_group_id,
                                      GError **error)
{
    return create_group_common (mgr, group_name, user_name, parent_group_id, error);
}

/* static gboolean */
/* duplicate_org_group_name (CcnetGroupManager *mgr, */
/*                           int org_id, */
/*                           const char *group_name) */
/* { */
/*     GList *org_groups = NULL, *ptr; */
/*     CcnetOrgManager *org_mgr = seaf->org_mgr; */
    
/*     org_groups = ccnet_org_manager_get_org_groups (org_mgr, org_id, -1, -1); */
/*     if (!org_groups) */
/*         return FALSE; */

/*     for (ptr = org_groups; ptr; ptr = ptr->next) { */
/*         int group_id = (int)(long)ptr->data; */
/*         CcnetGroup *group = ccnet_group_manager_get_group (mgr, group_id, */
/*                                                            NULL); */
/*         if (!group) */
/*             continue; */

/*         if (g_strcmp0 (group_name, ccnet_group_get_group_name(group)) == 0) { */
/*             g_list_free (org_groups); */
/*             g_object_unref (group); */
/*             return TRUE; */
/*         } else { */
/*             g_object_unref (group); */
/*         } */
/*     } */

/*     g_list_free (org_groups); */
/*     return FALSE; */
/* } */

int ccnet_group_manager_create_org_group (CcnetGroupManager *mgr,
                                          int org_id,
                                          const char *group_name,
                                          const char *user_name,
                                          int parent_group_id,
                                          GError **error)
{
    CcnetOrgManager *org_mgr = seaf->org_mgr;
    
    /* if (duplicate_org_group_name (mgr, org_id, group_name)) { */
    /*     g_set_error (error, CCNET_DOMAIN, 0, */
    /*                  "The group has already created in this org."); */
    /*     return -1; */
    /* } */

    int group_id = create_group_common (mgr, group_name, user_name, parent_group_id, error);
    if (group_id < 0) {
        g_set_error (error, CCNET_DOMAIN, 0, "Failed to create org group.");
        return -1;
    }

    if (ccnet_org_manager_add_org_group (org_mgr, org_id, group_id,
                                         error) < 0) {
        g_set_error (error, CCNET_DOMAIN, 0, "Failed to create org group.");
        return -1;
    }

    return group_id;
}

static gboolean
check_group_staff (CcnetDB *db, int group_id, const char *user_name, gboolean in_structure)
{
    gboolean exists, err;
    if (!in_structure) {
        exists = seaf_db_statement_exists (db, "SELECT group_id FROM GroupUser WHERE "
                                          "group_id = ? AND user_name = ? AND "
                                          "is_staff = 1", &err,
                                          2, "int", group_id, "string", user_name);
        if (err) {
            ccnet_warning ("DB error when check staff user exist in GroupUser.\n");
            return FALSE;
        }
        return exists;
    }


    GString *sql = g_string_new("");
    g_string_printf (sql, "SELECT path FROM GroupStructure WHERE group_id=?");
    char *path = seaf_db_statement_get_string (db, sql->str, 1, "int", group_id);


    if (!path) {
        exists = seaf_db_statement_exists (db, "SELECT group_id FROM GroupUser WHERE "
                                            "group_id = ? AND user_name = ? AND "
                                            "is_staff = 1", &err,
                                            2, "int", group_id, "string", user_name);
    } else {
        g_string_printf (sql, "SELECT group_id FROM GroupUser WHERE "
                              "group_id IN (%s) AND user_name = ? AND "
                              "is_staff = 1", path);
        exists = seaf_db_statement_exists (db, sql->str, &err,
                                            1, "string", user_name);
    }
    g_string_free (sql, TRUE);
    g_free (path);

    if (err) {
        ccnet_warning ("DB error when check staff user exist in GroupUser.\n");
        return FALSE;
    }

    return exists;
}

int ccnet_group_manager_remove_group (CcnetGroupManager *mgr,
                                      int group_id,
                                      gboolean remove_anyway,
                                      GError **error)
{
    CcnetDB *db = mgr->priv->db;
    GString *sql = g_string_new ("");
    gboolean exists, err;
    const char *table_name = mgr->priv->table_name;

    /* No permission check here, since both group staff and seahub staff
     * can remove group.
     */
     if (remove_anyway != TRUE) {
        if (seaf_db_type(db) == SEAF_DB_TYPE_PGSQL)
            g_string_printf (sql, "SELECT 1 FROM \"%s\" WHERE parent_group_id=?", table_name);
        else
            g_string_printf (sql, "SELECT 1 FROM `%s` WHERE parent_group_id=?", table_name);
        exists = seaf_db_statement_exists (db, sql->str, &err, 1, "int", group_id);
        if (err) {
            ccnet_warning ("DB error when check remove group.\n");
            g_string_free (sql, TRUE);
            return -1;
        }
        if (exists) {
            ccnet_warning ("Failed to remove group [%d] whose child group must be removed first.\n", group_id);
            g_string_free (sql, TRUE);
            return -1;
        }
     }
    
    if (seaf_db_type(db) == SEAF_DB_TYPE_PGSQL)
        g_string_printf (sql, "DELETE FROM \"%s\" WHERE group_id=?", table_name);
    else
        g_string_printf (sql, "DELETE FROM `%s` WHERE group_id=?", table_name);
    seaf_db_statement_query (db, sql->str, 1, "int", group_id);

    g_string_printf (sql, "DELETE FROM GroupUser WHERE group_id=?");
    seaf_db_statement_query (db, sql->str, 1, "int", group_id);

    g_string_printf (sql, "DELETE FROM GroupStructure WHERE group_id=?");
    seaf_db_statement_query (db, sql->str, 1, "int", group_id);

    g_string_free (sql, TRUE);
    
    return 0;
}

static gboolean
check_group_exists (CcnetGroupManager *mgr, CcnetDB *db, int group_id)
{
    GString *sql = g_string_new ("");
    const char *table_name = mgr->priv->table_name;
    gboolean exists, err;

    if (seaf_db_type(db) == SEAF_DB_TYPE_PGSQL) {
        g_string_printf (sql, "SELECT group_id FROM \"%s\" WHERE group_id=?", table_name);
        exists = seaf_db_statement_exists (db, sql->str, &err, 1, "int", group_id);
    } else {
        g_string_printf (sql, "SELECT group_id FROM `%s` WHERE group_id=?", table_name);
        exists = seaf_db_statement_exists (db, sql->str, &err, 1, "int", group_id);
    }
    g_string_free (sql, TRUE);

    if (err) {
        ccnet_warning ("DB error when check group exist.\n");
        return FALSE;
    }
    return exists;
}

int ccnet_group_manager_add_member (CcnetGroupManager *mgr,
                                    int group_id,
                                    const char *user_name,
                                    const char *member_name,
                                    GError **error)
{
    CcnetDB *db = mgr->priv->db;

    /* check whether group exists */
    if (!check_group_exists (mgr, db, group_id)) {
        g_set_error (error, CCNET_DOMAIN, 0, "Group not exists");
        return -1;
    }

    char *member_name_l = g_ascii_strdown (member_name, -1);
    int rc = seaf_db_statement_query (db, "INSERT INTO GroupUser (group_id, user_name, is_staff) VALUES (?, ?, ?)",
                                       3, "int", group_id, "string", member_name_l,
                                       "int", 0);
    g_free (member_name_l);
    if (rc < 0) {
        g_set_error (error, CCNET_DOMAIN, 0, "Failed to add member to group");
        return -1;
    }

    return 0;
}

int ccnet_group_manager_remove_member (CcnetGroupManager *mgr,
                                       int group_id,
                                       const char *user_name,
                                       const char *member_name,
                                       GError **error)
{
    CcnetDB *db = mgr->priv->db;
    char *sql;

    /* check whether group exists */
    if (!check_group_exists (mgr, db, group_id)) {
        g_set_error (error, CCNET_DOMAIN, 0, "Group not exists");
        return -1;
    }

    /* can not remove myself */
    if (g_strcmp0 (user_name, member_name) == 0) {
        g_set_error (error, CCNET_DOMAIN, 0, "Can not remove myself");
        return -1;
    }

    sql = "DELETE FROM GroupUser WHERE group_id=? AND user_name=?";
    seaf_db_statement_query (db, sql, 2, "int", group_id, "string", member_name);

    return 0;
}

int ccnet_group_manager_set_admin (CcnetGroupManager *mgr,
                                   int group_id,
                                   const char *member_name,
                                   GError **error)
{
    CcnetDB *db = mgr->priv->db;

    seaf_db_statement_query (db,
                              "UPDATE GroupUser SET is_staff = 1 "
                              "WHERE group_id = ? and user_name = ?",
                              2, "int", group_id, "string", member_name);

    return 0;
}

int ccnet_group_manager_unset_admin (CcnetGroupManager *mgr,
                                     int group_id,
                                     const char *member_name,
                                     GError **error)
{
    CcnetDB *db = mgr->priv->db;

    seaf_db_statement_query (db,
                              "UPDATE GroupUser SET is_staff = 0 "
                              "WHERE group_id = ? and user_name = ?",
                              2, "int", group_id, "string", member_name);

    return 0;
}

int ccnet_group_manager_set_group_name (CcnetGroupManager *mgr,
                                        int group_id,
                                        const char *group_name,
                                        GError **error)
{
    const char *table_name = mgr->priv->table_name;
    GString *sql = g_string_new ("");
    CcnetDB *db = mgr->priv->db;

    if (seaf_db_type(db) == SEAF_DB_TYPE_PGSQL) {
        g_string_printf (sql, "UPDATE \"%s\" SET group_name = ? "
                              "WHERE group_id = ?", table_name);
        seaf_db_statement_query (db, sql->str, 2, "string", group_name, "int", group_id);
    } else {
        g_string_printf (sql, "UPDATE `%s` SET group_name = ? "
                              "WHERE group_id = ?", table_name);
        seaf_db_statement_query (db, sql->str, 2, "string", group_name, "int", group_id);
    }
    g_string_free (sql, TRUE);

    return 0;
}

int ccnet_group_manager_quit_group (CcnetGroupManager *mgr,
                                    int group_id,
                                    const char *user_name,
                                    GError **error)
{
    CcnetDB *db = mgr->priv->db;
    
    /* check whether group exists */
    if (!check_group_exists (mgr, db, group_id)) {
        g_set_error (error, CCNET_DOMAIN, 0, "Group not exists");
        return -1;
    }

    seaf_db_statement_query (db,
                              "DELETE FROM GroupUser WHERE group_id=? "
                              "AND user_name=?",
                              2, "int", group_id, "string", user_name);

    return 0;
}

static gboolean
get_user_groups_cb (CcnetDBRow *row, void *data)
{
    GList **plist = data;
    CcnetGroup *group;

    int group_id = seaf_db_row_get_column_int (row, 0);
    const char *group_name = seaf_db_row_get_column_text (row, 1);
    const char *creator_name = seaf_db_row_get_column_text (row, 2);
    gint64 ts = seaf_db_row_get_column_int64 (row, 3);
    int parent_group_id = seaf_db_row_get_column_int (row, 4);

    group = g_object_new (CCNET_TYPE_GROUP,
                          "id", group_id,
                          "group_name", group_name,
                          "creator_name", creator_name,
                          "timestamp", ts,
                          "source", "DB",
                          "parent_group_id", parent_group_id,
                          NULL);

    *plist = g_list_append (*plist, group);

    return TRUE;
}

GList *
ccnet_group_manager_get_ancestor_groups (CcnetGroupManager *mgr, int group_id)
{
    CcnetDB *db = mgr->priv->db;
    GList *ret = NULL;
    CcnetGroup *group = NULL;
    GString *sql = g_string_new ("");
    const char *table_name = mgr->priv->table_name;

    g_string_printf (sql, "SELECT path FROM GroupStructure WHERE group_id=?");

    char *path = seaf_db_statement_get_string (db, sql->str, 1, "int", group_id);

    if (path) {
        if (seaf_db_type(db) == SEAF_DB_TYPE_PGSQL)
            g_string_printf (sql, "SELECT g.group_id, group_name, creator_name, timestamp, parent_group_id FROM "
                             "\"%s\" g WHERE g.group_id IN(%s) "
                             "ORDER BY g.group_id",
                             table_name, path);
        else
            g_string_printf (sql, "SELECT g.group_id, group_name, creator_name, timestamp, parent_group_id FROM "
                             "`%s` g WHERE g.group_id IN(%s) "
                             "ORDER BY g.group_id",
                             table_name, path);

        if (seaf_db_statement_foreach_row (db, sql->str, get_user_groups_cb, &ret, 0) < 0) {
            ccnet_warning ("Failed to get ancestor groups of group %d\n", group_id);
            g_string_free (sql, TRUE);
            g_free (path);
            return NULL;
        }
        g_string_free (sql, TRUE);
        g_free (path);
    } else { // group is not in structure, return itself.
        group = ccnet_group_manager_get_group (mgr, group_id, NULL);
        if (group) {
            ret = g_list_prepend (ret, group);
        }
    }

    return ret;
}

static gint
group_comp_func (gconstpointer a, gconstpointer b)
{
    CcnetGroup *g1 = (CcnetGroup *)a;
    CcnetGroup *g2 = (CcnetGroup *)b;
    int id_1 = 0, id_2 = 0;
    g_object_get (g1, "id", &id_1, NULL);
    g_object_get (g2, "id", &id_2, NULL);

    if (id_1 == id_2)
        return 0;
    return id_1 > id_2 ? -1 : 1;
}

gboolean
get_group_paths_cb (CcnetDBRow *row, void *data)
{
    GString *paths = data;
    const char *path = seaf_db_row_get_column_text (row, 0);

    if (g_strcmp0 (paths->str, "") == 0)
        g_string_append_printf (paths, "%s", path);
    else
        g_string_append_printf (paths, ", %s", path);

    return TRUE;
}

GList *
ccnet_group_manager_get_groups_by_user (CcnetGroupManager *mgr,
                                        const char *user_name,
                                        gboolean return_ancestors,
                                        GError **error)
{
    CcnetDB *db = mgr->priv->db;
    GList *groups = NULL, *ret = NULL;
    GList *ptr;
    GString *sql = g_string_new ("");
    const char *table_name = mgr->priv->table_name;
    CcnetGroup *group;
    int parent_group_id = 0, group_id = 0;

    if (seaf_db_type(db) == SEAF_DB_TYPE_PGSQL)
        g_string_printf (sql, 
            "SELECT g.group_id, group_name, creator_name, timestamp, parent_group_id FROM "
            "\"%s\" g, GroupUser u WHERE g.group_id = u.group_id AND user_name=? ORDER BY g.group_id DESC",
            table_name);
    else
        g_string_printf (sql,
            "SELECT g.group_id, group_name, creator_name, timestamp, parent_group_id FROM "
            "`%s` g, GroupUser u WHERE g.group_id = u.group_id AND user_name=? ORDER BY g.group_id DESC",
            table_name);

    if (seaf_db_statement_foreach_row (db,
                                        sql->str,
                                        get_user_groups_cb,
                                        &groups,
                                        1, "string", user_name) < 0) {
        g_string_free (sql, TRUE);
        return NULL;
    }

    if (!return_ancestors) {
        g_string_free (sql, TRUE);
        return groups;
    }

    /* Get ancestor groups in descending order by group_id.*/
    GString *paths = g_string_new ("");
    g_string_erase (sql, 0, -1);
    for (ptr = groups; ptr; ptr = ptr->next) {
        group = ptr->data;
        g_object_get (group, "parent_group_id", &parent_group_id, NULL);
        g_object_get (group, "id", &group_id, NULL);
        if (parent_group_id != 0) {
            if (g_strcmp0(sql->str, "") == 0)
                g_string_append_printf (sql, "SELECT path FROM GroupStructure WHERE group_id IN (%d", group_id);
            else
                g_string_append_printf (sql, ", %d", group_id);
        } else {
            g_object_ref (group);
            ret = g_list_insert_sorted (ret, group, group_comp_func);
        }
    }
    if (g_strcmp0(sql->str, "") != 0) {
        g_string_append_printf (sql, ")");
        if (seaf_db_statement_foreach_row (db,
                                            sql->str,
                                            get_group_paths_cb,
                                            paths, 0) < 0) {
            g_list_free_full (ret, g_object_unref);
            ret = NULL;
            goto out;
        }
        if (g_strcmp0(paths->str, "") == 0) {
            ccnet_warning ("Failed to get groups path for user %s\n", user_name);
            g_list_free_full (ret, g_object_unref);
            ret = NULL;
            goto out;
        }

        g_string_printf (sql, "SELECT g.group_id, group_name, creator_name, timestamp, parent_group_id FROM "
                         "`%s` g WHERE g.group_id IN (%s) ORDER BY g.group_id DESC",
                         table_name, paths->str);
        if (seaf_db_statement_foreach_row (db,
                                        sql->str,
                                        get_user_groups_cb,
                                        &ret, 0) < 0) {
            g_list_free_full (ret, g_object_unref);
            ret = NULL;
            goto out;
        }
    }
    ret = g_list_sort (ret, group_comp_func);

out:
    g_string_free (sql, TRUE);
    g_list_free_full (groups, g_object_unref);
    g_string_free (paths, TRUE);

    return ret;
}

static gboolean
get_ccnetgroup_cb (CcnetDBRow *row, void *data)
{
    CcnetGroup **p_group = data;
    int group_id;
    const char *group_name;
    const char *creator;
    int parent_group_id;
    gint64 ts;
    
    group_id = seaf_db_row_get_column_int (row, 0);
    group_name = (const char *)seaf_db_row_get_column_text (row, 1);
    creator = (const char *)seaf_db_row_get_column_text (row, 2);
    ts = seaf_db_row_get_column_int64 (row, 3);
    parent_group_id = seaf_db_row_get_column_int (row, 4);

    char *creator_l = g_ascii_strdown (creator, -1);
    *p_group = g_object_new (CCNET_TYPE_GROUP,
                             "id", group_id,
                             "group_name", group_name,
                             "creator_name", creator_l,
                             "timestamp", ts,
                             "source", "DB",
                             "parent_group_id", parent_group_id,
                             NULL);
    g_free (creator_l);

    return FALSE;
}

GList *
ccnet_group_manager_get_child_groups (CcnetGroupManager *mgr, int group_id,
                                      GError **error)
{
    CcnetDB *db = mgr->priv->db;
    GString *sql = g_string_new ("");
    GList *ret = NULL;
    const char *table_name = mgr->priv->table_name;

    if (seaf_db_type(db) == SEAF_DB_TYPE_PGSQL)
        g_string_printf (sql,
            "SELECT group_id, group_name, creator_name, timestamp, parent_group_id FROM "
            "\"%s\" WHERE parent_group_id=?", table_name);
    else
        g_string_printf (sql,
            "SELECT group_id, group_name, creator_name, timestamp, parent_group_id FROM "
            "`%s` WHERE parent_group_id=?", table_name);
    if (seaf_db_statement_foreach_row (db, sql->str,
                                        get_user_groups_cb, &ret,
                                        1, "int", group_id) < 0) {
        g_string_free (sql, TRUE);
        return NULL;
    }
    g_string_free (sql, TRUE);

    return ret;
}

GList *
ccnet_group_manager_get_descendants_groups(CcnetGroupManager *mgr, int group_id,
                                           GError **error)
{
    GList *ret = NULL;
    CcnetDB *db = mgr->priv->db;
    const char *table_name = mgr->priv->table_name;

    GString *sql = g_string_new("");
    if (seaf_db_type(db) == SEAF_DB_TYPE_PGSQL)
        g_string_printf (sql, "SELECT g.group_id, group_name, creator_name, timestamp, "
                              "parent_group_id FROM \"%s\" g, GroupStructure s "
                              "WHERE g.group_id=s.group_id "
                              "AND (s.path LIKE '%d, %%' OR s.path LIKE '%%, %d, %%' "
                              "OR g.group_id=?)",
                              table_name, group_id, group_id);

    else
        g_string_printf (sql, "SELECT g.group_id, group_name, creator_name, timestamp, "
                              "parent_group_id FROM `%s` g, GroupStructure s "
                              "WHERE g.group_id=s.group_id "
                              "AND (s.path LIKE '%d, %%' OR s.path LIKE '%%, %d, %%' "
                              "OR g.group_id=?)",
                              table_name, group_id, group_id);

    if (seaf_db_statement_foreach_row (db, sql->str,
                                        get_user_groups_cb, &ret,
                                        1, "int", group_id) < 0) {
        g_string_free (sql, TRUE);
        return NULL;
    }
    g_string_free (sql, TRUE);

    return ret;
}

CcnetGroup *
ccnet_group_manager_get_group (CcnetGroupManager *mgr, int group_id,
                               GError **error)
{
    CcnetDB *db = mgr->priv->db;
    GString *sql = g_string_new ("");
    CcnetGroup *ccnetgroup = NULL;
    const char *table_name = mgr->priv->table_name;

    if (seaf_db_type(db) == SEAF_DB_TYPE_PGSQL)
        g_string_printf (sql,
            "SELECT group_id, group_name, creator_name, timestamp, parent_group_id FROM "
            "\"%s\" WHERE group_id = ?", table_name);
    else
        g_string_printf (sql,
            "SELECT group_id, group_name, creator_name, timestamp, parent_group_id FROM "
            "`%s` WHERE group_id = ?", table_name);
    if (seaf_db_statement_foreach_row (db, sql->str,
                                        get_ccnetgroup_cb, &ccnetgroup,
                                        1, "int", group_id) < 0) {
        g_string_free (sql, TRUE);
        return NULL;
    }
    g_string_free (sql, TRUE);

    return ccnetgroup;
}

static gboolean
get_ccnet_groupuser_cb (CcnetDBRow *row, void *data)
{
    GList **plist = data;
    CcnetGroupUser *group_user;
    
    int group_id = seaf_db_row_get_column_int (row, 0);
    const char *user = (const char *)seaf_db_row_get_column_text (row, 1);
    int is_staff = seaf_db_row_get_column_int (row, 2);

    char *user_l = g_ascii_strdown (user, -1);
    group_user = g_object_new (CCNET_TYPE_GROUP_USER,
                               "group_id", group_id,
                               "user_name", user_l,
                               "is_staff", is_staff,
                               NULL);
    g_free (user_l);
    if (group_user != NULL) {
        *plist = g_list_prepend (*plist, group_user);
    }
    
    return TRUE;
}

GList *
ccnet_group_manager_get_group_members (CcnetGroupManager *mgr,
                                       int group_id,
                                       int start,
                                       int limit,
                                       GError **error)
{
    CcnetDB *db = mgr->priv->db;
    char *sql;
    GList *group_users = NULL;
    int rc;
    
    if (limit == -1) {
        sql = "SELECT group_id, user_name, is_staff FROM GroupUser WHERE group_id = ?";
        rc =seaf_db_statement_foreach_row (db, sql,
                                           get_ccnet_groupuser_cb, &group_users,
                                           1, "int", group_id);
    } else {
        sql = "SELECT group_id, user_name, is_staff FROM GroupUser WHERE group_id = ? LIMIT ? OFFSET ?";
        rc = seaf_db_statement_foreach_row (db, sql,
                                            get_ccnet_groupuser_cb, &group_users,
                                            3, "int", group_id,
                                            "int", limit,
                                            "int", start);
    }

    if (rc < 0) {
        return NULL;
    }

    return g_list_reverse (group_users);
}

GList *
ccnet_group_manager_get_members_with_prefix (CcnetGroupManager *mgr,
                                             int group_id,
                                             const char *prefix,
                                             GError **error)
{
    CcnetDB *db = mgr->priv->db;
    GList *group_users = NULL;
    GList *ptr;
    CcnetGroup *group;
    GString *sql = g_string_new ("");
    int id;

    g_string_printf(sql, "SELECT group_id, user_name, is_staff FROM GroupUser "
                         "WHERE group_id IN (");
    GList *groups = ccnet_group_manager_get_descendants_groups(mgr, group_id, NULL);
    if (!groups)
        g_string_append_printf(sql, "%d", group_id);

    for (ptr = groups; ptr; ptr = ptr->next) {
        group = ptr->data;
        g_object_get(group, "id", &id, NULL);
        g_string_append_printf(sql, "%d", id);
        if (ptr->next)
            g_string_append_printf(sql, ", ");
    }
    g_string_append_printf(sql, ")");
    if (prefix)
        g_string_append_printf(sql, " AND user_name LIKE '%s%%'", prefix);
    g_list_free_full (groups, g_object_unref);

    if (seaf_db_statement_foreach_row (db, sql->str,
                                        get_ccnet_groupuser_cb, &group_users, 0) < 0) {
        g_string_free(sql, TRUE);
        return NULL;
    }
    g_string_free(sql, TRUE);

    return group_users;
}

int
ccnet_group_manager_check_group_staff (CcnetGroupManager *mgr,
                                       int group_id,
                                       const char *user_name,
                                       gboolean in_structure)
{
    return check_group_staff (mgr->priv->db, group_id, user_name, in_structure);
}

int
ccnet_group_manager_remove_group_user (CcnetGroupManager *mgr,
                                       const char *user)
{
    CcnetDB *db = mgr->priv->db;

    seaf_db_statement_query (db,
                              "DELETE FROM GroupUser "
                              "WHERE user_name = ?",
                              1, "string", user);

    return 0;
}

int
ccnet_group_manager_is_group_user (CcnetGroupManager *mgr,
                                   int group_id,
                                   const char *user,
                                   gboolean in_structure)
{
    CcnetDB *db = mgr->priv->db;

    gboolean exists, err;
    exists = seaf_db_statement_exists (db, "SELECT group_id FROM GroupUser "
                                        "WHERE group_id=? AND user_name=?", &err,
                                        2, "int", group_id, "string", user);
    if (err) {
        ccnet_warning ("DB error when check user exist in GroupUser.\n");
        return 0;
    }
    if (!in_structure || exists)
        return exists ? 1 : 0;

    GList *ptr;
    GList *groups = ccnet_group_manager_get_groups_by_user (mgr, user, TRUE, NULL);
    if (!groups)
        return 0;

    CcnetGroup *group;
    int id;
    for (ptr = groups; ptr; ptr = ptr->next) {
        group = ptr->data;
        g_object_get (group, "id", &id, NULL);
        if (group_id == id) {
            exists = TRUE;
            break;
        }
    }
    g_list_free_full (groups, g_object_unref);

    return exists ? 1 : 0;
}

static gboolean
get_all_ccnetgroups_cb (CcnetDBRow *row, void *data)
{
    GList **plist = data;
    int group_id;
    const char *group_name;
    const char *creator;
    gint64 ts;
    int parent_group_id;

    group_id = seaf_db_row_get_column_int (row, 0);
    group_name = (const char *)seaf_db_row_get_column_text (row, 1);
    creator = (const char *)seaf_db_row_get_column_text (row, 2);
    ts = seaf_db_row_get_column_int64 (row, 3);
    parent_group_id = seaf_db_row_get_column_int (row, 4);

    char *creator_l = g_ascii_strdown (creator, -1);
    CcnetGroup *group = g_object_new (CCNET_TYPE_GROUP,
                                      "id", group_id,
                                      "group_name", group_name,
                                      "creator_name", creator_l,
                                      "timestamp", ts,
                                      "source", "DB",
                                      "parent_group_id", parent_group_id,
                                      NULL);
    g_free (creator_l);

    *plist = g_list_prepend (*plist, group);
    
    return TRUE;
}

GList *
ccnet_group_manager_get_top_groups (CcnetGroupManager *mgr,
                                    gboolean including_org,
                                    GError **error)
{
    CcnetDB *db = mgr->priv->db;
    GList *ret = NULL;
    GString *sql = g_string_new ("");
    const char *table_name = mgr->priv->table_name;
    int rc;

    if (seaf_db_type(mgr->priv->db) == SEAF_DB_TYPE_PGSQL) {
        if (including_org)
            g_string_printf (sql, "SELECT group_id, group_name, "
                                  "creator_name, timestamp, parent_group_id FROM \"%s\" "
                                  "WHERE parent_group_id=-1 ORDER BY timestamp DESC", table_name);
        else
            g_string_printf (sql, "SELECT g.group_id, g.group_name, "
                                  "g.creator_name, g.timestamp, g.parent_group_id FROM \"%s\" g "
                                  "LEFT JOIN OrgGroup o ON g.group_id = o.group_id "
                                  "WHERE g.parent_group_id=-1 AND o.group_id is NULL "
                                  "ORDER BY timestamp DESC", table_name);
    } else {
        if (including_org)
            g_string_printf (sql, "SELECT group_id, group_name, "
                                  "creator_name, timestamp, parent_group_id FROM `%s` "
                                  "WHERE parent_group_id=-1 ORDER BY timestamp DESC", table_name);
        else
            g_string_printf (sql, "SELECT g.group_id, g.group_name, "
                                  "g.creator_name, g.timestamp, g.parent_group_id FROM `%s` g "
                                  "LEFT JOIN OrgGroup o ON g.group_id = o.group_id "
                                  "WHERE g.parent_group_id=-1 AND o.group_id is NULL "
                                  "ORDER BY timestamp DESC", table_name);
    }
    rc = seaf_db_statement_foreach_row (db, sql->str,
                                         get_all_ccnetgroups_cb, &ret, 0);
    g_string_free (sql, TRUE);
    if (rc < 0)
        return NULL;

    return g_list_reverse (ret);
}

GList*
ccnet_group_manager_list_all_departments (CcnetGroupManager *mgr,
                                          GError **error)
{
    CcnetDB *db = mgr->priv->db;
    GList *ret = NULL;
    GString *sql = g_string_new ("");
    const char *table_name = mgr->priv->table_name;
    int rc;
    int db_type = seaf_db_type(db);

    if (db_type == SEAF_DB_TYPE_PGSQL) {
        g_string_printf (sql, "SELECT group_id, group_name, "
                              "creator_name, timestamp, type, "
                              "parent_group_id FROM \"%s\" "
                              "WHERE parent_group_id = -1 OR parent_group_id > 0 "
                              "ORDER BY group_id", table_name);
        rc = seaf_db_statement_foreach_row (db, sql->str,
                                             get_all_ccnetgroups_cb, &ret, 0);
    } else {
        g_string_printf (sql, "SELECT `group_id`, `group_name`, "
                              "`creator_name`, `timestamp`, `type`, `parent_group_id` FROM `%s` "
                              "WHERE parent_group_id = -1 OR parent_group_id > 0 "
                              "ORDER BY group_id", table_name);
        rc = seaf_db_statement_foreach_row (db, sql->str,
                                             get_all_ccnetgroups_cb, &ret, 0);
    }
    g_string_free (sql, TRUE);

    if (rc < 0)
        return NULL;

    return g_list_reverse (ret);
}

GList*
ccnet_group_manager_get_all_groups (CcnetGroupManager *mgr,
                                    int start, int limit, GError **error)
{
    CcnetDB *db = mgr->priv->db;
    GList *ret = NULL;
    GString *sql = g_string_new ("");
    const char *table_name = mgr->priv->table_name;
    int rc;

    if (seaf_db_type(mgr->priv->db) == SEAF_DB_TYPE_PGSQL) {
        if (start == -1 && limit == -1) {
            g_string_printf (sql, "SELECT group_id, group_name, "
                                  "creator_name, timestamp, parent_group_id FROM \"%s\" "
                                  "ORDER BY timestamp DESC", table_name);
            rc = seaf_db_statement_foreach_row (db, sql->str,
                                                 get_all_ccnetgroups_cb, &ret, 0);
        } else {
            g_string_printf (sql, "SELECT group_id, group_name, "
                                  "creator_name, timestamp, parent_group_id FROM \"%s\" "
                                  "ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                                  table_name);
            rc = seaf_db_statement_foreach_row (db, sql->str,
                                                 get_all_ccnetgroups_cb, &ret,
                                                 2, "int", limit, "int", start);
        }
    } else {
        if (start == -1 && limit == -1) {
            g_string_printf (sql, "SELECT `group_id`, `group_name`, "
                                  "`creator_name`, `timestamp`, `parent_group_id` FROM `%s` "
                                  "ORDER BY timestamp DESC", table_name);
            rc = seaf_db_statement_foreach_row (db, sql->str,
                                                 get_all_ccnetgroups_cb, &ret, 0);
        } else {
            g_string_printf (sql, "SELECT `group_id`, `group_name`, "
                                  "`creator_name`, `timestamp`, `parent_group_id` FROM `%s` "
                                  "ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                                  table_name);
            rc = seaf_db_statement_foreach_row (db, sql->str,
                                                 get_all_ccnetgroups_cb, &ret,
                                                 2, "int", limit, "int", start);
        }
    }
    g_string_free (sql, TRUE);

    if (rc < 0)
        return NULL;

    return g_list_reverse (ret);
}

int
ccnet_group_manager_set_group_creator (CcnetGroupManager *mgr,
                                       int group_id,
                                       const char *user_name)
{
    CcnetDB *db = mgr->priv->db;
    const char *table_name = mgr->priv->table_name;
    GString *sql = g_string_new ("");

    if (seaf_db_type(db) == SEAF_DB_TYPE_PGSQL) {
        g_string_printf (sql, "UPDATE \"%s\" SET creator_name = ? WHERE group_id = ?",
                         table_name);
    } else {
        g_string_printf (sql, "UPDATE `%s` SET creator_name = ? WHERE group_id = ?",
                         table_name);
    }

    seaf_db_statement_query (db, sql->str, 2, "string", user_name, "int", group_id);
    g_string_free (sql, TRUE);

    return 0;
    
}

GList *
ccnet_group_manager_search_groups (CcnetGroupManager *mgr,
                                   const char *keyword,
                                   int start, int limit)
{
    CcnetDB *db = mgr->priv->db;
    GList *ret = NULL;
    GString *sql = g_string_new ("");
    const char *table_name = mgr->priv->table_name;

    int rc;
    char *db_patt = g_strdup_printf ("%%%s%%", keyword);

    if (seaf_db_type(db) == SEAF_DB_TYPE_PGSQL) {
        if (start == -1 && limit == -1) {
            g_string_printf (sql,
                             "SELECT group_id, group_name, "
                             "creator_name, timestamp, parent_group_id "
                             "FROM \"%s\" WHERE group_name LIKE ?", table_name);
            rc = seaf_db_statement_foreach_row (db, sql->str,
                                                 get_all_ccnetgroups_cb, &ret,
                                                 1, "string", db_patt);
        } else {
            g_string_printf (sql,
                             "SELECT group_id, group_name, "
                             "creator_name, timestamp, parent_group_id "
                             "FROM \"%s\" WHERE group_name LIKE ? "
                             "LIMIT ? OFFSET ?", table_name);
            rc = seaf_db_statement_foreach_row (db, sql->str,
                                                 get_all_ccnetgroups_cb, &ret,
                                                 3, "string", db_patt,
                                                 "int", limit, "int", start);
        }
    } else {
        if (start == -1 && limit == -1) {
            g_string_printf (sql,
                             "SELECT group_id, group_name, "
                             "creator_name, timestamp, parent_group_id "
                             "FROM `%s` WHERE group_name LIKE ?", table_name);
            rc = seaf_db_statement_foreach_row (db, sql->str,
                                                 get_all_ccnetgroups_cb, &ret,
                                                 1, "string", db_patt);
        } else {
            g_string_printf (sql,
                             "SELECT group_id, group_name, "
                             "creator_name, timestamp, parent_group_id "
                             "FROM `%s` WHERE group_name LIKE ? "
                             "LIMIT ? OFFSET ?", table_name);
            rc = seaf_db_statement_foreach_row (db, sql->str,
                                                 get_all_ccnetgroups_cb, &ret,
                                                 3, "string", db_patt,
                                                 "int", limit, "int", start);
        }
    }
    g_free (db_patt);
    g_string_free (sql, TRUE);

    if (rc < 0) {
        while (ret != NULL) {
            g_object_unref (ret->data);
            ret = g_list_delete_link (ret, ret);
        }
        return NULL;
    }

    return g_list_reverse (ret);
}

static gboolean
get_groups_members_cb (CcnetDBRow *row, void *data)
{
    GList **users = data;
    const char *user = seaf_db_row_get_column_text (row, 0);

    char *user_l = g_ascii_strdown (user, -1);
    CcnetGroupUser *group_user = g_object_new (CCNET_TYPE_GROUP_USER,
                                               "user_name", user_l,
                                               NULL);
    g_free (user_l);
    *users = g_list_append(*users, group_user);

    return TRUE;
}

/* group_ids is json format: "[id1, id2, id3, ...]" */
GList *
ccnet_group_manager_get_groups_members (CcnetGroupManager *mgr, const char *group_ids,
                                        GError **error)
{
    CcnetDB *db = mgr->priv->db;
    GList *ret = NULL;
    GString *sql = g_string_new ("");
    int i, group_id;
    json_t *j_array = NULL, *j_obj;
    json_error_t j_error;

    g_string_printf (sql, "SELECT DISTINCT user_name FROM GroupUser WHERE group_id IN (");
    j_array = json_loadb (group_ids, strlen(group_ids), 0, &j_error);
    if (!j_array) {
        g_set_error (error, CCNET_DOMAIN, 0, "Bad args.");
        g_string_free (sql, TRUE);
        return NULL;
    }
    size_t id_num = json_array_size (j_array);

    for (i = 0; i < id_num; i++) {
        j_obj = json_array_get (j_array, i);
        group_id = json_integer_value (j_obj);
        if (group_id <= 0) {
            g_set_error (error, CCNET_DOMAIN, 0, "Bad args.");
            g_string_free (sql, TRUE);
            json_decref (j_array);
            return NULL;
        }
        g_string_append_printf (sql, "%d", group_id);
        if (i + 1 < id_num)
            g_string_append_printf (sql, ",");
    }
    g_string_append_printf (sql, ")");
    json_decref (j_array);

    if (seaf_db_statement_foreach_row (db, sql->str, get_groups_members_cb, &ret, 0) < 0)
        ccnet_warning("Failed to get groups members for group [%s].\n", group_ids);

    g_string_free (sql, TRUE);

    return ret;
}

GList*
ccnet_group_manager_search_group_members (CcnetGroupManager *mgr,
                                          int group_id,
                                          const char *pattern)
{
    CcnetDB *db = mgr->priv->db;
    GList *ret = NULL;
    char *sql;
    int rc;

    char *db_patt = g_strdup_printf ("%%%s%%", pattern);

    sql = "SELECT DISTINCT user_name FROM GroupUser "
          "WHERE group_id = ? AND user_name LIKE ? ORDER BY user_name";
    rc = seaf_db_statement_foreach_row (db, sql,
                                        get_groups_members_cb, &ret,
                                        2, "int", group_id, "string", db_patt);

    g_free (db_patt);
    if (rc < 0) {
        g_list_free_full (ret, g_object_unref);
        return NULL;
    }

    return g_list_reverse (ret);
}

int
ccnet_group_manager_update_group_user (CcnetGroupManager *mgr,
                                       const char *old_email,
                                       const char *new_email)
{
    int rc;
    CcnetDB *db = mgr->priv->db;

    rc = seaf_db_statement_query (db,
                                  "UPDATE GroupUser SET user_name=? "
                                  "WHERE user_name = ?",
                                  2, "string", new_email, "string", old_email);
    if (rc < 0){
        return -1;
    }

    return 0;
}
