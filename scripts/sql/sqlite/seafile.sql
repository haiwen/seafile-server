CREATE TABLE IF NOT EXISTS Branch (name VARCHAR(10), repo_id CHAR(40), commit_id CHAR(40), PRIMARY KEY (repo_id, name));
CREATE TABLE IF NOT EXISTS Repo (repo_id CHAR(37) PRIMARY KEY);
CREATE TABLE IF NOT EXISTS RepoOwner (repo_id CHAR(37) PRIMARY KEY, owner_id TEXT);
CREATE INDEX IF NOT EXISTS OwnerIndex ON RepoOwner (owner_id);

CREATE TABLE IF NOT EXISTS RepoGroup (repo_id CHAR(37), group_id INTEGER, user_name TEXT, permission CHAR(15));
CREATE UNIQUE INDEX IF NOT EXISTS groupid_repoid_indx on RepoGroup (group_id, repo_id);
CREATE INDEX IF NOT EXISTS repogroup_repoid_index on RepoGroup (repo_id);
CREATE INDEX IF NOT EXISTS repogroup_username_indx on RepoGroup (user_name);
CREATE TABLE IF NOT EXISTS InnerPubRepo (repo_id CHAR(37) PRIMARY KEY, permission CHAR(15));

CREATE TABLE IF NOT EXISTS OrgRepo (org_id INTEGER, repo_id CHAR(37), user VARCHAR(255));
CREATE UNIQUE INDEX IF NOT EXISTS repoid_indx on OrgRepo (repo_id);
CREATE INDEX IF NOT EXISTS orgid_repoid_indx on OrgRepo (org_id, repo_id);
CREATE INDEX IF NOT EXISTS orgrepo_orgid_user_indx on OrgRepo (org_id, user);
CREATE INDEX IF NOT EXISTS orgrepo_user_indx on OrgRepo (user);
CREATE TABLE IF NOT EXISTS OrgGroupRepo (org_id INTEGER, repo_id CHAR(37), group_id INTEGER, owner VARCHAR(255), permission CHAR(15));
CREATE UNIQUE INDEX IF NOT EXISTS orgid_groupid_repoid_indx on OrgGroupRepo (org_id, group_id, repo_id);
CREATE INDEX IF NOT EXISTS org_repoid_index on OrgGroupRepo (repo_id);
CREATE INDEX IF NOT EXISTS org_owner_indx on OrgGroupRepo (owner);
CREATE TABLE IF NOT EXISTS OrgInnerPubRepo (org_id INTEGER, repo_id CHAR(37), permission CHAR(15), PRIMARY KEY (org_id, repo_id));
CREATE TABLE IF NOT EXISTS RepoUserToken (repo_id CHAR(37), email VARCHAR(255), token CHAR(41));
CREATE UNIQUE INDEX IF NOT EXISTS repo_token_indx on RepoUserToken (repo_id, token);
CREATE INDEX IF NOT EXISTS repo_token_email_indx on RepoUserToken (email);
CREATE TABLE IF NOT EXISTS RepoTokenPeerInfo (token CHAR(41) PRIMARY KEY, peer_id CHAR(41), peer_ip VARCHAR(41), peer_name VARCHAR(255), sync_time BIGINT, client_ver VARCHAR(20));
CREATE TABLE IF NOT EXISTS RepoSyncError (token CHAR(41) PRIMARY KEY, error_time BIGINT, error_con VARCHAR(1024));
CREATE TABLE IF NOT EXISTS RepoHead (repo_id CHAR(37) PRIMARY KEY, branch_name VARCHAR(10));
CREATE TABLE IF NOT EXISTS RepoSize (repo_id CHAR(37) PRIMARY KEY, size BIGINT UNSIGNED, head_id CHAR(41));
CREATE TABLE IF NOT EXISTS RepoHistoryLimit (repo_id CHAR(37) PRIMARY KEY, days INTEGER);
CREATE TABLE IF NOT EXISTS RepoValidSince (repo_id CHAR(37) PRIMARY KEY, timestamp BIGINT);
CREATE TABLE IF NOT EXISTS WebAP (repo_id CHAR(37) PRIMARY KEY, access_property CHAR(10));
CREATE TABLE IF NOT EXISTS VirtualRepo (repo_id CHAR(36) PRIMARY KEY, origin_repo CHAR(36), path TEXT, base_commit CHAR(40));
CREATE INDEX IF NOT EXISTS virtualrepo_origin_repo_idx ON VirtualRepo (origin_repo);
CREATE INDEX IF NOT EXISTS virtualrepo_unique_idx ON VirtualRepo (origin_repo, path);
CREATE TABLE IF NOT EXISTS GarbageRepos (repo_id CHAR(36) PRIMARY KEY);
CREATE TABLE IF NOT EXISTS RepoTrash (repo_id CHAR(36) PRIMARY KEY, repo_name VARCHAR(255), head_id CHAR(40), owner_id VARCHAR(255), size BIGINT UNSIGNED, org_id INTEGER, del_time BIGINT);
CREATE INDEX IF NOT EXISTS repotrash_owner_id_idx ON RepoTrash(owner_id);
CREATE INDEX IF NOT EXISTS repotrash_org_id_idx ON RepoTrash(org_id);
CREATE TABLE IF NOT EXISTS RepoFileCount (repo_id CHAR(36) PRIMARY KEY, file_count BIGINT UNSIGNED);
CREATE TABLE IF NOT EXISTS FolderUserPerm (repo_id CHAR(36) NOT NULL, path TEXT NOT NULL, permission CHAR(15), user VARCHAR(255) NOT NULL);
CREATE INDEX IF NOT EXISTS folder_user_perm_idx ON FolderUserPerm(repo_id);
CREATE TABLE IF NOT EXISTS FolderGroupPerm (repo_id CHAR(36) NOT NULL, path TEXT NOT NULL, permission CHAR(15), group_id INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS folder_group_perm_idx ON FolderGroupPerm(repo_id);
CREATE TABLE IF NOT EXISTS FolderPermTimestamp (repo_id CHAR(36) PRIMARY KEY, timestamp INTEGER);
CREATE TABLE IF NOT EXISTS WebUploadTempFiles (repo_id CHAR(40) NOT NULL, file_path TEXT NOT NULL, tmp_file_path TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS RepoInfo (repo_id CHAR(36) PRIMARY KEY, name VARCHAR(255) NOT NULL, update_time INTEGER, version INTEGER, is_encrypted INTEGER, last_modifier VARCHAR(255), status INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS RepoStorageId (repo_id CHAR(40) NOT NULL, storage_id VARCHAR(255) NOT NULL);
CREATE TABLE IF NOT EXISTS UserQuota (user VARCHAR(255) PRIMARY KEY, quota BIGINT);
CREATE TABLE IF NOT EXISTS UserShareQuota (user VARCHAR(255) PRIMARY KEY, quota BIGINT);
CREATE TABLE IF NOT EXISTS OrgQuota (org_id INTEGER PRIMARY KEY, quota BIGINT);
CREATE TABLE IF NOT EXISTS OrgUserQuota (org_id INTEGER, user VARCHAR(255), quota BIGINT, PRIMARY KEY (org_id, user));
CREATE TABLE IF NOT EXISTS RoleQuota (role VARCHAR(255) PRIMARY KEY, quota BIGINT);
CREATE TABLE IF NOT EXISTS SeafileConf (cfg_group VARCHAR(255) NOT NULL, cfg_key VARCHAR(255) NOT NULL, value VARCHAR(255), property INTEGER);
CREATE TABLE IF NOT EXISTS FileLocks (repo_id CHAR(40) NOT NULL, path TEXT NOT NULL, user_name VARCHAR(255) NOT NULL, lock_time BIGINT, expire BIGINT);
CREATE INDEX IF NOT EXISTS FileLocksIndex ON FileLocks (repo_id);
CREATE TABLE IF NOT EXISTS FileLockTimestamp (repo_id CHAR(40) PRIMARY KEY, update_time BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS SharedRepo (repo_id CHAR(37) , from_email VARCHAR(255), to_email VARCHAR(255), permission CHAR(15));
CREATE INDEX IF NOT EXISTS RepoIdIndex on SharedRepo (repo_id);
CREATE INDEX IF NOT EXISTS FromEmailIndex on SharedRepo (from_email);
CREATE INDEX IF NOT EXISTS ToEmailIndex on SharedRepo (to_email);
CREATE TABLE IF NOT EXISTS OrgSharedRepo (org_id INTEGER, repo_id CHAR(37) , from_email VARCHAR(255), to_email VARCHAR(255), permission CHAR(15));
CREATE INDEX IF NOT EXISTS OrgRepoIdIndex on OrgSharedRepo (org_id, repo_id);
CREATE INDEX IF NOT EXISTS OrgFromEmailIndex on OrgSharedRepo (from_email);
CREATE INDEX IF NOT EXISTS OrgToEmailIndex on OrgSharedRepo (to_email);
CREATE INDEX IF NOT EXISTS OrgLibIdIndex on OrgSharedRepo (repo_id);
CREATE TABLE IF NOT EXISTS SystemInfo (info_key VARCHAR(256), info_value VARCHAR(1024));
