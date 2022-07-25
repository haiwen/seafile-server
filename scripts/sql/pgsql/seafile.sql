CREATE TABLE IF NOT EXISTS Branch (
 id BIGSERIAL PRIMARY KEY,
 name VARCHAR(10),
 repo_id CHAR(41),
 commit_id CHAR(41));
CREATE UNIQUE INDEX IF NOT EXISTS branch_repoidname_idx ON Branch (repo_id, name);

CREATE TABLE IF NOT EXISTS FileLockTimestamp (
 id BIGSERIAL PRIMARY KEY,
 repo_id CHAR(40),
 update_time BIGINT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS filelocktimestamp_repoid_idx ON FileLockTimestamp (repo_id);

CREATE TABLE IF NOT EXISTS FileLocks (
 id BIGSERIAL PRIMARY KEY,
 repo_id CHAR(40) NOT NULL,
 path TEXT NOT NULL,
 user_name VARCHAR(255) NOT NULL,
 lock_time BIGINT,
 expire BIGINT);
CREATE INDEX IF NOT EXISTS filelocks_repoid_idx ON FileLocks (repo_id);

CREATE TABLE IF NOT EXISTS FolderGroupPerm (
 id BIGSERIAL PRIMARY KEY,
 repo_id CHAR(36) NOT NULL,
 path TEXT NOT NULL,
 permission CHAR(15),
 group_id INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS foldergroupperm_repoid_idx ON FolderGroupPerm (repo_id);

CREATE TABLE IF NOT EXISTS FolderPermTimestamp (
 id BIGSERIAL PRIMARY KEY,
 repo_id CHAR(36),
 timestamp BIGINT);
CREATE UNIQUE INDEX IF NOT EXISTS folderpermtimestamp_repoid_idx ON FolderPermTimestamp (repo_id);

CREATE TABLE IF NOT EXISTS FolderUserPerm (
 id BIGSERIAL PRIMARY KEY,
 repo_id CHAR(36) NOT NULL,
 path TEXT NOT NULL,
 permission CHAR(15),
 "user" VARCHAR(255) NOT NULL);
CREATE INDEX IF NOT EXISTS folderuserperm_repoid_idx ON FolderUserPerm (repo_id);

CREATE TABLE IF NOT EXISTS GCID (
 id BIGSERIAL PRIMARY KEY,
 repo_id CHAR(36),
 gc_id CHAR(36));
CREATE UNIQUE INDEX IF NOT EXISTS gcid_repoid_idx ON GCID (repo_id);

CREATE TABLE IF NOT EXISTS GarbageRepos (
 id BIGSERIAL PRIMARY KEY,
 repo_id CHAR(36));
CREATE UNIQUE INDEX IF NOT EXISTS garbagerepos_repoid_idx ON GarbageRepos (repo_id);

CREATE TABLE IF NOT EXISTS InnerPubRepo (
 id BIGSERIAL PRIMARY KEY,
 repo_id CHAR(37),
 permission CHAR(15));
CREATE UNIQUE INDEX IF NOT EXISTS innerpubrepo_repoid_idx ON InnerPubRepo (repo_id);

CREATE TABLE IF NOT EXISTS LastGCID (
 id BIGSERIAL PRIMARY KEY,
 repo_id CHAR(36),
 client_id VARCHAR(128),
 gc_id CHAR(36));
CREATE UNIQUE INDEX IF NOT EXISTS lastgcid_repoid_clientid_idx ON LastGCID (repo_id, client_id);

CREATE TABLE IF NOT EXISTS OrgGroupRepo (
 id BIGSERIAL PRIMARY KEY,
 org_id INTEGER,
 repo_id CHAR(37),
 group_id INTEGER,
 "owner" VARCHAR(255),
 permission CHAR(15));
CREATE UNIQUE INDEX IF NOT EXISTS orggrouprepo_orgid_groupid_repoid_idx ON OrgGroupRepo (org_id, group_id, repo_id);
CREATE INDEX IF NOT EXISTS orggrouprepo_repoid_idx ON OrgGroupRepo (repo_id);
CREATE INDEX IF NOT EXISTS orggrouprepo_owner_idx ON OrgGroupRepo (owner);

CREATE TABLE IF NOT EXISTS OrgInnerPubRepo (
 id BIGSERIAL PRIMARY KEY,
 org_id INTEGER,
 repo_id CHAR(37),
 permission CHAR(15));
CREATE UNIQUE INDEX IF NOT EXISTS orginnerpubrepo_orgid_repoid_idx ON OrgInnerPubRepo (org_id, repo_id);

CREATE TABLE IF NOT EXISTS OrgQuota (
 id BIGSERIAL PRIMARY KEY,
 org_id INTEGER,
 quota BIGINT);
CREATE UNIQUE INDEX IF NOT EXISTS orgquota_orgid_idx ON OrgQuota (org_id);

CREATE TABLE IF NOT EXISTS OrgRepo (
 id BIGSERIAL PRIMARY KEY,
 org_id INTEGER,
 repo_id CHAR(37),
 "user" VARCHAR(255));
CREATE UNIQUE INDEX IF NOT EXISTS orgrepo_orgid_repoid_idx ON OrgRepo (org_id, repo_id);
CREATE UNIQUE INDEX IF NOT EXISTS orgrepo_repoid_idx ON OrgRepo (repo_id);
CREATE INDEX IF NOT EXISTS orgrepo_orgid_user_idx ON OrgRepo (org_id, "user");
CREATE INDEX IF NOT EXISTS orgrepo_user_idx ON OrgRepo ("user");

CREATE TABLE IF NOT EXISTS OrgSharedRepo (
 id SERIAL PRIMARY KEY,
 org_id INT,
 repo_id CHAR(37),
 from_email VARCHAR(255),
 to_email VARCHAR(255),
 permission CHAR(15));
CREATE INDEX IF NOT EXISTS orgsharedrepo_repoid_idx ON OrgSharedRepo (repo_id);
CREATE INDEX IF NOT EXISTS orgsharedrepo_orgid_repoid_idx ON OrgSharedRepo (org_id, repo_id);
CREATE INDEX IF NOT EXISTS orgsharedrepo_from_email_idx ON OrgSharedRepo (from_email);
CREATE INDEX IF NOT EXISTS orgsharedrepo_to_email_idx ON OrgSharedRepo (to_email);

CREATE TABLE IF NOT EXISTS OrgUserQuota (
 id BIGSERIAL PRIMARY KEY,
 org_id INTEGER,
 "user" VARCHAR(255),
 quota BIGINT);
CREATE UNIQUE INDEX IF NOT EXISTS orguserquota_orgid_user_idx ON OrgUserQuota (org_id, "user");

CREATE TABLE IF NOT EXISTS Repo (
 id BIGSERIAL PRIMARY KEY,
 repo_id CHAR(37));
CREATE UNIQUE INDEX IF NOT EXISTS repo_repoid_idx ON Repo (repo_id);

CREATE TABLE IF NOT EXISTS RepoFileCount (
 id BIGSERIAL PRIMARY KEY,
 repo_id CHAR(36),
 file_count BIGINT);
CREATE UNIQUE INDEX IF NOT EXISTS repofilecount_repoid_idx ON RepoFileCount (repo_id);

CREATE TABLE IF NOT EXISTS RepoGroup (
 id BIGSERIAL PRIMARY KEY,
 repo_id CHAR(37),
 group_id INTEGER,
 user_name VARCHAR(255),
 permission CHAR(15));
-- existing index, reuse old name
CREATE UNIQUE INDEX IF NOT EXISTS repogroup_group_id_repo_id_idx ON RepoGroup (group_id, repo_id);
-- existing index, reuse old name
CREATE INDEX IF NOT EXISTS repogroup_repoid_idx ON RepoGroup (repo_id);
-- existing index, reuse old name
CREATE INDEX IF NOT EXISTS repogroup_username_idx ON RepoGroup (user_name);

CREATE TABLE IF NOT EXISTS RepoHead (
 id BIGSERIAL PRIMARY KEY,
 repo_id CHAR(37),
 branch_name VARCHAR(10));
CREATE UNIQUE INDEX IF NOT EXISTS repohead_repoid_idx ON RepoHead (repo_id);

CREATE TABLE IF NOT EXISTS RepoHistoryLimit (
 id BIGSERIAL PRIMARY KEY,
 repo_id CHAR(37),
 days INTEGER);
CREATE UNIQUE INDEX IF NOT EXISTS repohistorylimit_repoid_idx ON RepoHistoryLimit (repo_id);

CREATE TABLE IF NOT EXISTS RepoInfo (
 id BIGSERIAL PRIMARY KEY,
 repo_id CHAR(36),
 name VARCHAR(255) NOT NULL,
 update_time BIGINT,
 version INTEGER,
 is_encrypted INTEGER,
 last_modifier VARCHAR(255),
 status INTEGER DEFAULT 0);
CREATE UNIQUE INDEX IF NOT EXISTS repoinfo_repoid_idx ON RepoInfo (repo_id);

CREATE TABLE IF NOT EXISTS RepoOwner (
 id BIGSERIAL PRIMARY KEY,
 repo_id CHAR(37),
 owner_id VARCHAR(255));
CREATE UNIQUE INDEX IF NOT EXISTS repoowner_repoid_idx ON RepoOwner (repo_id);
-- existing index, reuse old name
CREATE INDEX IF NOT EXISTS repoowner_owner_idx ON RepoOwner (owner_id);

CREATE TABLE IF NOT EXISTS RepoSize (
 id BIGSERIAL PRIMARY KEY,
 repo_id CHAR(37),
 size BIGINT,
 head_id CHAR(41));
CREATE UNIQUE INDEX IF NOT EXISTS reposize_repoid_idx ON RepoSize (repo_id);

CREATE TABLE IF NOT EXISTS RepoStorageId (
 id BIGSERIAL PRIMARY KEY,
 repo_id CHAR(40) NOT NULL,
 storage_id VARCHAR(255) NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS repostorageid_repoid_idx ON RepoStorageId (repo_id);

CREATE TABLE IF NOT EXISTS RepoSyncError (
 id BIGSERIAL PRIMARY KEY,
 token CHAR(41),
 error_time BIGINT,
 error_con VARCHAR(1024));
-- existing index, reuse old name
CREATE UNIQUE INDEX IF NOT EXISTS reposyncerror_token_key ON RepoSyncError (token);

CREATE TABLE IF NOT EXISTS RepoTokenPeerInfo (
 id BIGSERIAL PRIMARY KEY,
 token CHAR(41),
 peer_id CHAR(41),
 peer_ip VARCHAR(41),
 peer_name VARCHAR(255),
 sync_time BIGINT,
 client_ver VARCHAR(20));
CREATE UNIQUE INDEX IF NOT EXISTS repotokenpeerinfo_token_idx ON RepoTokenPeerInfo (token);
CREATE INDEX IF NOT EXISTS repotokenpeerinfo_peerid_idx ON RepoTokenPeerInfo (peer_id);

CREATE TABLE IF NOT EXISTS RepoTrash (
 id BIGSERIAL PRIMARY KEY,
 repo_id CHAR(36),
 repo_name VARCHAR(255),
 head_id CHAR(40),
 owner_id VARCHAR(255),
 size BIGINT,
 org_id INTEGER,
 del_time BIGINT);
CREATE UNIQUE INDEX IF NOT EXISTS repotrash_repoid_idx ON RepoTrash (repo_id);
-- existing index, reuse old name
CREATE INDEX IF NOT EXISTS repotrash_owner_id ON RepoTrash (owner_id);
-- existing index, reuse old name
CREATE INDEX IF NOT EXISTS repotrash_org_id ON RepoTrash (org_id);

CREATE TABLE IF NOT EXISTS RepoUserToken (
 id BIGSERIAL PRIMARY KEY,
 repo_id CHAR(37),
 email VARCHAR(255),
 token CHAR(41));
-- existing index, reuse old name
CREATE UNIQUE INDEX IF NOT EXISTS repousertoken_repo_id_token_key ON RepoUserToken (repo_id, token);
CREATE INDEX IF NOT EXISTS repousertoken_token_idx ON RepoUserToken (token);
-- existing index, reuse old name
CREATE INDEX IF NOT EXISTS repousertoken_email_idx ON RepoUserToken (email);

CREATE TABLE IF NOT EXISTS RepoValidSince (
 id BIGSERIAL PRIMARY KEY,
 repo_id CHAR(37),
 timestamp BIGINT);
CREATE UNIQUE INDEX IF NOT EXISTS repovalidsince_repoid_idx ON RepoValidSince (repo_id);

CREATE TABLE IF NOT EXISTS RoleQuota (
 id BIGSERIAL PRIMARY KEY,
 "role" VARCHAR(255),
 quota BIGINT);
CREATE UNIQUE INDEX IF NOT EXISTS rolequota_role_idx ON RoleQuota ("role");

CREATE TABLE IF NOT EXISTS SeafileConf (
 id BIGSERIAL PRIMARY KEY,
 cfg_group VARCHAR(255) NOT NULL,
 cfg_key VARCHAR(255) NOT NULL,
 value VARCHAR(255),
 property INTEGER);

CREATE TABLE IF NOT EXISTS SharedRepo (
 id BIGSERIAL PRIMARY KEY,
 repo_id CHAR(37),
 from_email VARCHAR(255),
 to_email VARCHAR(255),
 permission CHAR(15));
-- existing index, reuse old name
CREATE INDEX IF NOT EXISTS sharedrepo_from_email_idx ON SharedRepo (from_email);
-- existing index, reuse old name
CREATE INDEX IF NOT EXISTS sharedrepo_repoid_idx ON SharedRepo (repo_id);
-- existing index, reuse old name
CREATE INDEX IF NOT EXISTS sharedrepo_to_email_idx ON SharedRepo (to_email);

CREATE TABLE IF NOT EXISTS SystemInfo (
 id BIGSERIAL PRIMARY KEY,
 info_key VARCHAR(256),
 info_value VARCHAR(1024));

CREATE TABLE IF NOT EXISTS UserQuota (
 id BIGSERIAL PRIMARY KEY,
 "user" VARCHAR(255),
 quota BIGINT);
CREATE UNIQUE INDEX IF NOT EXISTS userquota_user_idx ON UserQuota ("user");

CREATE TABLE IF NOT EXISTS UserShareQuota (
 id BIGSERIAL PRIMARY KEY,
 "user" VARCHAR(255),
 quota BIGINT);
CREATE UNIQUE INDEX IF NOT EXISTS usersharequota_user_idx ON UserShareQuota ("user");

CREATE TABLE IF NOT EXISTS VirtualRepo (
 id BIGSERIAL PRIMARY KEY,
 repo_id CHAR(36),
 origin_repo CHAR(36),
 path TEXT,
 base_commit CHAR(40));
CREATE UNIQUE INDEX IF NOT EXISTS virtualrepo_repoid_idx ON VirtualRepo (repo_id);
-- existing index, reuse old name
CREATE INDEX IF NOT EXISTS virtualrepo_origin_repo_idx ON VirtualRepo (origin_repo);

CREATE TABLE IF NOT EXISTS WebAP (
 id BIGSERIAL PRIMARY KEY,
 repo_id CHAR(37),
 access_property CHAR(10));
CREATE UNIQUE INDEX IF NOT EXISTS webap_repoid_idx ON WebAP (repo_id);

CREATE TABLE IF NOT EXISTS WebUploadTempFiles (
 id BIGSERIAL PRIMARY KEY,
 repo_id CHAR(40) NOT NULL,
 file_path TEXT NOT NULL,
 tmp_file_path TEXT NOT NULL);
