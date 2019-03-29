CREATE TABLE Branch (name VARCHAR(10), repo_id CHAR(41), commit_id CHAR(41),PRIMARY KEY (repo_id, name));

CREATE TABLE Repo (repo_id CHAR(37) PRIMARY KEY);

CREATE TABLE RepoOwner (repo_id CHAR(37) PRIMARY KEY, owner_id TEXT);
CREATE INDEX OwnerIndex ON RepoOwner (owner_id);

CREATE TABLE RepoGroup (repo_id CHAR(37), group_id INTEGER, user_name TEXT, permission CHAR(15));
CREATE UNIQUE INDEX groupid_repoid_indx on RepoGroup (group_id, repo_id);
CREATE INDEX repogroup_repoid_index on RepoGroup (repo_id);
CREATE INDEX repogroup_username_indx on RepoGroup (user_name);

CREATE TABLE InnerPubRepo (repo_id CHAR(37) PRIMARY KEY,permission CHAR(15));

CREATE TABLE RepoUserToken (repo_id CHAR(37), email VARCHAR(255), token CHAR(41));
CREATE UNIQUE INDEX repo_token_indx on RepoUserToken (repo_id, token);
CREATE INDEX repo_token_email_indx on RepoUserToken (email);

CREATE TABLE RepoTokenPeerInfo (token CHAR(41) PRIMARY KEY, peer_id CHAR(41), peer_ip VARCHAR(41), peer_name VARCHAR(255), sync_time BIGINT, client_ver VARCHAR(20));

CREATE TABLE RepoHead (repo_id CHAR(37) PRIMARY KEY, branch_name VARCHAR(10));

CREATE TABLE RepoSize (repo_id CHAR(37) PRIMARY KEY,size BIGINT UNSIGNED,head_id CHAR(41));

CREATE TABLE RepoHistoryLimit (repo_id CHAR(37) PRIMARY KEY, days INTEGER);

CREATE TABLE RepoValidSince (repo_id CHAR(37) PRIMARY KEY, timestamp BIGINT);

CREATE TABLE WebAP (repo_id CHAR(37) PRIMARY KEY, access_property CHAR(10));

CREATE TABLE VirtualRepo (repo_id CHAR(36) PRIMARY KEY,origin_repo CHAR(36), path TEXT, base_commit CHAR(40));
CREATE INDEX virtualrepo_origin_repo_idx ON VirtualRepo (origin_repo);

CREATE TABLE GarbageRepos (repo_id CHAR(36) PRIMARY KEY);

CREATE TABLE RepoTrash (repo_id CHAR(36) PRIMARY KEY,repo_name VARCHAR(255), head_id CHAR(40), owner_id VARCHAR(255), size BIGINT UNSIGNED,org_id INTEGER, del_time BIGINT);
CREATE INDEX repotrash_owner_id_idx ON RepoTrash(owner_id);
CREATE INDEX repotrash_org_id_idx ON RepoTrash(org_id);

CREATE TABLE RepoFileCount (repo_id CHAR(36) PRIMARY KEY,file_count BIGINT UNSIGNED);

CREATE TABLE RepoInfo (repo_id CHAR(36) PRIMARY KEY, name VARCHAR(255) NOT NULL, update_time INTEGER, version INTEGER, is_encrypted INTEGER, last_modifier VARCHAR(255), status INTEGER DEFAULT 0);

CREATE TABLE UserQuota (user VARCHAR(255) PRIMARY KEY,quota BIGINT);

CREATE TABLE UserShareQuota (user VARCHAR(255) PRIMARY KEY,quota BIGINT);

CREATE TABLE OrgQuota (org_id INTEGER PRIMARY KEY,quota BIGINT);

CREATE TABLE OrgUserQuota (org_id INTEGER,user VARCHAR(255), quota BIGINT, PRIMARY KEY (org_id, user));

CREATE TABLE SeafileConf (cfg_group VARCHAR(255) NOT NULL,cfg_key VARCHAR(255) NOT NULL, value VARCHAR(255), property INTEGER);

CREATE TABLE SharedRepo (repo_id CHAR(37) , from_email VARCHAR(255), to_email VARCHAR(255), permission CHAR(15));
CREATE INDEX RepoIdIndex on SharedRepo (repo_id);
CREATE INDEX FromEmailIndex on SharedRepo (from_email);
CREATE INDEX ToEmailIndex on SharedRepo (to_email);

CREATE TABLE SystemInfo( info_key VARCHAR(256), info_value VARCHAR(1024));

CREATE TABLE WebUploadTempFiles (repo_id CHAR(40) NOT NULL, file_path TEXT NOT NULL, tmp_file_path TEXT NOT NULL);
