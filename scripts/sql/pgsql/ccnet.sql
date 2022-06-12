CREATE TABLE IF NOT EXISTS Binding (
 id BIGSERIAL PRIMARY KEY,
 email VARCHAR(255),
 peer_id CHAR(41));
CREATE UNIQUE INDEX IF NOT EXISTS binding_peerid_idx ON Binding (peer_id);
CREATE INDEX IF NOT EXISTS binding_email_idx ON Binding (email);

CREATE TABLE IF NOT EXISTS EmailUser (
 id BIGSERIAL PRIMARY KEY,
 email VARCHAR(255),
 passwd VARCHAR(256),
 is_staff BOOLEAN NOT NULL,
 is_active BOOLEAN NOT NULL,
 ctime BIGINT,
 reference_id VARCHAR(255));
-- existing index, reuse old name
CREATE UNIQUE INDEX IF NOT EXISTS emailuser_email_key ON EmailUser (email);
-- existing index, reuse old name
CREATE UNIQUE INDEX IF NOT EXISTS emailuser_reference_id_idx ON EmailUser (reference_id);

CREATE TABLE IF NOT EXISTS "Group" (
 group_id BIGSERIAL PRIMARY KEY,
 group_name VARCHAR(255),
 creator_name VARCHAR(255),
 timestamp BIGINT,
 type VARCHAR(32),
 parent_group_id INTEGER);

CREATE TABLE IF NOT EXISTS GroupDNPair (
 id BIGSERIAL PRIMARY KEY,
 group_id INTEGER,
 dn VARCHAR(255));

CREATE TABLE IF NOT EXISTS GroupStructure (
 id BIGSERIAL PRIMARY KEY,
 group_id INTEGER,
 path VARCHAR(1024));
CREATE UNIQUE INDEX IF NOT EXISTS groupstructure_groupid_idx ON GroupStructure (group_id);
-- existing index, reuse old name
CREATE INDEX IF NOT EXISTS structure_path_idx ON GroupStructure (path);

CREATE TABLE IF NOT EXISTS GroupUser (
 id BIGSERIAL PRIMARY KEY,
 group_id BIGINT,
 user_name VARCHAR(255),
 is_staff BOOLEAN);
-- existing index, reuse old name
CREATE UNIQUE INDEX IF NOT EXISTS groupuser_group_id_user_name_key ON GroupUser (group_id, user_name);
-- existing index, reuse old name
CREATE INDEX IF NOT EXISTS groupuser_username_idx ON GroupUser (user_name);

CREATE TABLE IF NOT EXISTS LDAPConfig (
 id BIGSERIAL PRIMARY KEY,
 cfg_group VARCHAR(255) NOT NULL,
 cfg_key VARCHAR(255) NOT NULL,
 value VARCHAR(255),
 property INTEGER);

CREATE TABLE IF NOT EXISTS LDAPUsers (
 id BIGSERIAL PRIMARY KEY,
 email VARCHAR(255) NOT NULL,
 password varchar(255) NOT NULL,
 is_staff BOOLEAN NOT NULL,
 is_active BOOLEAN NOT NULL,
 extra_attrs TEXT,
 reference_id VARCHAR(255));
-- existing index, reuse old name
CREATE UNIQUE INDEX IF NOT EXISTS ldapusers_email_idx ON LDAPUsers (email);
-- existing index, reuse old name
CREATE UNIQUE INDEX IF NOT EXISTS ldapusers_reference_id_idx ON LDAPUsers (reference_id);

CREATE TABLE IF NOT EXISTS OrgGroup (
 id BIGSERIAL PRIMARY KEY,
 org_id INTEGER,
 group_id INTEGER);
-- existing index, reuse old name
CREATE UNIQUE INDEX IF NOT EXISTS orggroup_org_id_group_id_key ON OrgGroup (org_id, group_id);
-- existing index, reuse old name
CREATE INDEX IF NOT EXISTS orggroup_groupid_idx ON OrgGroup (group_id);

CREATE TABLE IF NOT EXISTS OrgUser (
 id BIGSERIAL PRIMARY KEY,
 org_id INTEGER,
 email VARCHAR(255),
 is_staff BOOLEAN NOT NULL);
-- existing index, reuse old name
CREATE UNIQUE INDEX IF NOT EXISTS orguser_org_id_email_key ON OrgUser (org_id, email);
-- existing index, reuse old name
CREATE INDEX IF NOT EXISTS orguser_email_idx ON OrgUser (email);

CREATE TABLE IF NOT EXISTS Organization (
 org_id BIGSERIAL PRIMARY KEY,
 org_name VARCHAR(255),
 url_prefix VARCHAR(255),
 creator VARCHAR(255),
 ctime BIGINT);
-- existing index, reuse old name
CREATE UNIQUE INDEX IF NOT EXISTS organization_url_prefix_key ON Organization (url_prefix);

CREATE TABLE IF NOT EXISTS UserRole (
 id BIGSERIAL PRIMARY KEY,
 email VARCHAR(255),
 "role" VARCHAR(255),
 is_manual_set BOOLEAN DEFAULT false);
-- existing index, reuse old name
CREATE UNIQUE INDEX IF NOT EXISTS userrole_email_role_key ON UserRole (email, role);
-- existing index, reuse old name
CREATE INDEX IF NOT EXISTS userrole_email_idx ON UserRole (email);
