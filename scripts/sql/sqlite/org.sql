CREATE TABLE OrgGroup (org_id INTEGER, group_id INTEGER);
CREATE INDEX groupid_indx on OrgGroup (group_id);
CREATE UNIQUE INDEX org_group_indx on OrgGroup (org_id, group_id);

CREATE TABLE Organization (org_id INTEGER PRIMARY KEY AUTOINCREMENT, org_name VARCHAR(255), url_prefix VARCHAR(255),  creator VARCHAR(255), ctime BIGINT);
CREATE UNIQUE INDEX url_prefix_indx on Organization (url_prefix);

CREATE TABLE OrgUser (org_id INTEGER, email TEXT, is_staff bool NOT NULL);
CREATE INDEX email_indx on OrgUser (email);
CREATE UNIQUE INDEX orgid_email_indx on OrgUser (org_id, email);
