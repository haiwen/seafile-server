CREATE TABLE Binding (email TEXT, peer_id TEXT);
CREATE UNIQUE INDEX peer_index on Binding (peer_id);

CREATE TABLE EmailUser (id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,email TEXT, passwd TEXT, is_staff bool NOT NULL, is_active bool NOT NULL, ctime INTEGER, reference_id TEXT);
CREATE UNIQUE INDEX email_index on EmailUser (email);
CREATE UNIQUE INDEX reference_id_index on EmailUser (reference_id);

CREATE TABLE LDAPConfig (cfg_group VARCHAR(255) NOT NULL,cfg_key VARCHAR(255) NOT NULL, value VARCHAR(255), property INTEGER);

CREATE TABLE LDAPUsers (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL, password TEXT NOT NULL, is_staff BOOL NOT NULL, is_active BOOL NOT NULL, extra_attrs TEXT, reference_id TEXT);
CREATE UNIQUE INDEX ldapusers_email_index on LDAPUsers(email);
CREATE UNIQUE INDEX ldapusers_reference_id_index on LDAPUsers(reference_id);

CREATE TABLE UserRole (email TEXT, role TEXT);
CREATE INDEX userrole_email_index on UserRole (email);
CREATE UNIQUE INDEX userrole_userrole_index on UserRole (email, role);
