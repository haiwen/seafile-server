CREATE TABLE `Group` (`group_id` INTEGER PRIMARY KEY AUTOINCREMENT, `group_name` VARCHAR(255), `creator_name` VARCHAR(255), `timestamp` BIGINT, `type` VARCHAR(32), `parent_group_id` INTEGER);

CREATE TABLE `GroupUser` (`group_id` INTEGER, `user_name` VARCHAR(255), `is_staff` tinyint);
CREATE UNIQUE INDEX groupid_username_indx on `GroupUser` (`group_id`, `user_name`);
CREATE INDEX username_indx on `GroupUser` (`user_name`);

CREATE TABLE GroupDNPair (group_id INTEGER, dn VARCHAR(255));

CREATE TABLE GroupStructure (group_id INTEGER PRIMARY KEY, path VARCHAR(1024));
