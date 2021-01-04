CREATE TABLE IF NOT EXISTS "ocm_share" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "shared_secret" varchar(36) NOT NULL UNIQUE, "from_user" varchar(255) NOT NULL, "to_user" varchar(255) NOT NULL, "to_server_url" varchar(200) NOT NULL, "repo_id" varchar(36) NOT NULL, "repo_name" varchar(255) NOT NULL, "permission" varchar(50) NOT NULL, "path" text NOT NULL, "ctime" datetime(6) NOT NULL);
CREATE INDEX IF NOT EXISTS "ocm_share_from_user_7fbb7bb6" ON "ocm_share" ("from_user");
CREATE INDEX IF NOT EXISTS "ocm_share_to_user_4e255523" ON "ocm_share" ("to_user");
CREATE INDEX IF NOT EXISTS "ocm_share_to_server_url_43f0e89b" ON "ocm_share" ("to_server_url");
CREATE INDEX IF NOT EXISTS "ocm_share_repo_id_51937581" ON "ocm_share" ("repo_id");

CREATE TABLE IF NOT EXISTS "ocm_share_received" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "shared_secret" varchar(36) NOT NULL UNIQUE, "from_user" varchar(255) NOT NULL, "to_user" varchar(255) NOT NULL, "from_server_url" varchar(200) NOT NULL, "repo_id" varchar(36) NOT NULL, "repo_name" varchar(255) NOT NULL, "permission" varchar(50) NOT NULL, "path" text NOT NULL, "provider_id" varchar(40) NOT NULL, "ctime" datetime(6) NOT NULL);
CREATE INDEX IF NOT EXISTS "ocm_share_received_from_user_8137d8eb" ON "ocm_share_received" ("from_user");
CREATE INDEX IF NOT EXISTS "ocm_share_received_to_user_0921d09a" ON "ocm_share_received" ("to_user");
CREATE INDEX IF NOT EXISTS "ocm_share_received_from_server_url_10527b80" ON "ocm_share_received" ("from_server_url");
CREATE INDEX IF NOT EXISTS "ocm_share_received_repo_id_9e77a1b9" ON "ocm_share_received" ("repo_id");
CREATE INDEX IF NOT EXISTS "ocm_share_received_provider_id_60c873e0" ON "ocm_share_received" ("provider_id");

DROP TABLE IF EXISTS "VirusFile_old";
ALTER TABLE "VirusFile" RENAME TO "VirusFile_old";
CREATE TABLE IF NOT EXISTS "VirusFile" ("vid" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "repo_id" varchar(36) NOT NULL, "commit_id" varchar(40) NOT NULL, "file_path" text NOT NULL, "has_deleted" tinyint(1) NOT NULL, "has_ignored" TINYINT(1) NOT NULL DEFAULT 0);
INSERT INTO "VirusFile" ("vid", "repo_id", "commit_id", "file_path", "has_deleted") SELECT "vid", "repo_id", "commit_id", "file_path", "has_handle" FROM "VirusFile_old";
DROP TABLE "VirusFile_old";

CREATE INDEX IF NOT EXISTS "VirusFile_repo_id_yewnci4gd" ON "VirusFile" ("repo_id");
CREATE INDEX IF NOT EXISTS "VirusFile_has_deleted_834ndyts" ON "VirusFile" ("has_deleted");
CREATE INDEX IF NOT EXISTS "VirusFile_has_ignored_d84tvuwg" ON "VirusFile" ("has_ignored");
