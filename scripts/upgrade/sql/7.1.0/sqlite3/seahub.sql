DROP INDEX IF EXISTS "drafts_draft_origin_file_uuid_7c003c98_uniq" ON "drafts_draft";
ALTER TABLE "drafts_draft" ADD CONSTRAINT "drafts_draft_origin_file_uuid_7c003c98_uniq" UNIQUE ("origin_file_uuid");
CREATE INDEX  IF NOT EXISTS "drafts_draft_origin_repo_id_8978ca2c" ON "drafts_draft" ("origin_repo_id");


CREATE TABLE "abuse_reports_abusereport" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "reporter" text NULL, "repo_id" varchar(36) NOT NULL, "repo_name" varchar(255) NOT NULL, "file_path" text NULL, "abuse_type" varchar(255) NOT NULL, "description" text NULL, "handled" bool NOT NULL, "time" datetime NOT NULL);
CREATE INDEX "abuse_reports_abusereport_abuse_type_703d5335" ON "abuse_reports_abusereport" ("abuse_type");
CREATE INDEX "abuse_reports_abusereport_handled_94b8304c" ON "abuse_reports_abusereport" ("handled");


CREATE TABLE "file_participants_fileparticipant" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "username" varchar(255) NOT NULL, "uuid_id" char(32) NOT NULL REFERENCES "tags_fileuuidmap" ("uuid"));
CREATE UNIQUE INDEX "file_participants_fileparticipant_uuid_id_username_c747dd36_uniq" ON "file_participants_fileparticipant" ("uuid_id", "username");
CREATE INDEX "file_participants_fileparticipant_uuid_id_861b7339" ON "file_participants_fileparticipant" ("uuid_id");


CREATE TABLE "repo_share_invitation" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "repo_id" varchar(36) NOT NULL, "path" text NOT NULL, "permission" varchar(50) NOT NULL, "invitation_id" integer NOT NULL REFERENCES "invitations_invitation" ("id"));
CREATE INDEX "repo_share_invitation_repo_id_7bcf84fa" ON "repo_share_invitation" ("repo_id");
CREATE INDEX "repo_share_invitation_invitation_id_b71effd2" ON "repo_share_invitation" ("invitation_id");

CREATE TABLE "repo_api_tokens" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "repo_id" varchar(36) NOT NULL, "app_name" varchar(255) NOT NULL, "token" varchar(40) NOT NULL UNIQUE, "generated_at" datetime NOT NULL, "generated_by" varchar(255) NOT NULL, "last_access" datetime NOT NULL, "permission" varchar(15) NOT NULL);
CREATE INDEX "repo_api_tokens_repo_id_47a50fef" ON "repo_api_tokens" ("repo_id");
CREATE INDEX "repo_api_tokens_app_name_7c395c31" ON "repo_api_tokens" ("app_name");

ALTER TABLE "post_office_attachment" add column "headers" text DEFAULT NULL;

