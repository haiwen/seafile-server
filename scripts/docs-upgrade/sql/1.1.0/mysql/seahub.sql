ALTER TABLE `file_tags_filetags` DROP FOREIGN KEY `file_tags_filetags_parent_folder_uuid_i_df56f09b_fk_tags_file`;
ALTER TABLE `file_tags_filetags` DROP `parent_folder_uuid_id`;


DROP TABLE drafts_reviewcomment;
DROP TABLE drafts_reviewreviewer;
DROP TABLE drafts_draftreview;
DROP TABLE drafts_draft;

CREATE TABLE IF NOT EXISTS `drafts_draft` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `username` varchar(255) NOT NULL,
  `origin_repo_id` varchar(36) NOT NULL,
  `origin_file_version` varchar(100) NOT NULL,
  `draft_file_path` varchar(1024) NOT NULL,
  `origin_file_uuid` char(32) NOT NULL,
  `publish_file_version` varchar(100) DEFAULT NULL,
  `status` varchar(20) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `drafts_draft_origin_file_uuid_id_f150319e_fk_tags_file` (`origin_file_uuid`),
  KEY `drafts_draft_created_at_e9f4523f` (`created_at`),
  KEY `drafts_draft_updated_at_0a144b05` (`updated_at`),
  KEY `drafts_draft_username_73e6738b` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
    
CREATE TABLE IF NOT EXISTS `drafts_draftreviewer` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `reviewer` varchar(255) NOT NULL,
  `draft_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `drafts_draftreviewer_reviewer_e4c777ac` (`reviewer`),
  KEY `drafts_draftreviewer_draft_id_4ea59775_fk_drafts_draft_id` (`draft_id`),
  CONSTRAINT `drafts_draftreviewer_draft_id_4ea59775_fk_drafts_draft_id` FOREIGN KEY (`draft_id`) REFERENCES `drafts_draft` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `organizations_orgsettings` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `org_id` int(11) NOT NULL,
  `role` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `organizations_orgsettings_org_id_630f6843_uniq` (`org_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

DROP INDEX `profile_profile_contact_email_0975e4bf_uniq` ON `profile_profile`;
ALTER TABLE `profile_profile` ADD CONSTRAINT `profile_profile_contact_email_0975e4bf_uniq` UNIQUE (`contact_email`);

CREATE TABLE IF NOT EXISTS `social_auth_usersocialauth` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(255) NOT NULL,
  `provider` varchar(32) NOT NULL,
  `uid` varchar(150) NOT NULL,
  `extra_data` longtext NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `social_auth_usersocialauth_provider_uid_e6b5e668_uniq` (`provider`,`uid`),
  KEY `social_auth_usersocialauth_username_3f06b5cf` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
