ALTER TABLE notifications_notification ADD INDEX `notifications_notification_386bba5a` (`primary`);

ALTER TABLE institutions_institutionadmin ADD INDEX `institutions_institutionadmin_user_7560167c8413ff0e_uniq` (`user`);

CREATE TABLE IF NOT EXISTS `wiki_wiki` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(255) NOT NULL,
  `name` varchar(255) NOT NULL,
  `slug` varchar(255) NOT NULL,
  `repo_id` varchar(36) NOT NULL,
  `permission` varchar(50) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `slug` (`slug`),
  UNIQUE KEY `wiki_wiki_username_3c0f83e1b93de663_uniq` (`username`,`repo_id`),
  KEY `wiki_wiki_fde81f11` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
