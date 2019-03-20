ALTER TABLE `base_filecomment` ADD `detail` LONGTEXT DEFAULT NULL;
ALTER TABLE `base_filecomment` ADD `resolved` TINYINT(1) NOT NULL DEFAULT 0;
ALTER TABLE `base_filecomment` ADD INDEX `resolved` (`resolved`);
