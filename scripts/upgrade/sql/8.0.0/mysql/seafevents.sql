ALTER TABLE `VirusFile` ADD COLUMN IF NOT EXISTS `has_ignored` TINYINT(1) NOT NULL DEFAULT 0;
ALTER TABLE `VirusFile` CHANGE `has_handle` `has_deleted` TINYINT(1);
ALTER TABLE `VirusFile` ADD INDEX IF NOT EXISTS `has_deleted` (`has_deleted`);
ALTER TABLE `VirusFile` ADD INDEX IF NOT EXISTS `has_ignored` (`has_ignored`);
