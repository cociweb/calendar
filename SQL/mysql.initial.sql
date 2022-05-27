/*
 * Roundcube Database, CalDav & iCal Calendar Schema
 *
 * @author Gene Hawkins <texxasrulez@yahoo.com>
 *
 * @licence GNU AGPL
 */

CREATE TABLE IF NOT EXISTS `calendar_oauth_states` (
  `provider` varchar(255) NOT NULL,
  `client_config_id` varchar(255) NOT NULL,
  `user_id` varchar(255) NOT NULL,
  `scope` varchar(255) NOT NULL,
  `issue_time` INTEGER NOT NULL,
  `state` varchar(255) NOT NULL,
  UNIQUE (`provider`(50), `client_config_id`(50), `user_id`(50), `scope`(50)),
  PRIMARY KEY (`state`)
) /*!40000 ENGINE=INNODB */ /*!40101 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci */;

CREATE TABLE IF NOT EXISTS `calendar_oauth_access_tokens` (
  `provider` varchar(255) NOT NULL,
  `client_config_id` varchar(255) NOT NULL,
  `user_id` varchar(255) NOT NULL,
  `scope` varchar(255) NOT NULL,
  `issue_time` INTEGER NOT NULL,
  `access_token` varchar(255) NOT NULL,
  `token_type` varchar(255) NOT NULL,
  `expires_in` INTEGER DEFAULT NULL,
  UNIQUE (`provider`(50), `client_config_id`(50), `user_id`(50), `scope`(50))
) /*!40000 ENGINE=INNODB */ /*!40101 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci */;

CREATE TABLE IF NOT EXISTS `calendar_oauth_refresh_tokens` (
  `provider` varchar(255) NOT NULL,
  `client_config_id` varchar(255) NOT NULL,
  `user_id` varchar(255) NOT NULL,
  `scope` varchar(255) NOT NULL,
  `issue_time` INTEGER NOT NULL,
  `refresh_token` varchar(255) DEFAULT NULL,
  UNIQUE (`provider`(50), `client_config_id`(50), `user_id`(50), `scope`(50))
) /*!40000 ENGINE=INNODB */ /*!40101 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci */;

CREATE TABLE IF NOT EXISTS `caldav_calendars` (
  `calendar_id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` int(10) UNSIGNED NOT NULL DEFAULT '0',
  `name` varchar(255) NOT NULL,
  `color` varchar(8) NOT NULL,
  `showalarms` tinyint(1) NOT NULL DEFAULT '1',
  `caldav_url` varchar(1000) DEFAULT NULL,
  `caldav_tag` varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL DEFAULT 'COLLATE',
  `caldav_user` varchar(1000) DEFAULT NULL,
  `caldav_pass` varchar(1000) DEFAULT NULL,
  `caldav_oauth_provider` varbinary(200) DEFAULT NULL,
  `readonly` int NOT NULL DEFAULT '0',
  `caldav_last_change` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

  PRIMARY KEY(`calendar_id`),
  INDEX `caldav_user_name_idx` (`user_id`, `name`),
  CONSTRAINT `fk_caldav_calendars_user_id` FOREIGN KEY (`user_id`)
  REFERENCES `users`(`user_id`) ON DELETE CASCADE ON UPDATE CASCADE
) /*!40000 ENGINE=INNODB */ /*!40101 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci */;

CREATE TABLE IF NOT EXISTS `caldav_events` (
  `event_id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `calendar_id` int(11) UNSIGNED NOT NULL DEFAULT '0',
  `recurrence_id` int(11) UNSIGNED NOT NULL DEFAULT '0',
  `uid` varchar(255) NOT NULL DEFAULT '',
  `instance` varchar(16) NOT NULL DEFAULT '',
  `isexception` tinyint(1) NOT NULL DEFAULT '0',
  `created` datetime NOT NULL DEFAULT '1000-01-01 00:00:00',
  `changed` datetime NOT NULL DEFAULT '1000-01-01 00:00:00',
  `sequence` int(1) UNSIGNED NOT NULL DEFAULT '0',
  `start` datetime NOT NULL DEFAULT '1000-01-01 00:00:00',
  `end` datetime NOT NULL DEFAULT '1000-01-01 00:00:00',
  `recurrence` varchar(255) DEFAULT NULL,
  `title` varbinary(128) NOT NULL,
  `description` varbinary(2048) NOT NULL,
  `location` varbinary(128) NOT NULL DEFAULT '',
  `categories` varbinary(128) NOT NULL DEFAULT '',
  `url` varchar(1000) NOT NULL DEFAULT '',
  `all_day` tinyint(1) NOT NULL DEFAULT '0',
  `free_busy` tinyint(1) NOT NULL DEFAULT '0',
  `priority` tinyint(1) NOT NULL DEFAULT '0',
  `sensitivity` tinyint(1) NOT NULL DEFAULT '0',
  `status` varchar(32) NOT NULL DEFAULT '',
  `alarms` text NULL DEFAULT NULL,
  `attendees` text DEFAULT NULL,
  `notifyat` datetime DEFAULT NULL,
  `caldav_url` varchar(1000) NOT NULL,
  `caldav_tag` varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL DEFAULT 'COLLATE',
  `caldav_last_change` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

  PRIMARY KEY(`event_id`),
  INDEX `caldav_uid_idx` (`uid`),
  INDEX `caldav_recurrence_idx` (`recurrence_id`),
  INDEX `caldav_calendar_notify_idx` (`calendar_id`,`notifyat`),
  CONSTRAINT `fk_caldav_events_calendar_id` FOREIGN KEY (`calendar_id`)
  REFERENCES `caldav_calendars`(`calendar_id`) ON DELETE CASCADE ON UPDATE CASCADE
) /*!40000 ENGINE=INNODB */ /*!40101 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci */;

CREATE TABLE IF NOT EXISTS `caldav_attachments` (
  `attachment_id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `event_id` int(11) UNSIGNED NOT NULL DEFAULT '0',
  `filename` varchar(255) NOT NULL DEFAULT '',
  `mimetype` varchar(255) NOT NULL DEFAULT '',
  `size` int(11) NOT NULL DEFAULT '0',
  `data` MEDIUMBLOB,
  
  PRIMARY KEY(`attachment_id`),
  CONSTRAINT `fk_caldav_attachments_event_id` FOREIGN KEY (`event_id`)
  REFERENCES `caldav_events`(`event_id`) ON DELETE CASCADE ON UPDATE CASCADE
) /*!40000 ENGINE=INNODB */ /*!40101 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci */;

CREATE TABLE IF NOT EXISTS `database_calendars` (
  `calendar_id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` int(10) UNSIGNED NOT NULL DEFAULT '0',
  `name` varchar(255) NOT NULL,
  `color` varchar(8) NOT NULL,
  `showalarms` tinyint(1) NOT NULL DEFAULT '1',
  PRIMARY KEY(`calendar_id`),
  INDEX `user_name_idx` (`user_id`, `name`),
  CONSTRAINT `fk_calendars_user_id` FOREIGN KEY (`user_id`)
    REFERENCES `users`(`user_id`) ON DELETE CASCADE ON UPDATE CASCADE
) /*!40000 ENGINE=INNODB */ /*!40101 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci */;

CREATE TABLE IF NOT EXISTS `database_events` (
  `event_id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `calendar_id` int(11) UNSIGNED NOT NULL DEFAULT '0',
  `recurrence_id` int(11) UNSIGNED NOT NULL DEFAULT '0',
  `uid` varchar(255) NOT NULL DEFAULT '',
  `instance` varchar(16) NOT NULL DEFAULT '',
  `isexception` tinyint(1) NOT NULL DEFAULT '0',
  `created` datetime NOT NULL DEFAULT '1000-01-01 00:00:00',
  `changed` datetime NOT NULL DEFAULT '1000-01-01 00:00:00',
  `sequence` int(1) UNSIGNED NOT NULL DEFAULT '0',
  `start` datetime NOT NULL DEFAULT '1000-01-01 00:00:00',
  `end` datetime NOT NULL DEFAULT '1000-01-01 00:00:00',
  `recurrence` varchar(255) DEFAULT NULL,
  `title` varchar(255) NOT NULL,
  `description` text NOT NULL,
  `location` varchar(255) NOT NULL DEFAULT '',
  `categories` varchar(255) NOT NULL DEFAULT '',
  `url` varchar(255) NOT NULL DEFAULT '',
  `all_day` tinyint(1) NOT NULL DEFAULT '0',
  `free_busy` tinyint(1) NOT NULL DEFAULT '0',
  `priority` tinyint(1) NOT NULL DEFAULT '0',
  `sensitivity` tinyint(1) NOT NULL DEFAULT '0',
  `status` varchar(32) NOT NULL DEFAULT '',
  `alarms` text DEFAULT NULL,
  `attendees` text DEFAULT NULL,
  `notifyat` datetime DEFAULT NULL,
  PRIMARY KEY(`event_id`),
  INDEX `uid_idx` (`uid`),
  INDEX `recurrence_idx` (`recurrence_id`),
  INDEX `calendar_notify_idx` (`calendar_id`,`notifyat`),
  CONSTRAINT `fk_events_calendar_id` FOREIGN KEY (`calendar_id`)
    REFERENCES `database_calendars`(`calendar_id`) ON DELETE CASCADE ON UPDATE CASCADE
) /*!40000 ENGINE=INNODB */ /*!40101 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci */;

CREATE TABLE IF NOT EXISTS `database_attachments` (
  `attachment_id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `event_id` int(11) UNSIGNED NOT NULL DEFAULT '0',
  `filename` varchar(255) NOT NULL DEFAULT '',
  `mimetype` varchar(255) NOT NULL DEFAULT '',
  `size` int(11) NOT NULL DEFAULT '0',
  `data` longtext NOT NULL,
  PRIMARY KEY(`attachment_id`),
  CONSTRAINT `fk_attachments_event_id` FOREIGN KEY (`event_id`)
    REFERENCES `database_events`(`event_id`) ON DELETE CASCADE ON UPDATE CASCADE
) /*!40000 ENGINE=INNODB */ /*!40101 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci */;

CREATE TABLE IF NOT EXISTS `itipinvitations` (
  `token` VARCHAR(64) NOT NULL,
  `event_uid` VARCHAR(255) NOT NULL,
  `user_id` int(10) UNSIGNED NOT NULL DEFAULT '0',
  `event` TEXT NOT NULL,
  `expires` DATETIME DEFAULT NULL,
  `cancelled` TINYINT(3) UNSIGNED NOT NULL DEFAULT '0',
  PRIMARY KEY(`token`),
  INDEX `uid_idx` (`user_id`,`event_uid`),
  CONSTRAINT `fk_itipinvitations_user_id` FOREIGN KEY (`user_id`)
    REFERENCES `users`(`user_id`) ON DELETE CASCADE ON UPDATE CASCADE
) /*!40000 ENGINE=INNODB */ /*!40101 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci */;

CREATE TABLE IF NOT EXISTS `ical_calendars` (
  `calendar_id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` int(10) UNSIGNED NOT NULL DEFAULT '0',
  `name` varchar(255) NOT NULL,
  `color` varchar(8) NOT NULL,
  `showalarms` tinyint(1) NOT NULL DEFAULT '1',

  `ical_url` varchar(1000) NOT NULL,
  `ical_user` varchar(255) DEFAULT NULL,
  `ical_pass` varchar(1024) DEFAULT NULL,
  `ical_last_change` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

  PRIMARY KEY(`calendar_id`),
  INDEX `ical_user_name_idx` (`user_id`, `name`),
  CONSTRAINT `fk_ical_calendars_user_id` FOREIGN KEY (`user_id`)
  REFERENCES `users`(`user_id`) ON DELETE CASCADE ON UPDATE CASCADE
) /*!40000 ENGINE=INNODB */ /*!40101 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci */;

CREATE TABLE IF NOT EXISTS `ical_events` (
  `event_id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `calendar_id` int(11) UNSIGNED NOT NULL DEFAULT '0',
  `recurrence_id` int(11) UNSIGNED NOT NULL DEFAULT '0',
  `uid` varchar(255) NOT NULL DEFAULT '',
  `instance` varchar(16) NOT NULL DEFAULT '',
  `isexception` tinyint(1) NOT NULL DEFAULT '0',
  `created` datetime NOT NULL DEFAULT '1000-01-01 00:00:00',
  `changed` datetime NOT NULL DEFAULT '1000-01-01 00:00:00',
  `sequence` int(1) UNSIGNED NOT NULL DEFAULT '0',
  `start` datetime NOT NULL DEFAULT '1000-01-01 00:00:00',
  `end` datetime NOT NULL DEFAULT '1000-01-01 00:00:00',
  `recurrence` varchar(255) DEFAULT NULL,
  `title` varbinary(128) NOT NULL,
  `description` varbinary(2048) NOT NULL,
  `location` varbinary(128) NOT NULL DEFAULT '',
  `categories` varbinary(128) NOT NULL DEFAULT '',
  `url` varchar(1000) NOT NULL DEFAULT '',
  `all_day` tinyint(1) NOT NULL DEFAULT '0',
  `free_busy` tinyint(1) NOT NULL DEFAULT '0',
  `priority` tinyint(1) NOT NULL DEFAULT '0',
  `sensitivity` tinyint(1) NOT NULL DEFAULT '0',
  `status` varchar(32) NOT NULL DEFAULT '',
  `alarms` text NULL DEFAULT NULL,
  `attendees` text DEFAULT NULL,
  `notifyat` datetime DEFAULT NULL,

  `ical_url` varchar(1000) NOT NULL,
  `ical_last_change` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

  PRIMARY KEY(`event_id`),
  INDEX `ical_uid_idx` (`uid`),
  INDEX `ical_recurrence_idx` (`recurrence_id`),
  INDEX `ical_calendar_notify_idx` (`calendar_id`,`notifyat`),
  CONSTRAINT `fk_ical_events_calendar_id` FOREIGN KEY (`calendar_id`)
  REFERENCES `ical_calendars`(`calendar_id`) ON DELETE CASCADE ON UPDATE CASCADE
) /*!40000 ENGINE=INNODB */ /*!40101 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci */;

CREATE TABLE IF NOT EXISTS `ical_attachments` (
  `attachment_id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `event_id` int(11) UNSIGNED NOT NULL DEFAULT '0',
  `filename` varchar(255) NOT NULL DEFAULT '',
  `mimetype` varchar(255) NOT NULL DEFAULT '',
  `size` int(11) NOT NULL DEFAULT '0',
  `data` longtext NOT NULL,
  PRIMARY KEY(`attachment_id`),
  CONSTRAINT `fk_ical_attachments_event_id` FOREIGN KEY (`event_id`)
  REFERENCES `ical_events`(`event_id`) ON DELETE CASCADE ON UPDATE CASCADE
) /*!40000 ENGINE=INNODB */ /*!40101 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci */;

REPLACE INTO `system` (`name`, `value`) VALUES ('calendar-version', '2020081200');
