/*
 * Roundcube Database, CalDav & iCal Calendar Schema
 *
 * @author Gene Hawkins <texxasrulez@yahoo.com>
 *
 * @licence GNU AGPL
 */

CREATE TABLE calendar_oauth_states (
  provider varchar(255) NOT NULL,
  client_config_id varchar(255) NOT NULL,
  user_id varchar(255) NOT NULL,
  scope varchar(255) NOT NULL,
  issue_time INTEGER NOT NULL,
  state varchar(255) NOT NULL,
  UNIQUE (provider, client_config_id, user_id, scope),
  PRIMARY KEY (state)
) /*!40000 ENGINE=INNODB */ /*!40101 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci */;

CREATE TABLE calendar_oauth_access_tokens (
  provider varchar(255) NOT NULL,
  client_config_id varchar(255) NOT NULL,
  user_id varchar(255) NOT NULL,
  scope varchar(255) NOT NULL,
  issue_time INTEGER NOT NULL,
  access_token varchar(255) NOT NULL,
  token_type varchar(255) NOT NULL,
  expires_in INTEGER DEFAULT NULL,
  UNIQUE (provider, client_config_id, user_id, scope)
) /*!40000 ENGINE=INNODB */ /*!40101 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci */;

CREATE TABLE calendar_oauth_refresh_tokens (
  provider varchar(255) NOT NULL,
  client_config_id varchar(255) NOT NULL,
  user_id varchar(255) NOT NULL,
  scope varchar(255) NOT NULL,
  issue_time INTEGER NOT NULL,
  refresh_token varchar(255) DEFAULT NULL,
  UNIQUE (provider, client_config_id, user_id, scope)
) /*!40000 ENGINE=INNODB */ /*!40101 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci */;

CREATE SEQUENCE caldav_calendars_seq;

CREATE TABLE caldav_calendars (
  calendar_id int CHECK (calendar_id > 0) NOT NULL DEFAULT NEXTVAL ('caldav_calendars_seq'),
  user_id int CHECK (user_id > 0) NOT NULL DEFAULT '0',
  name varchar(255) NOT NULL,
  color varchar(8) NOT NULL,
  showalarms smallint NOT NULL DEFAULT '1',
  caldav_url varchar(1000) DEFAULT NULL,
  caldav_tag varchar(32) DEFAULT 'COLLATE',
  caldav_user varchar(1000) DEFAULT NULL,
  caldav_pass varchar(1000) DEFAULT NULL,
  caldav_oauth_provider bytea DEFAULT NULL,
  readonly int NOT NULL DEFAULT '0',
  caldav_last_change timestamp(0) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  PRIMARY KEY(calendar_id)
 ,
  CONSTRAINT fk_caldav_calendars_user_id FOREIGN KEY (user_id)
  REFERENCES users(user_id) ON DELETE CASCADE ON UPDATE CASCADE
) /*!40000 ENGINE=INNODB */ /*!40101 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci */;

CREATE INDEX caldav_user_name_idx ON caldav_calendars (user_id, name);

CREATE SEQUENCE caldav_events_seq;

CREATE TABLE caldav_events (
  event_id int CHECK (event_id > 0) NOT NULL DEFAULT NEXTVAL ('caldav_events_seq'),
  calendar_id int CHECK (calendar_id > 0) NOT NULL DEFAULT '0',
  recurrence_id int CHECK (recurrence_id > 0) NOT NULL DEFAULT '0',
  uid varchar(255) NOT NULL DEFAULT '',
  instance varchar(16) NOT NULL DEFAULT '',
  isexception smallint NOT NULL DEFAULT '0',
  created timestamp(0) NOT NULL DEFAULT '1000-01-01 00:00:00',
  changed timestamp(0) NOT NULL DEFAULT '1000-01-01 00:00:00',
  sequence int CHECK (sequence > 0) NOT NULL DEFAULT '0',
  start timestamp(0) NOT NULL DEFAULT '1000-01-01 00:00:00',
  "end" timestamp(0) NOT NULL DEFAULT '1000-01-01 00:00:00',
  recurrence varchar(255) DEFAULT NULL,
  title bytea NOT NULL,
  description bytea NOT NULL,
  location bytea NOT NULL DEFAULT '',
  categories bytea NOT NULL DEFAULT '',
  url varchar(1000) NOT NULL DEFAULT '',
  all_day smallint NOT NULL DEFAULT '0',
  free_busy smallint NOT NULL DEFAULT '0',
  priority smallint NOT NULL DEFAULT '0',
  sensitivity smallint NOT NULL DEFAULT '0',
  status varchar(32) NOT NULL DEFAULT '',
  alarms text NULL DEFAULT NULL,
  attendees text DEFAULT NULL,
  notifyat timestamp(0) DEFAULT NULL,
  caldav_url varchar(1000) NOT NULL,
  caldav_tag varchar(32) DEFAULT 'COLLATE',
  caldav_last_change timestamp(0) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  PRIMARY KEY(event_id)
 ,
  CONSTRAINT fk_caldav_events_calendar_id FOREIGN KEY (calendar_id)
  REFERENCES caldav_calendars(calendar_id) ON DELETE CASCADE ON UPDATE CASCADE
) /*!40000 ENGINE=INNODB */ /*!40101 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci */;

CREATE INDEX caldav_uid_idx ON caldav_events (uid);
CREATE INDEX caldav_recurrence_idx ON caldav_events (recurrence_id);
CREATE INDEX caldav_calendar_notify_idx ON caldav_events (calendar_id,notifyat);

CREATE SEQUENCE caldav_attachments_seq;

CREATE TABLE caldav_attachments (
  attachment_id int CHECK (attachment_id > 0) NOT NULL DEFAULT NEXTVAL ('caldav_attachments_seq'),
  event_id int CHECK (event_id > 0) NOT NULL DEFAULT '0',
  filename varchar(255) NOT NULL DEFAULT '',
  mimetype varchar(255) NOT NULL DEFAULT '',
  size int NOT NULL DEFAULT '0',
  data bytea,
  
  PRIMARY KEY(attachment_id),
  CONSTRAINT fk_caldav_attachments_event_id FOREIGN KEY (event_id)
  REFERENCES caldav_events(event_id) ON DELETE CASCADE ON UPDATE CASCADE
) /*!40000 ENGINE=INNODB */ /*!40101 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci */;

CREATE SEQUENCE database_calendars_seq;

CREATE TABLE database_calendars (
  calendar_id int CHECK (calendar_id > 0) NOT NULL DEFAULT NEXTVAL ('database_calendars_seq'),
  user_id int CHECK (user_id > 0) NOT NULL DEFAULT '0',
  name varchar(255) NOT NULL,
  color varchar(8) NOT NULL,
  showalarms smallint NOT NULL DEFAULT '1',
  PRIMARY KEY(calendar_id)
 ,
  CONSTRAINT fk_calendars_user_id FOREIGN KEY (user_id)
    REFERENCES users(user_id) ON DELETE CASCADE ON UPDATE CASCADE
) /*!40000 ENGINE=INNODB */ /*!40101 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci */;

CREATE INDEX user_name_idx ON database_calendars (user_id, name);

CREATE SEQUENCE database_events_seq;

CREATE TABLE database_events (
  event_id int CHECK (event_id > 0) NOT NULL DEFAULT NEXTVAL ('database_events_seq'),
  calendar_id int CHECK (calendar_id > 0) NOT NULL DEFAULT '0',
  recurrence_id int CHECK (recurrence_id > 0) NOT NULL DEFAULT '0',
  uid varchar(255) NOT NULL DEFAULT '',
  instance varchar(16) NOT NULL DEFAULT '',
  isexception smallint NOT NULL DEFAULT '0',
  created timestamp(0) NOT NULL DEFAULT '1000-01-01 00:00:00',
  changed timestamp(0) NOT NULL DEFAULT '1000-01-01 00:00:00',
  sequence int CHECK (sequence > 0) NOT NULL DEFAULT '0',
  start timestamp(0) NOT NULL DEFAULT '1000-01-01 00:00:00',
  "end" timestamp(0) NOT NULL DEFAULT '1000-01-01 00:00:00',
  recurrence varchar(255) DEFAULT NULL,
  title varchar(255) NOT NULL,
  description text NOT NULL,
  location varchar(255) NOT NULL DEFAULT '',
  categories varchar(255) NOT NULL DEFAULT '',
  url varchar(255) NOT NULL DEFAULT '',
  all_day smallint NOT NULL DEFAULT '0',
  free_busy smallint NOT NULL DEFAULT '0',
  priority smallint NOT NULL DEFAULT '0',
  sensitivity smallint NOT NULL DEFAULT '0',
  status varchar(32) NOT NULL DEFAULT '',
  alarms text DEFAULT NULL,
  attendees text DEFAULT NULL,
  notifyat timestamp(0) DEFAULT NULL,
  PRIMARY KEY(event_id)
 ,
  CONSTRAINT fk_events_calendar_id FOREIGN KEY (calendar_id)
    REFERENCES database_calendars(calendar_id) ON DELETE CASCADE ON UPDATE CASCADE
) /*!40000 ENGINE=INNODB */ /*!40101 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci */;

CREATE INDEX uid_idx ON database_events (uid);
CREATE INDEX recurrence_idx ON database_events (recurrence_id);
CREATE INDEX calendar_notify_idx ON database_events (calendar_id,notifyat);

CREATE SEQUENCE database_attachments_seq;

CREATE TABLE database_attachments (
  attachment_id int CHECK (attachment_id > 0) NOT NULL DEFAULT NEXTVAL ('database_attachments_seq'),
  event_id int CHECK (event_id > 0) NOT NULL DEFAULT '0',
  filename varchar(255) NOT NULL DEFAULT '',
  mimetype varchar(255) NOT NULL DEFAULT '',
  size int NOT NULL DEFAULT '0',
  data text NOT NULL,
  PRIMARY KEY(attachment_id),
  CONSTRAINT fk_attachments_event_id FOREIGN KEY (event_id)
    REFERENCES database_events(event_id) ON DELETE CASCADE ON UPDATE CASCADE
) /*!40000 ENGINE=INNODB */ /*!40101 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci */;

CREATE TABLE itipinvitations (
  token VARCHAR(64) NOT NULL,
  event_uid VARCHAR(255) NOT NULL,
  user_id int CHECK (user_id > 0) NOT NULL DEFAULT '0',
  event TEXT NOT NULL,
  expires TIMESTAMP(0) DEFAULT NULL,
  cancelled SMALLINT CHECK (cancelled > 0) NOT NULL DEFAULT '0',
  PRIMARY KEY(token)
 ,
  CONSTRAINT fk_itipinvitations_user_id FOREIGN KEY (user_id)
    REFERENCES users(user_id) ON DELETE CASCADE ON UPDATE CASCADE
) /*!40000 ENGINE=INNODB */ /*!40101 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci */;

CREATE INDEX iti_uid_idx ON itipinvitations (user_id,event_uid);

CREATE SEQUENCE ical_calendars_seq;

CREATE TABLE ical_calendars (
  calendar_id int CHECK (calendar_id > 0) NOT NULL DEFAULT NEXTVAL ('ical_calendars_seq'),
  user_id int CHECK (user_id > 0) NOT NULL DEFAULT '0',
  name varchar(255) NOT NULL,
  color varchar(8) NOT NULL,
  showalarms smallint NOT NULL DEFAULT '1',

  ical_url varchar(1000) NOT NULL,
  ical_user varchar(255) DEFAULT NULL,
  ical_pass varchar(1024) DEFAULT NULL,
  ical_last_change timestamp(0) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  PRIMARY KEY(calendar_id)
 ,
  CONSTRAINT fk_ical_calendars_user_id FOREIGN KEY (user_id)
  REFERENCES users(user_id) ON DELETE CASCADE ON UPDATE CASCADE
) /*!40000 ENGINE=INNODB */ /*!40101 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci */;

CREATE INDEX ical_user_name_idx ON ical_calendars (user_id, name);

CREATE SEQUENCE ical_events_seq;

CREATE TABLE ical_events (
  event_id int CHECK (event_id > 0) NOT NULL DEFAULT NEXTVAL ('ical_events_seq'),
  calendar_id int CHECK (calendar_id > 0) NOT NULL DEFAULT '0',
  recurrence_id int CHECK (recurrence_id > 0) NOT NULL DEFAULT '0',
  uid varchar(255) NOT NULL DEFAULT '',
  instance varchar(16) NOT NULL DEFAULT '',
  isexception smallint NOT NULL DEFAULT '0',
  created timestamp(0) NOT NULL DEFAULT '1000-01-01 00:00:00',
  changed timestamp(0) NOT NULL DEFAULT '1000-01-01 00:00:00',
  sequence int CHECK (sequence > 0) NOT NULL DEFAULT '0',
  start timestamp(0) NOT NULL DEFAULT '1000-01-01 00:00:00',
  "end" timestamp(0) NOT NULL DEFAULT '1000-01-01 00:00:00',
  recurrence varchar(255) DEFAULT NULL,
  title bytea NOT NULL,
  description bytea NOT NULL,
  location bytea NOT NULL DEFAULT '',
  categories bytea NOT NULL DEFAULT '',
  url varchar(1000) NOT NULL DEFAULT '',
  all_day smallint NOT NULL DEFAULT '0',
  free_busy smallint NOT NULL DEFAULT '0',
  priority smallint NOT NULL DEFAULT '0',
  sensitivity smallint NOT NULL DEFAULT '0',
  status varchar(32) NOT NULL DEFAULT '',
  alarms text NULL DEFAULT NULL,
  attendees text DEFAULT NULL,
  notifyat timestamp(0) DEFAULT NULL,

  ical_url varchar(1000) NOT NULL,
  ical_last_change timestamp(0) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  PRIMARY KEY(event_id)
 ,
  CONSTRAINT fk_ical_events_calendar_id FOREIGN KEY (calendar_id)
  REFERENCES ical_calendars(calendar_id) ON DELETE CASCADE ON UPDATE CASCADE
) /*!40000 ENGINE=INNODB */ /*!40101 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci */;

CREATE INDEX ical_uid_idx ON ical_events (uid);
CREATE INDEX ical_recurrence_idx ON ical_events (recurrence_id);
CREATE INDEX ical_calendar_notify_idx ON ical_events (calendar_id,notifyat);

CREATE SEQUENCE ical_attachments_seq;

CREATE TABLE ical_attachments (
  attachment_id int CHECK (attachment_id > 0) NOT NULL DEFAULT NEXTVAL ('ical_attachments_seq'),
  event_id int CHECK (event_id > 0) NOT NULL DEFAULT '0',
  filename varchar(255) NOT NULL DEFAULT '',
  mimetype varchar(255) NOT NULL DEFAULT '',
  size int NOT NULL DEFAULT '0',
  da NOT NULL,
  PRIMARY KEY(attachment_id),
  CONSTRAINT fk_ical_attachments_event_id FOREIGN KEY (event_id)
  REFERENCES ical_events(event_id) ON DELETE CASCADE ON UPDATE CASCADE
) /*!40000 ENGINE=INNODB */ /*!40101 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci */;

INSERT INTO system (name, value) VALUES ('calendar-version', '2020081200') ON CONFLICT (name) DO UPDATE;
