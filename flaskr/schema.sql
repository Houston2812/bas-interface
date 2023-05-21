DROP TABLE IF EXISTS user;
DROP TABLE IF EXISTS post;

CREATE TABLE user (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL
);

CREATE TABLE post (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  author_id INTEGER NOT NULL,
  created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  FOREIGN KEY (author_id) REFERENCES user (id)
);


CREATE TABLE scanner (
  id INTEGER PRIMARY KEY AUTOINCREMENT, 
  auth_key TEXT NOT NULL,
  org TEXT NOT NULL,
  user_id INTEGER NOT NULL,
  scanner_status INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY (user_id) REFERENCES user (id)
);

CREATE TABLE scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  auth_key TEXT NOT NULL,
  finished INTEGER NOT NULL DEFAULT 0,
  scan_category TEXT NOT NULL,
  scan_type TEXT NOT NULL,
  scan_speed TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES user (id),
  FOREIGN KEY (auth_key) REFERENCES scanner (auth_key)
);

CREATE TABLE report (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  scan_id INTEGER NOT NULL,
  payload TEXT NOT NULL,
  status_ TEXT NOT NULL,
  time TEXT NOT NULL, 
  FOREIGN KEY (user_id) REFERENCES user (id),
  FOREIGN KEY (scan_id) REFERENCES scans (id)
)