CREATE TABLE IF NOT EXISTS sftp_users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  display_name TEXT NOT NULL,
  group_name TEXT NOT NULL,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT,        -- bcrypt hash; nullable if using key auth only
  public_key TEXT,           -- optional: authorized public key (openssh format)
  root_path TEXT NOT NULL,   -- absolute path on host
  perms INTEGER NOT NULL,    -- bitmask: 1=Read,2=List,4=Write,8=Delete
  disabled BOOLEAN DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);