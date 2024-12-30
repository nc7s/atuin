-- This migration is based on a pg_dump after running all atuin-server-postgres
-- migrations, currently up to 20240702094825_idx_cache_index.sql.

CREATE TABLE IF NOT EXISTS history (
    id integer PRIMARY KEY AUTOINCREMENT NOT NULL,
    client_id text NOT NULL,
    user_id integer NOT NULL,
    hostname text NOT NULL,
    timestamp integer NOT NULL, -- Unix timestamp
    data text NOT NULL,
    created_at integer DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Unix timestamp
    deleted_at integer -- Unix timestamp
);

CREATE TABLE IF NOT EXISTS user_history_count (
	user_id integer PRIMARY KEY NOT NULL,
	count integer
);

CREATE TRIGGER IF NOT EXISTS user_history_count_increment_on_insert AFTER INSERT ON history FOR EACH ROW
BEGIN
	INSERT INTO user_history_count (user_id, count) VALUES (NEW.user_id, 1)
		ON CONFLICT DO UPDATE SET count = count + 1 WHERE user_id = NEW.user_id;
END;

CREATE TABLE IF NOT EXISTS records (
    id text NOT NULL, -- uuid, but sqlite does not have uuid types
    client_id text NOT NULL, -- uuid
    host text NOT NULL, -- uuid
    parent text, -- uuid
    timestamp integer NOT NULL, -- Unix timestamp
    version text NOT NULL,
    tag text NOT NULL,
    data text NOT NULL,
    cek text NOT NULL,
    user_id integer NOT NULL,
    created_at integer DEFAULT CURRENT_TIMESTAMP NOT NULL -- Unix timestamp
);

CREATE TABLE IF NOT EXISTS sessions (
    id integer PRIMARY KEY AUTOINCREMENT NOT NULL,
    user_id integer NOT NULL,
    token text UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS store (
    id text NOT NULL, -- uuid
    client_id text NOT NULL, -- uuid
    host text NOT NULL, -- uuid
    idx integer NOT NULL,
    timestamp integer NOT NULL, -- Unix timestamp
    version text NOT NULL,
    tag text NOT NULL,
    data text NOT NULL,
    cek text NOT NULL,
    user_id integer NOT NULL,
    created_at integer DEFAULT CURRENT_TIMESTAMP NOT NULL -- Unix timestamp
);

CREATE TABLE IF NOT EXISTS store_idx_cache (
    id integer PRIMARY KEY AUTOINCREMENT NOT NULL,
    user_id integer NOT NULL,
    host text NOT NULL, -- uuid
    tag text NOT NULL,
    idx integer NOT NULL
);

CREATE TABLE IF NOT EXISTS total_history_count_user (
    id integer PRIMARY KEY AUTOINCREMENT NOT NULL,
    user_id integer NOT NULL,
    total integer
);

CREATE TABLE IF NOT EXISTS user_verification_token (
    id integer PRIMARY KEY AUTOINCREMENT NOT NULL,
    user_id integer UNIQUE,
    token text,
    valid_until integer, -- Unix timestamp
	FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS users (
    id integer PRIMARY KEY AUTOINCREMENT NOT NULL,
    username text UNIQUE COLLATE NOCASE NOT NULL,
    email text UNIQUE COLLATE NOCASE NOT NULL,
    password text NOT NULL,
    created_at integer DEFAULT CURRENT_TIMESTAMP NOT NULL, -- Unix timestamp
    verified_at integer -- Unix timestamp
);

CREATE INDEX IF NOT EXISTS history_deleted_index ON history (client_id, user_id, deleted_at);

CREATE UNIQUE INDEX IF NOT EXISTS record_uniq ON store (user_id, host, tag, idx);

CREATE UNIQUE INDEX IF NOT EXISTS store_idx_cache_uniq ON store_idx_cache (user_id, host, tag);

