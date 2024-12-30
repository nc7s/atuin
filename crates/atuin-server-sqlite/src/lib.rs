use std::collections::HashMap;
use std::ops::Range;

use async_trait::async_trait;
use atuin_common::record::{EncryptedData, HostId, Record, RecordIdx, RecordStatus};
use atuin_common::utils::crypto_random_string;
use atuin_server_database::{
    models::{History, NewHistory, NewSession, NewUser, Session, User},
    Database, DbError, DbResult,
};
use futures_util::TryStreamExt;
use metrics::counter;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePoolOptions;
use time::{OffsetDateTime, PrimitiveDateTime, UtcOffset};
use tracing::{instrument, trace};

#[derive(Clone)]
pub struct Sqlite {
    pool: sqlx::Pool<sqlx::sqlite::Sqlite>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct SqliteSettings {
    pub db_uri: String,
}

impl std::fmt::Debug for SqliteSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redacted_uri = url::Url::parse(&self.db_uri)
            .map(|mut url| {
                let _ = url.set_password(Some("****"));
                url.to_string()
            })
            .unwrap_or_else(|_| self.db_uri.clone());
        f.debug_struct("SqliteSettings")
            .field("db_uri", &redacted_uri)
            .finish()
    }
}

fn fix_error(e: sqlx::Error) -> DbError {
    match e {
        sqlx::Error::RowNotFound => DbError::NotFound,
        e => DbError::Other(e.into()),
    }
}

#[async_trait]
impl Database for Sqlite {
    type Settings = SqliteSettings;

    async fn new(uri: &str) -> DbResult<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(100)
            .connect(uri)
            .await
            .map_err(fix_error)?;

        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(|e| DbError::Other(e.into()))?;

        Ok(Self { pool })
    }

    #[instrument(skip_all)]
    async fn get_session(&self, token: &str) -> DbResult<Session> {
        sqlx::query_as!(
            Session,
            "select id, user_id, token from sessions where token = $1",
            token
        )
        .fetch_one(&self.pool)
        .await
        .map_err(fix_error)
    }

    #[instrument(skip_all)]
    async fn get_user(&self, username: &str) -> DbResult<User> {
        sqlx::query_as!(
			User,
            r#"select id, username, email, password, verified_at "verified: OffsetDateTime" from users where username = $1"#,
			username
        )
        .fetch_one(&self.pool)
        .await
        .map_err(fix_error)
    }

    #[instrument(skip_all)]
    async fn user_verified(&self, id: i64) -> DbResult<bool> {
        sqlx::query!("select verified_at from users where id = $1", id)
            .fetch_one(&self.pool)
            .await
            .map_err(fix_error)
            .map(|r| r.verified_at.is_some())
    }

    #[instrument(skip_all)]
    async fn verify_user(&self, id: i64) -> DbResult<()> {
        sqlx::query(
            "update users set verified_at = (current_timestamp at time zone 'utc') where id=$1",
        )
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(fix_error)?;

        Ok(())
    }

    /// Return a valid verification token for the user
    /// If the user does not have any token, create one, insert it, and return
    /// If the user has a token, but it's invalid, delete it, create a new one, return
    /// If the user already has a valid token, return it
    #[instrument(skip_all)]
    async fn user_verification_token(&self, id: i64) -> DbResult<String> {
        const TOKEN_VALID_MINUTES: i64 = 15;

        // First we check if there is a verification token
        let token = sqlx::query!(
            "select token, valid_until from user_verification_token where user_id = $1",
            id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(fix_error)?
        .map(|r| {
            (
                r.token,
                r.valid_until.map(OffsetDateTime::from_unix_timestamp),
            )
        });

        let token = if let Some((Some(token), Some(Ok(valid_until)))) = token {
            trace!("Token for user {id} valid until {valid_until}");

            // We have a token, AND it's still valid
            if valid_until > time::OffsetDateTime::now_utc() {
                token
            } else {
                // token has expired. generate a new one, return it
                let token = crypto_random_string::<24>();
                let valid =
                    OffsetDateTime::now_utc() + time::Duration::minutes(TOKEN_VALID_MINUTES);

                sqlx::query!("update user_verification_token set token = $2, valid_until = $3 where user_id= $1", id, token, valid)
                    .execute(&self.pool)
                    .await
                    .map_err(fix_error)?;

                token
            }
        } else {
            // No token in the database! Generate one, insert it
            let token = crypto_random_string::<24>();

            sqlx::query("insert into user_verification_token (user_id, token, valid_until) values ($1, $2, $3)")
                .bind(id)
                .bind(&token)
                .bind(time::OffsetDateTime::now_utc() + time::Duration::minutes(TOKEN_VALID_MINUTES))
                .execute(&self.pool)
                .await
                .map_err(fix_error)?;

            token
        };

        Ok(token)
    }

    #[instrument(skip_all)]
    async fn get_session_user(&self, token: &str) -> DbResult<User> {
        sqlx::query_as!(
			User,
            r#"select users.id, users.username, users.email, users.password, users.verified_at "verified: OffsetDateTime" from users 
            inner join sessions on users.id = sessions.user_id and sessions.token = $1"#,
			token
        )
        .fetch_one(&self.pool)
        .await
        .map_err(fix_error)
    }

    #[instrument(skip_all)]
    async fn count_history(&self, user: &User) -> DbResult<i64> {
        // The cache is new, and the user might not yet have a cache value.
        // They will have one as soon as they post up some new history, but handle that
        // edge case.

        sqlx::query!(
            "select count(1) as total from history
            where user_id = $1",
            user.id
        )
        .fetch_one(&self.pool)
        .await
        .map_err(fix_error)
        .map(|r| r.total)
    }

    #[instrument(skip_all)]
    async fn total_history(&self) -> DbResult<i64> {
        // The cache is new, and the user might not yet have a cache value.
        // They will have one as soon as they post up some new history, but handle that
        // edge case.

        sqlx::query!("select sum(total) as total from total_history_count_user")
            .fetch_optional(&self.pool)
            .await
            .map_err(fix_error)
            .map(|r| r.and_then(|r| r.total).unwrap_or(0))
    }

    #[instrument(skip_all)]
    async fn count_history_cached(&self, user: &User) -> DbResult<i64> {
        sqlx::query!(
            "select total from total_history_count_user
            where user_id = $1",
            user.id
        )
        .fetch_one(&self.pool)
        .await
        .map_err(fix_error)
        .map(|r| r.total.unwrap_or(0))
    }

    async fn delete_store(&self, user: &User) -> DbResult<()> {
        sqlx::query!(
            "delete from store
            where user_id = $1",
            user.id
        )
        .execute(&self.pool)
        .await
        .map_err(fix_error)
        .map(|_| ())
    }

    async fn delete_history(&self, user: &User, id: String) -> DbResult<()> {
        let now = OffsetDateTime::now_utc();
        sqlx::query!(
            "update history set deleted_at = $3
            where user_id = $1 and client_id = $2 and deleted_at is null", // don't just keep setting it
            user.id,
            id,
            now
        )
        .fetch_all(&self.pool)
        .await
        .map_err(fix_error)
        .map(|_| ())
    }

    #[instrument(skip_all)]
    async fn deleted_history(&self, user: &User) -> DbResult<Vec<String>> {
        // The cache is new, and the user might not yet have a cache value.
        // They will have one as soon as they post up some new history, but handle that
        // edge case.

        sqlx::query!(
            "select client_id from history 
            where user_id = $1 and deleted_at is not null",
            user.id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(fix_error)
        .map(|rs| rs.into_iter().map(|r| r.client_id).collect())
    }

    #[instrument(skip_all)]
    async fn count_history_range(
        &self,
        user: &User,
        range: Range<OffsetDateTime>,
    ) -> DbResult<i64> {
        let start = into_utc(range.start);
        let end = into_utc(range.end);
        sqlx::query!(
            "select count(1) as total from history
            where user_id = $1 and timestamp >= $2::date and timestamp < $3::date",
            user.id,
            start,
            end
        )
        .fetch_one(&self.pool)
        .await
        .map_err(fix_error)
        .map(|r| r.total)
    }

    #[instrument(skip_all)]
    async fn list_history(
        &self,
        user: &User,
        created_after: OffsetDateTime,
        since: OffsetDateTime,
        host: &str,
        page_size: i64,
    ) -> DbResult<Vec<History>> {
        let created_after = into_utc(created_after);
        let since = into_utc(since);
        sqlx::query_as!(
            History,
            r#"select id, client_id, user_id, hostname, timestamp "timestamp: OffsetDateTime", data, created_at "created_at: OffsetDateTime" from history 
            where user_id = $1 and hostname != $2 and created_at >= $3 and timestamp >= $4
			order by timestamp asc limit $5"#,
            user.id,
            host,
			created_after,
			since,
            page_size
        )
        .fetch(&self.pool)
        .try_collect()
        .await
        .map_err(fix_error)
    }

    #[instrument(skip_all)]
    async fn add_history(&self, history: &[NewHistory]) -> DbResult<()> {
        let mut tx = self.pool.begin().await.map_err(fix_error)?;

        for i in history {
            let client_id: &str = &i.client_id;
            let hostname: &str = &i.hostname;
            let data: &str = &i.data;

            sqlx::query!(
                "insert into history
                    (client_id, user_id, hostname, timestamp, data) 
                values ($1, $2, $3, $4, $5)
                on conflict do nothing
                ",
                client_id,
                i.user_id,
                hostname,
                i.timestamp,
                data
            )
            .execute(&mut *tx)
            .await
            .map_err(fix_error)?;
        }

        tx.commit().await.map_err(fix_error)?;

        Ok(())
    }

    #[instrument(skip_all)]
    async fn delete_user(&self, u: &User) -> DbResult<()> {
        sqlx::query!("delete from sessions where user_id = $1", u.id)
            .execute(&self.pool)
            .await
            .map_err(fix_error)?;

        sqlx::query!("delete from history where user_id = $1", u.id)
            .execute(&self.pool)
            .await
            .map_err(fix_error)?;

        sqlx::query!("delete from store where user_id = $1", u.id)
            .execute(&self.pool)
            .await
            .map_err(fix_error)?;

        sqlx::query!(
            "delete from user_verification_token where user_id = $1",
            u.id
        )
        .execute(&self.pool)
        .await
        .map_err(fix_error)?;

        sqlx::query!(
            "delete from total_history_count_user where user_id = $1",
            u.id
        )
        .execute(&self.pool)
        .await
        .map_err(fix_error)?;

        sqlx::query!("delete from users where id = $1", u.id)
            .execute(&self.pool)
            .await
            .map_err(fix_error)?;

        Ok(())
    }

    #[instrument(skip_all)]
    async fn update_user_password(&self, user: &User) -> DbResult<()> {
        let password = user.password.as_str();
        sqlx::query!(
            "update users set password = $1 where id = $2",
            password,
            user.id
        )
        .execute(&self.pool)
        .await
        .map_err(fix_error)
        .map(|_| ())
    }

    #[instrument(skip_all)]
    async fn add_user(&self, user: &NewUser) -> DbResult<i64> {
        let email: &str = &user.email;
        let username: &str = &user.username;
        let password: &str = &user.password;

        sqlx::query!(
            "insert into users (username, email, password)
            values ($1, $2, $3)
            returning id",
            username,
            email,
            password
        )
        .fetch_one(&self.pool)
        .await
        .map_err(fix_error)
        .map(|r| r.id)
    }

    #[instrument(skip_all)]
    async fn add_session(&self, session: &NewSession) -> DbResult<()> {
        let token: &str = &session.token;

        sqlx::query!(
            "insert into sessions (user_id, token)
            values($1, $2)",
            session.user_id,
            token
        )
        .execute(&self.pool)
        .await
        .map_err(fix_error)
        .map(|_| ())
    }

    #[instrument(skip_all)]
    async fn get_user_session(&self, u: &User) -> DbResult<Session> {
        sqlx::query_as!(
            Session,
            "select id, user_id, token from sessions where user_id = $1",
            u.id
        )
        .fetch_one(&self.pool)
        .await
        .map_err(fix_error)
    }

    #[instrument(skip_all)]
    async fn oldest_history(&self, user: &User) -> DbResult<History> {
        sqlx::query_as!(
            History,
            r#"select id, client_id, user_id, hostname, timestamp "timestamp: OffsetDateTime", data, created_at "created_at: OffsetDateTime" from history 
            where user_id = $1
            order by timestamp asc limit 1"#,
            user.id
        )
        .fetch_one(&self.pool)
        .await
        .map_err(fix_error)
    }

    #[instrument(skip_all)]
    async fn add_records(&self, user: &User, records: &[Record<EncryptedData>]) -> DbResult<()> {
        let mut tx = self.pool.begin().await.map_err(fix_error)?;

        // We won't have uploaded this data if it wasn't the max. Therefore, we can deduce the max
        // idx without having to make further database queries. Doing the query on this small
        // amount of data should be much, much faster.
        //
        // Worst case, say we get this wrong. We end up caching data that isn't actually the max
        // idx, so clients upload again. The cache logic can be verified with a sql query anyway :)

        let mut heads = HashMap::<(HostId, &str), u64>::new();

        for i in records {
            let id = atuin_common::utils::uuid_v7();
            let idx = i.idx as i64;
            let timestamp = i.timestamp as i64;
            let version = i.version.as_str();
            let tag = i.tag.as_str();
            let data = i.data.data.as_str();
            let cek = i.data.content_encryption_key.as_str();

            sqlx::query!(
                "insert into store (id, client_id, host, idx, timestamp, version, tag, data, cek, user_id) 
                values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                on conflict do nothing
                ",
                id,
                i.id,
                i.host.id,
				idx,
				timestamp,
				version,
				tag,
				data,
				cek,
                user.id
            )
            .execute(&mut *tx)
            .await
            .map_err(fix_error)?;

            // we're already iterating sooooo
            heads
                .entry((i.host.id, &i.tag))
                .and_modify(|e| {
                    if i.idx > *e {
                        *e = i.idx
                    }
                })
                .or_insert(i.idx);
        }

        // we've built the map of heads for this push, so commit it to the database
        for ((host, tag), idx) in heads {
            let idx = idx as i64;
            sqlx::query!(
                "insert into store_idx_cache (user_id, host, tag, idx) 
                values ($1, $2, $3, $4)
                on conflict(user_id, host, tag) do update set idx = max(store_idx_cache.idx, $4)
                ",
                user.id,
                host,
                tag,
                idx
            )
            .execute(&mut *tx)
            .await
            .map_err(fix_error)?;
        }

        tx.commit().await.map_err(fix_error)?;

        Ok(())
    }

    #[instrument(skip_all)]
    async fn next_records(
        &self,
        user: &User,
        host: HostId,
        tag: String,
        start: Option<RecordIdx>,
        count: u64,
    ) -> DbResult<Vec<Record<EncryptedData>>> {
        tracing::debug!("{:?} - {:?} - {:?}", host, tag, start);
        let start = start.unwrap_or(0);

        struct DbRecord {
            id: String,
            idx: i64,
            host: String,
            tag: String,
            timestamp: i64,
            version: String,
            data: String,
            cek: String,
        }

        impl From<DbRecord> for Record<EncryptedData> {
            fn from(value: DbRecord) -> Self {
                use atuin_common::record as r;
                Self {
                    id: r::RecordId(value.id.parse().unwrap()),
                    idx: value.idx as u64,
                    host: r::Host::new(r::HostId(value.host.parse().unwrap())),
                    tag: value.tag,
                    timestamp: value.timestamp as u64,
                    version: value.version,
                    data: EncryptedData {
                        data: value.data,
                        content_encryption_key: value.cek,
                    },
                }
            }
        }

        let tag = tag.clone();
        let start = start as i64;
        let count = count as i64;
        let records = sqlx::query_as!(
            DbRecord,
            "select id, host, idx, timestamp, version, tag, data, cek from store
			where user_id = $1 and tag = $2 and host = $3 and idx >= $4
            order by idx asc limit $5",
            user.id,
            tag,
            host,
            start,
            count
        )
        .fetch_all(&self.pool)
        .await
        .map_err(fix_error);

        let ret = match records {
            Ok(records) => {
                let records: Vec<Record<EncryptedData>> = records
                    .into_iter()
                    .map(|f| {
                        let record: Record<EncryptedData> = f.into();
                        record
                    })
                    .collect();

                records
            }
            Err(DbError::NotFound) => {
                tracing::debug!("no records found in store: {:?}/{}", host, tag);
                return Ok(vec![]);
            }
            Err(e) => return Err(e),
        };

        Ok(ret)
    }

    async fn status(&self, user: &User) -> DbResult<RecordStatus> {
        #[derive(PartialEq, Eq, PartialOrd, Ord, Debug)]
        struct S {
            host: String,
            tag: String,
            idx: Option<i64>,
        }

        let mut res: Vec<S> = sqlx::query_as!(
			S,
			r#"select host, tag, max(idx) "idx: i64" from store where user_id = $1 group by host, tag"#,
			user.id
		)
            .fetch_all(&self.pool)
            .await
            .map_err(fix_error)?;
        res.sort();

        // We're temporarily increasing latency in order to improve confidence in the cache
        // If it runs for a few days, and we confirm that cached values are equal to realtime, we
        // can replace realtime with cached.
        //
        // But let's check so sync doesn't do Weird Things.

        let mut cached_res = sqlx::query_as!(
            S,
            "select host, tag, idx from store_idx_cache where user_id = $1",
            user.id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(fix_error)?;
        cached_res.sort();

        let mut status = RecordStatus::new();

        let equal = res == cached_res;

        if equal {
            counter!("atuin_store_idx_cache_consistent", 1);
        } else {
            // log the values if we have an inconsistent cache
            tracing::debug!(user = user.username, cache_match = equal, res = ?res, cached = ?cached_res, "record store index request");
            counter!("atuin_store_idx_cache_inconsistent", 1);
        };

        for i in res.iter() {
            status.set_raw(
                HostId(i.host.parse().unwrap()),
                i.tag.clone(),
                i.idx.unwrap() as u64,
            );
        }

        Ok(status)
    }
}

fn into_utc(x: OffsetDateTime) -> PrimitiveDateTime {
    let x = x.to_offset(UtcOffset::UTC);
    PrimitiveDateTime::new(x.date(), x.time())
}
