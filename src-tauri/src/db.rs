//! SQLite persistence for OAuth clients, authorization codes and tokens.
//!
//! Exactly three tables exist — clients, authorization codes and tokens.
//! No pre-registered client or secret is ever written by the app.

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id TEXT PRIMARY KEY,
    client_secret TEXT,
    client_name TEXT NOT NULL DEFAULT 'MCP Client',
    redirect_uris TEXT NOT NULL DEFAULT '[]',
    grant_types TEXT NOT NULL DEFAULT '["authorization_code","refresh_token"]',
    response_types TEXT NOT NULL DEFAULT '["code"]',
    token_endpoint_auth_method TEXT NOT NULL DEFAULT 'none',
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_codes (
    code TEXT PRIMARY KEY,
    client_id TEXT,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT,
    code_challenge_method TEXT,
    scope TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_tokens (
    token TEXT PRIMARY KEY,
    token_type TEXT NOT NULL,
    client_id TEXT,
    scope TEXT NOT NULL,
    expires_at INTEGER,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_oauth_tokens_type ON oauth_tokens(token_type);
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRecord {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeRecord {
    pub code: String,
    pub client_id: Option<String>,
    pub redirect_uri: String,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub scope: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenRecord {
    pub token: String,
    pub token_type: String,
    pub client_id: Option<String>,
    pub scope: String,
    pub expires_at: Option<i64>,
    pub created_at: i64,
}

impl TokenRecord {
    pub fn is_expired(&self, now: i64) -> bool {
        matches!(self.expires_at, Some(exp) if exp <= now)
    }
}

pub struct OAuthDb {
    conn: Mutex<Connection>,
}

impl OAuthDb {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create data dir {}", parent.display()))?;
        }
        let conn =
            Connection::open(path).with_context(|| format!("open sqlite db {}", path.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .context("enable sqlite WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(SCHEMA).context("create oauth schema")?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|err| err.into_inner())
    }

    pub fn save_client(&self, client: &ClientRecord) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "INSERT OR REPLACE INTO oauth_clients
             (client_id, client_secret, client_name, redirect_uris, grant_types,
              response_types, token_endpoint_auth_method, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                client.client_id,
                client.client_secret,
                client.client_name,
                serde_json::to_string(&client.redirect_uris).unwrap_or_else(|_| "[]".into()),
                serde_json::to_string(&client.grant_types).unwrap_or_else(|_| "[]".into()),
                serde_json::to_string(&client.response_types).unwrap_or_else(|_| "[]".into()),
                client.token_endpoint_auth_method,
                client.created_at,
            ],
        )
        .context("save oauth client")?;
        Ok(())
    }

    pub fn get_client(&self, client_id: &str) -> Result<Option<ClientRecord>> {
        let conn = self.lock();
        let row = conn
            .query_row(
                "SELECT client_id, client_secret, client_name, redirect_uris, grant_types,
                        response_types, token_endpoint_auth_method, created_at
                 FROM oauth_clients WHERE client_id = ?1",
                params![client_id],
                |row| {
                    let redirect_uris: String = row.get(3)?;
                    let grant_types: String = row.get(4)?;
                    let response_types: String = row.get(5)?;
                    Ok(ClientRecord {
                        client_id: row.get(0)?,
                        client_secret: row.get(1)?,
                        client_name: row.get(2)?,
                        redirect_uris: parse_list(&redirect_uris),
                        grant_types: parse_list(&grant_types),
                        response_types: parse_list(&response_types),
                        token_endpoint_auth_method: row.get(6)?,
                        created_at: row.get(7)?,
                    })
                },
            )
            .optional()
            .context("load oauth client")?;
        Ok(row)
    }

    pub fn list_clients(&self) -> Result<Vec<ClientRecord>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT client_id, client_secret, client_name, redirect_uris, grant_types,
                    response_types, token_endpoint_auth_method, created_at
             FROM oauth_clients ORDER BY created_at DESC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                let redirect_uris: String = row.get(3)?;
                let grant_types: String = row.get(4)?;
                let response_types: String = row.get(5)?;
                Ok(ClientRecord {
                    client_id: row.get(0)?,
                    client_secret: row.get(1)?,
                    client_name: row.get(2)?,
                    redirect_uris: parse_list(&redirect_uris),
                    grant_types: parse_list(&grant_types),
                    response_types: parse_list(&response_types),
                    token_endpoint_auth_method: row.get(6)?,
                    created_at: row.get(7)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn save_code(&self, code: &CodeRecord) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "INSERT OR REPLACE INTO oauth_codes
             (code, client_id, redirect_uri, code_challenge, code_challenge_method, scope, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                code.code,
                code.client_id,
                code.redirect_uri,
                code.code_challenge,
                code.code_challenge_method,
                code.scope,
                code.expires_at,
            ],
        )
        .context("save oauth code")?;
        Ok(())
    }

    pub fn get_code(&self, code: &str) -> Result<Option<CodeRecord>> {
        let conn = self.lock();
        let row = conn
            .query_row(
                "SELECT code, client_id, redirect_uri, code_challenge, code_challenge_method,
                        scope, expires_at FROM oauth_codes WHERE code = ?1",
                params![code],
                row_to_code,
            )
            .optional()?;
        Ok(row)
    }

    /// Reads and deletes the code in one step so a successful exchange can
    /// never be replayed.
    pub fn consume_code(&self, code: &str) -> Result<Option<CodeRecord>> {
        let conn = self.lock();
        let row = conn
            .query_row(
                "SELECT code, client_id, redirect_uri, code_challenge, code_challenge_method,
                        scope, expires_at FROM oauth_codes WHERE code = ?1",
                params![code],
                row_to_code,
            )
            .optional()?;
        if row.is_some() {
            conn.execute("DELETE FROM oauth_codes WHERE code = ?1", params![code])?;
        }
        Ok(row)
    }

    pub fn purge_expired_codes(&self, now: i64) -> Result<usize> {
        let conn = self.lock();
        let deleted = conn.execute(
            "DELETE FROM oauth_codes WHERE expires_at <= ?1",
            params![now],
        )?;
        Ok(deleted)
    }

    pub fn save_token(&self, token: &TokenRecord) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "INSERT OR REPLACE INTO oauth_tokens
             (token, token_type, client_id, scope, expires_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                token.token,
                token.token_type,
                token.client_id,
                token.scope,
                token.expires_at,
                token.created_at,
            ],
        )
        .context("save oauth token")?;
        Ok(())
    }

    /// Returns an unexpired token of the requested type, deleting stale
    /// access tokens as it goes.
    pub fn find_token(
        &self,
        token: &str,
        token_type: &str,
        now: i64,
    ) -> Result<Option<TokenRecord>> {
        let conn = self.lock();
        let row = conn
            .query_row(
                "SELECT token, token_type, client_id, scope, expires_at, created_at
                 FROM oauth_tokens WHERE token = ?1 AND token_type = ?2",
                params![token, token_type],
                |row| {
                    Ok(TokenRecord {
                        token: row.get(0)?,
                        token_type: row.get(1)?,
                        client_id: row.get(2)?,
                        scope: row.get(3)?,
                        expires_at: row.get(4)?,
                        created_at: row.get(5)?,
                    })
                },
            )
            .optional()?;
        match row {
            Some(record) if record.is_expired(now) => {
                conn.execute("DELETE FROM oauth_tokens WHERE token = ?1", params![token])?;
                Ok(None)
            }
            other => Ok(other),
        }
    }

    pub fn list_tokens(&self) -> Result<Vec<TokenRecord>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT token, token_type, client_id, scope, expires_at, created_at
             FROM oauth_tokens ORDER BY created_at DESC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(TokenRecord {
                    token: row.get(0)?,
                    token_type: row.get(1)?,
                    client_id: row.get(2)?,
                    scope: row.get(3)?,
                    expires_at: row.get(4)?,
                    created_at: row.get(5)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn count_active_tokens(&self, now: i64) -> Result<usize> {
        let conn = self.lock();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM oauth_tokens WHERE expires_at IS NULL OR expires_at > ?1",
            params![now],
            |row| row.get(0),
        )?;
        Ok(count.max(0) as usize)
    }

    pub fn revoke_token(&self, token: &str) -> Result<usize> {
        let conn = self.lock();
        let deleted = conn.execute("DELETE FROM oauth_tokens WHERE token = ?1", params![token])?;
        Ok(deleted)
    }

    pub fn revoke_all(&self) -> Result<usize> {
        let conn = self.lock();
        let deleted = conn.execute("DELETE FROM oauth_tokens", [])?;
        Ok(deleted)
    }
}

fn row_to_code(row: &rusqlite::Row<'_>) -> rusqlite::Result<CodeRecord> {
    Ok(CodeRecord {
        code: row.get(0)?,
        client_id: row.get(1)?,
        redirect_uri: row.get(2)?,
        code_challenge: row.get(3)?,
        code_challenge_method: row.get(4)?,
        scope: row.get(5)?,
        expires_at: row.get(6)?,
    })
}

fn parse_list(raw: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(raw).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> (tempfile::TempDir, OAuthDb) {
        let dir = tempfile::tempdir().unwrap();
        let db = OAuthDb::open(&dir.path().join("oauth.db")).unwrap();
        (dir, db)
    }

    fn client(id: &str) -> ClientRecord {
        ClientRecord {
            client_id: id.into(),
            client_secret: Some("secret".into()),
            client_name: "Test Client".into(),
            redirect_uris: vec!["http://127.0.0.1/cb".into()],
            grant_types: vec!["authorization_code".into()],
            response_types: vec!["code".into()],
            token_endpoint_auth_method: "none".into(),
            created_at: 1000,
        }
    }

    #[test]
    fn schema_contains_only_the_three_oauth_tables() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oauth.db");
        let db = OAuthDb::open(&path).unwrap();
        let conn = db.lock();
        let mut stmt = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
            )
            .unwrap();
        let names: Vec<String> = stmt
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let mut names = names;
        names.sort();
        assert_eq!(names, vec!["oauth_clients", "oauth_codes", "oauth_tokens"]);
    }

    #[test]
    fn client_round_trip() {
        let (_dir, db) = db();
        db.save_client(&client("dp_1")).unwrap();
        let loaded = db.get_client("dp_1").unwrap().unwrap();
        assert_eq!(loaded.client_name, "Test Client");
        assert_eq!(loaded.redirect_uris, vec!["http://127.0.0.1/cb"]);
        assert_eq!(db.list_clients().unwrap().len(), 1);
        assert_eq!(db.list_clients().unwrap().len(), 1);
        assert!(db.get_client("missing").unwrap().is_none());
    }

    #[test]
    fn auth_code_can_only_be_consumed_once() {
        let (_dir, db) = db();
        let code = CodeRecord {
            code: "code-1".into(),
            client_id: Some("dp_1".into()),
            redirect_uri: "http://127.0.0.1/cb".into(),
            code_challenge: Some("challenge".into()),
            code_challenge_method: Some("S256".into()),
            scope: "mcp:tools".into(),
            expires_at: 9_999_999_999_999,
        };
        db.save_code(&code).unwrap();
        assert!(db.get_code("code-1").unwrap().is_some());
        let first = db.consume_code("code-1").unwrap();
        assert_eq!(first.unwrap().redirect_uri, "http://127.0.0.1/cb");
        assert!(db.get_code("code-1").unwrap().is_none());
        assert!(db.consume_code("code-1").unwrap().is_none());
    }

    #[test]
    fn expired_codes_are_purged() {
        let (_dir, db) = db();
        for (code, exp) in [("old", 100), ("new", 9_999_999_999_999)] {
            db.save_code(&CodeRecord {
                code: code.into(),
                client_id: None,
                redirect_uri: "http://127.0.0.1/cb".into(),
                code_challenge: None,
                code_challenge_method: None,
                scope: "mcp:tools".into(),
                expires_at: exp,
            })
            .unwrap();
        }
        assert_eq!(db.purge_expired_codes(1_000).unwrap(), 1);
        assert!(db.consume_code("old").unwrap().is_none());
        assert!(db.consume_code("new").unwrap().is_some());
    }

    #[test]
    fn tokens_expire_and_can_be_revoked() {
        let (_dir, db) = db();
        let now = 10_000;
        db.save_token(&TokenRecord {
            token: "valid".into(),
            token_type: "access".into(),
            client_id: Some("dp_1".into()),
            scope: "mcp:tools".into(),
            expires_at: Some(now + 1_000),
            created_at: now,
        })
        .unwrap();
        db.save_token(&TokenRecord {
            token: "stale".into(),
            token_type: "access".into(),
            client_id: Some("dp_1".into()),
            scope: "mcp:tools".into(),
            expires_at: Some(now - 1),
            created_at: now,
        })
        .unwrap();
        db.save_token(&TokenRecord {
            token: "refresh".into(),
            token_type: "refresh".into(),
            client_id: Some("dp_1".into()),
            scope: "mcp:tools".into(),
            expires_at: None,
            created_at: now,
        })
        .unwrap();

        assert!(db.find_token("valid", "access", now).unwrap().is_some());
        assert!(db.find_token("stale", "access", now).unwrap().is_none());
        assert!(db.find_token("refresh", "refresh", now).unwrap().is_some());
        assert_eq!(db.count_active_tokens(now).unwrap(), 2);

        assert_eq!(db.revoke_token("valid").unwrap(), 1);
        assert!(db.find_token("valid", "access", now).unwrap().is_none());
        assert_eq!(db.revoke_all().unwrap(), 1);
        assert_eq!(db.count_active_tokens(now).unwrap(), 0);
    }
}
