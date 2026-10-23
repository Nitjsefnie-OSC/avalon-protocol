//! Shared server URL, Postgres pool, and identity-session fixtures for live integration tests.
#![allow(dead_code)]

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

pub fn server_url() -> String {
    std::env::var("AVALON_SERVER_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string())
}

pub async fn test_pool() -> PgPool {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    PgPoolOptions::new()
        .connect(&database_url)
        .await
        .expect("failed to connect to Postgres — is it reachable?")
}

pub async fn seed_identity_session(pool: &PgPool) -> (avalon_protocol::ids::IdentityId, String) {
    let who = avalon_protocol::identity_id::TestIdentity::new();
    let identity_id = who.id;
    sqlx::query("INSERT INTO identities (id, inception_public_key) VALUES ($1, $2)")
        .bind(identity_id)
        .bind(who.public_key().to_vec())
        .execute(pool)
        .await
        .expect("failed to seed identity");
    sqlx::query("INSERT INTO profiles (identity_id, display_name) VALUES ($1, $2)")
        .bind(identity_id)
        .bind(format!("revoke-test-{identity_id}"))
        .execute(pool)
        .await
        .expect("failed to seed profile");
    let token = format!("test-token-{}", Uuid::new_v4());
    let expires_at = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    sqlx::query("INSERT INTO sessions (token_hash, identity_id, expires_at) VALUES (sha256(convert_to($1::text, 'UTF8')), $2, $3)")
        .bind(&token)
        .bind(identity_id)
        .bind(expires_at)
        .execute(pool)
        .await
        .expect("failed to seed session");
    (identity_id, token)
}
