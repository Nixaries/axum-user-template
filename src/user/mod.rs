use sqlx::{Pool, Sqlite, sqlite::SqliteQueryResult};
use uuid::Uuid;
use bcrypt::{DEFAULT_COST, hash, verify, BcryptError};

pub struct User {
    pub id: String,
    pub username: String,
    pub password_hash: String
}

impl User {
   pub fn new(username:String, password:String) -> Result<User, BcryptError>{
        let hash = match hash(password, DEFAULT_COST) {
            Ok(result) => result,
            Err(err) => return Err(err)
        };

        return Ok(User {
            username,
            id: Uuid::new_v4().to_string(),
            password_hash: hash 
        });
    }

    pub async fn add_to_database(&self, db: &Pool<Sqlite>) -> Result<SqliteQueryResult, sqlx::Error> {
        return sqlx::query(
            &*format!("INSERT INTO users (id, username, passwrod) \
            VALUES ({}, {}, {});", self.id, self.username, self.password_hash) 
        ).execute(db).await;
    }
}

pub async fn init_user_table(db: &Pool<Sqlite>) ->  Result<SqliteQueryResult, sqlx::Error>{
    return sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (\
        id VARCHAR(256) PRIMARY KEY NOT NULL,\
        username VARCHAR(256) NOT NULL,\
        password_hash VARCHAR(256) NOT NULL);").execute(db).await
}
