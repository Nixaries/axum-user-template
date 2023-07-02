use sqlx::{Pool, Sqlite, sqlite::SqliteQueryResult, FromRow, migrate::MigrateDatabase};
use uuid::Uuid;
use bcrypt::{DEFAULT_COST, hash, BcryptError};
use chrono::{DateTime, Utc};
use rand::{self,  Rng};

#[derive(FromRow, Debug)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password_hash: String
}

impl User {
   pub fn new(username:&String, password:&String) -> Result<User, BcryptError>{
        let hash: String = match hash(password, DEFAULT_COST) {
            Ok(result) => result,
            Err(err) => return Err(err)
        };

        return Ok(User {
            username: username.clone(),
            id: Uuid::new_v4().to_string(),
            password_hash: hash 
        });
    }

    pub async fn add_to_database(&self, db: &Pool<Sqlite>) -> Result<SqliteQueryResult, sqlx::Error> {
        return sqlx::query(
            &*format!("INSERT INTO users (id, username, password_hash) \
            VALUES ('{}', '{}', '{}');", self.id, self.username, self.password_hash) 
        ).execute(db).await;
    }
}

pub async fn init_database(db_url:&String) {
    if !Sqlite::database_exists(db_url).await.unwrap_or(false) {
        println!("Creating database {}", db_url);
        match Sqlite::create_database(db_url).await {
            Ok(_) => println!("Created database {}", db_url),
            Err(error) => panic!("Failed to create database with error: {}", error)
        }
    } else {
        println!("Database {} already exists", db_url);
    }
}

pub async fn init_user_table(db: &Pool<Sqlite>) ->  Result<SqliteQueryResult, sqlx::Error>{
    return sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (\
        id VARCHAR(256) PRIMARY KEY NOT NULL,\
        username VARCHAR(256) NOT NULL,\
        password_hash VARCHAR(256) NOT NULL);").execute(db).await
}

pub async fn register_user(username:&String, password:&String, db:&Pool<Sqlite>) -> Result<User, ()> {
    let new_user:User = match User::new(&username, &password) {
        Ok(res) => res,
        Err(_) => return Err(())
    };

    match new_user.add_to_database(db).await {
        Ok(_) => (),
        Err(_) => return Err(())
    }

    return Ok(new_user);
} 

pub async fn login_user(username:&String, password:&String, db: &Pool<Sqlite>) -> Option<User> {
    let user:User = match sqlx::query_as::<_, User>(&*format!("SELECT * FROM users WHERE username = '{}'", username)).fetch_one(db).await {
        Ok(result) => result,
        Err(_) => return None
    };

    return match bcrypt::verify(password, &user.password_hash) {
        Ok(valid) => if valid {Some(user)} else {None}, 
        Err(_) => None 
    };
}

pub enum TokenUserResult {
    User(User),
    NotFound,
    Expired,
    Disabled
}

#[derive(FromRow, Debug)]
pub struct Session {
    pub id: String,
    pub token: String,
    pub user_id: String,
    pub valid_to: sqlx::types::chrono::DateTime<Utc>,
    pub disabled: i64 
}

impl Session {
    pub fn generate_session_token(length: usize) -> String {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let mut rng = rand::thread_rng();
    
        let token: String = (0..length)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect();
    
        return token
    }

    pub fn new(user:&User) -> Self {
        let token:String = Self::generate_session_token(32);

        // let hash: String = match hash(token, DEFAULT_COST) {
        //     Ok(result) => result,
        //     Err(err) => return Err(err)
        // };

        return Self {
            id: Uuid::new_v4().to_string(),
            token,
            user_id: user.id.clone(),
            valid_to: Utc::now(),
            disabled: 0 
        };
    }

    pub async fn add_to_database(&self, db: &Pool<Sqlite>) -> Result<SqliteQueryResult, sqlx::Error> {
        return sqlx::query(
            &*format!("INSERT INTO sessions (id, token, user_id, valid_to, disabled) \
            VALUES ('{}', '{}', '{}', '{}', {});", self.id, self.token, self.user_id, self.valid_to, self.disabled) 
        ).execute(db).await;
    }


    pub async fn get_token_user(token: &String, db: &Pool<Sqlite>) -> Result<User, sqlx::Error>{
        let user_id_query = match sqlx::query!("SELECT user_id FROM sessions WHERE token = ?;", token).fetch_one(db).await {
            Ok(res) => res,
            Err(err) => return Err(err)
        };

        let user = match sqlx::query_as!(User, "SELECT * FROM users WHERE id = ?;", user_id_query.user_id).fetch_one(db).await {
            Ok(res) => res,
            Err(err) => return Err(err)
        };

        return Ok(user);
    }
}

pub async fn init_token_table(db:&Pool<Sqlite>) -> Result<SqliteQueryResult, sqlx::Error> {
    return sqlx::query(
        "CREATE TABLE IF NOT EXISTS sessions (\
        id VARCHAR(256) PRIMARY KEY NOT NULL,\
        token VARCHAR(256) NOT NULL,\
        user_id VARCHAR(256) NOT NULL,\
        valid_to DATETIME NOT NULL,\
        disabled INTEGER NOT NULL);").execute(db).await
}
