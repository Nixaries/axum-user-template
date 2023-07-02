use axum_user_jwt_template::user::{self, User, Token};
use sqlx::SqlitePool;

const DB_URL: &str = "users.db";

#[tokio::main]
async fn main() {
    user::init_database(&DB_URL.to_string()).await;

    let db = SqlitePool::connect(&DB_URL.to_string()).await.unwrap();

    user::init_user_table(&db).await.unwrap();
    user::init_token_table(&db).await.unwrap();

    // user::register_user(&"dan".to_string(), &"password".to_string(), &db).await.unwrap();
    match user::login_user(&"dan".to_string(), &"password".to_string(), &db).await {
        Some(_) => println!("user found"),
        None => println!("No user found")
    };

    let user:User = User::new(&"username".to_string(), &"password".to_string()).unwrap();
    user.add_to_database(&db).await.unwrap();
    let token:Token = Token::new(&user).unwrap();
    token.add_to_database(&db).await.unwrap();
}
