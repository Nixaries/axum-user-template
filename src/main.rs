use std::sync::Arc;

use axum::{Router, extract::{self, State}, Form, Json, routing::post};
use axum_user_jwt_template::user::{self, User, Session};
use sqlx::{SqlitePool, Pool, Sqlite};
use serde::{Deserialize, Serialize};

const DB_URL: &str = "users.db";

#[derive(Clone)]
struct AppContext {
    db: Pool<Sqlite>
}

#[tokio::main]
async fn main() {
    user::init_database(&DB_URL.to_string()).await;

    let db = SqlitePool::connect(&DB_URL.to_string()).await.unwrap();

    user::init_user_table(&db).await.unwrap();
    user::init_token_table(&db).await.unwrap();

    let app = Router::new()
        .route("/login", post(login))
        .route("/register", post(register))
        .with_state(db);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();

    axum::serve(listener, app).await.unwrap();
}

#[derive(Deserialize, Serialize)]
struct TokenResult {
    token: String
}

#[derive(Deserialize, Debug)]
struct LoginForm {
    username: String,
    password: String
}

async fn login(State(db): State<Pool<Sqlite>>, Json(data): Json<LoginForm>) -> Json<TokenResult> {
    let user = match user::login_user(&data.username, &data.password, &db).await {
        Some(user) => user,
        None => panic!("Not valid login")
    };

    let token = user::Session::new(&user);

    token.add_to_database(&db).await.unwrap();

    let token_result = TokenResult {
        token: token.token
    };

    return Json(token_result);
}

async fn register(State(db): State<Pool<Sqlite>>, Json(data): Json<LoginForm>) -> Json<TokenResult> {
    let user = User::new(&data.username, &data.password).unwrap();
    user.add_to_database(&db).await.unwrap();
    let token = user::Session::new(&user);
    token.add_to_database(&db).await.unwrap();
    let token_result = TokenResult {
        token: token.token
    };

    return Json(token_result);
}
