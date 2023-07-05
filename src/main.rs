use axum::{Router, extract::{self, State}, Form, Json, routing::post, http::StatusCode};
use axum_user_jwt_template::user::{self, User, Session};
use sqlx::{SqlitePool, Pool, Sqlite};
use serde::{Deserialize, Serialize};
use serde_json::Result;

const DB_URL: &str = "users.db";

#[tokio::main]
async fn main() {
    user::init_database(&DB_URL.to_string()).await;

    let db = SqlitePool::connect(&DB_URL.to_string()).await.unwrap();

    let app = Router::new()
        .route("/login", post(login))
        .route("/register", post(register))
        .route("/verify", post(verify))
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

async fn login(State(db): State<Pool<Sqlite>>, Json(data): Json<LoginForm>) -> std::result::Result<String, StatusCode> {
    let user = match user::login_user(&data.username, &data.password, &db).await {
        Some(user) => user,
        None => return Err(StatusCode::UNAUTHORIZED)
    };
    
    let token = user::Session::new(&user);

    token.add_to_database(&db).await.unwrap();

    let token_result = TokenResult {
        token: token.token
    };

    return match serde_json::to_string(&token_result) {
        Ok(token) => Ok(token),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR)
    };
}

async fn register(State(db): State<Pool<Sqlite>>, Json(data): Json<LoginForm>) -> std::result::Result<String, StatusCode> {
    let user = User::new(&data.username, &data.password).unwrap();

    match user.add_to_database(&db).await {
        user::AddUserResult::Success => return Ok("Success".to_string()),
        user::AddUserResult::UsernameTaken => return Err(StatusCode::UNAUTHORIZED),
        user::AddUserResult::DatabaseError => return Err(StatusCode::INTERNAL_SERVER_ERROR) 
    };
}

#[derive(Deserialize, Debug)]
struct TokenInput {
    token: String
}

async fn verify(State(db): State<Pool<Sqlite>>, Json(data): Json<TokenInput>) -> std::result::Result<StatusCode, StatusCode> {
    let user = match user::Session::get_token_user(&data.token, &db).await {
        user::GetTokenUserResult::Success(user) => user, 
        user::GetTokenUserResult::NotFound => return Err(StatusCode::UNAUTHORIZED), 
        user::GetTokenUserResult::Unauthorized => return Err(StatusCode::UNAUTHORIZED),
        user::GetTokenUserResult::DatabaseError => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };

    return match serde_json::to_string(&user) {
        Ok(_) => Ok(StatusCode::OK),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR)
     }
}
