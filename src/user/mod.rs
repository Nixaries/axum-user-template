use uuid::Uuid;

pub struct User {
    id: String,
    username: String
}

impl User {
   fn new(username:String) -> Self {
        return User {
            username,
            id: Uuid::new_v4().to_string()
        };
   }
}
