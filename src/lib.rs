#[allow(dead_code)]
pub mod response {
    use axum::response::IntoResponse;
    use hyper::StatusCode;

    pub const SUCCESS: &str = "Success";
    pub const ERROR: &str = "Error";

    #[axum::debug_handler]
    pub async fn not_found(message: String) -> impl IntoResponse {
        (
            StatusCode::NOT_FOUND,
            message,
            //default message: "The requested resource was not found, nothing to see here.",
        )
    }

    pub async fn internal_server_error(message: String) -> impl IntoResponse {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            message,
            //default message: "An internal server error occurred. The server encountered an unexpected condition that prevented it from fulfilling the request."
        )
    }

    pub async fn bad_request(message: String) -> impl IntoResponse {
        (
            StatusCode::BAD_REQUEST,
            message,
            //default message: "The request was invalid or cannot be served."
        )
    }

    pub async fn unauthorized(message: String) -> impl IntoResponse {
        (
            StatusCode::UNAUTHORIZED,
            message,
            //default message: "Authentication is required and has failed or has not yet been provided."
        )
    }
}

pub mod lib {
    use axum::Json;
    use axum::response::IntoResponse;
    use hyper::StatusCode;
    use serde::{Deserialize, Serialize};
    use serde_json::json;

    // #[derive(Debug, Clone, Serialize, Deserialize)]
    // pub struct RegistrationRequest {
    //     pub id: Option<i32>,
    //     pub username: String,
    //     pub first_name: String,
    //     pub middle_name: Option<String>,
    //     pub last_name: String,
    //     pub email: String,
    //     pub password: String,
    //     pub email_verified: bool,
    //     pub email_verified_at: Option<chrono::NaiveDateTime>,
    //     pub birthday: Option<chrono::NaiveDate>,
    //     pub created_at: chrono::NaiveDateTime,
    //     pub updated_at: chrono::NaiveDateTime,
    //     pub image: Option<String>,
    //     pub role_type: String,
    // }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RegistrationRequest {
        pub username: String,
        pub first_name: String,
        pub middle_name: Option<String>,
        pub last_name: Option<String>,
        pub email: String,
        pub password: String,
        pub birthday: Option<chrono::NaiveDate>,
        pub image: Option<Vec<u8>>,
        pub role_type: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct User {
        // pub id: i64,
        pub first_name: String,
        pub middle_name: Option<String>,
        pub last_name: Option<String>,
        pub birthday: Option<chrono::NaiveDate>,
        pub role_type: String,
        pub image: Option<Vec<u8>>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Credentials {
        // pub user_id: Option<i64>,
        pub username: String,
        pub email: String,
        pub password: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct UsernameLoginPayload {
        pub username: String,
        pub password: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct EmailLoginPayload {
        pub email: String,
        pub password: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct LoginResponse {
        pub user_id: i64,
        pub content: String,
        pub session_id: String,
        pub jwt_token: String,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Claims {
        pub user_id: i64,
        pub iat: usize,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Session {
        pub id: i64,
        pub user_id: i64,
        pub session_id: String,
        pub jwt_token: String, // pub ip_address: String,
                               // pub user_agent: String,
                               // pub created_at: chrono::NaiveDateTime,
                               // pub updated_at: chrono::NaiveDateTime,
                               // pub last_activity_at: chrono::NaiveDateTime,
                               // pub expires_at: chrono::NaiveDateTime,
                               // pub user_agent: String,
                               // pub user_agent_version: String,
                               // pub user_agent_os: String,
                               // pub user_agent_browser: String,
                               // pub user_agent_browser_version: String,
                               // pub user_agent_os_version: String,
    }

    #[derive(Debug)]
    pub struct ErrorResponse(pub StatusCode, pub String);

    impl IntoResponse for ErrorResponse {
        fn into_response(self) -> axum::response::Response {
            // Return a JSON object like { "error": "message" }
            let body = Json(json!({ "error": self.1 }));
            (self.0, body).into_response()
        }
    }
}
