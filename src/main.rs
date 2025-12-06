use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, extract::Path};
use axum::{Router, routing::get};
use dotenvy::dotenv;
use fancy_regex::Regex;
use hyper::{HeaderMap, StatusCode};
use pie::{
    lib::{
        Claims, Credentials, EmailLoginPayload, ErrorResponse, LoginResponse, RegistrationRequest,
        User, UsernameLoginPayload,
    },
    response::not_found,
};
use sqlx::{Executor, PgPool, Row};
use std::{env, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::TcpListener, signal};
use tower::ServiceBuilder;
use tower_governor::{GovernorLayer, governor::GovernorConfig};
use tower_http::{
    compression::{CompressionLayer, CompressionLevel},
    cors::CorsLayer,
    limit::RequestBodyLimitLayer,
    timeout::TimeoutLayer,
    trace::{DefaultMakeSpan, DefaultOnFailure, DefaultOnRequest, DefaultOnResponse, TraceLayer},
    validate_request::ValidateRequestHeaderLayer,
};
use tracing::Level;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

#[derive(Clone, Debug)]
struct AppState {
    db: Arc<PgPool>,
}

async fn hello_world() -> &'static str {
    "Hello, world!"
}

#[cfg(feature = "shuttle")]
#[shuttle_runtime::main] // used on Shuttle
async fn main() -> shuttle_axum::ShuttleAxum {
    // setup logging
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            format!(
                "{}=debug,tower_http=debug,axum::rejection=trace",
                env!("CARGO_CRATE_NAME")
            )
            .into()
        }))
        .with(fmt::layer())
        .init();

    dotenv().ok();
    let database_url =
        env::var("POSTGRES_URL_NON_POOLING").expect("DB_URL env var must be set (from Supabase)");
    println!("Database URL: {}", database_url);
    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database");

    // Services
    let trace_layer = TraceLayer::new_for_http()
        .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
        .on_request(DefaultOnRequest::new().level(Level::INFO))
        .on_response(DefaultOnResponse::new().level(Level::INFO))
        .on_failure(DefaultOnFailure::new().level(Level::ERROR));

    let cors_layer = CorsLayer::permissive(); //should narrow this down later on

    let compression_layer = CompressionLayer::new()
        .zstd(true)
        .gzip(true)
        .quality(CompressionLevel::Default); // uses zstd with gzip as backup

    // let set_request_id_layer = SetRequestIdLayer::new( HeaderName::from_static("x-request-id", );

    // let propagate_request_id_layer: PropagateRequestIdLayer = PropagateRequestIdLayer::new(HeaderName::from_static("x-request-id"));

    let timeout_layer =
        TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, Duration::from_secs(30)); // 30 seconds timeout

    // let rate_limit_layer = RateLimitLayer::new(100, Duration::from_secs(60)); // 100 requests per minute

    let governor_config = GovernorConfig::default();

    let rate_limit_layer = GovernorLayer::new(governor_config);

    let bearer_token =
        env::var("BEARER_TOKEN").expect("BEARER_TOKEN environment variable must be set");
    // let bearer_auth_layer = ValidateRequestHeaderLayer::bearer(&bearer_token);

    let content_accept_layer = ValidateRequestHeaderLayer::accept("application/json");

    // build the app and convert to ShuttleAxum
    let app = build_app()
        .await
        .layer(
            ServiceBuilder::new() //order matters
                .layer(trace_layer)
                .layer(RequestBodyLimitLayer::new(10 * 1024 * 1024)) // 10 MB limit
                .layer(cors_layer)
                .layer(compression_layer) //(uses zstd with gzip as backup)
                .layer(rate_limit_layer) // 100 requests per minute
                .layer(timeout_layer) // 30 seconds timeout
                // .layer(bearer_auth_layer)
                .layer(content_accept_layer),
        )
        .fallback(not_found);
    let service: axum::extract::connect_info::IntoMakeServiceWithConnectInfo<Router, SocketAddr> =
        app.into_make_service_with_connect_info::<SocketAddr>();
    shuttle_axum::ShuttleAxum::from(app)
}

// used locally
#[cfg(not(feature = "shuttle"))]
#[tokio::main]
async fn main() {
    // setup logging
    // let subscriber =
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            format!(
                "{}=debug,tower_http=debug,axum::rejection=trace",
                env!("CARGO_CRATE_NAME")
            )
            .into()
        }))
        .with(fmt::layer().with_target(true))
        .init();

    // tracing::subscriber::set_global_default(subscriber).unwrap();

    dotenv().ok();
    let database_url =
        // env::var("POSTGRES_URL_NON_POOLING").expect("DB_URL env var must be set (from Supabase)");
        env::var("DB_URL").expect("DB_URL env var must be set");
    // println!("Database URL: {}", database_url);

    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database");

    let state = AppState { db: Arc::new(pool) };

    // Services
    let trace_layer = TraceLayer::new_for_http()
        .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
        .on_request(DefaultOnRequest::new().level(Level::INFO))
        .on_response(DefaultOnResponse::new().level(Level::INFO))
        .on_failure(DefaultOnFailure::new().level(Level::ERROR));

    let cors_layer = CorsLayer::permissive(); //should narrow this down later on

    let compression_layer = CompressionLayer::new()
        .zstd(true)
        .gzip(true)
        .quality(CompressionLevel::Default); // uses zstd with gzip as backup

    // let set_request_id_layer = SetRequestIdLayer::new( HeaderName::from_static("x-request-id", );

    // let propagate_request_id_layer: PropagateRequestIdLayer = PropagateRequestIdLayer::new(HeaderName::from_static("x-request-id"));

    let timeout_layer =
        TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, Duration::from_secs(30)); // 30 seconds timeout

    // let rate_limit_layer = RateLimitLayer::new(100, Duration::from_secs(60)); // 100 requests per minute

    let governor_config = GovernorConfig::default();

    let rate_limit_layer = GovernorLayer::new(governor_config);

    // let bearer_token =
    //     env::var("BEARER_TOKEN").expect("BEARER_TOKEN environment variable must be set");
    // let bearer_auth_layer = ValidateRequestHeaderLayer::bearer(&bearer_token);

    let content_accept_layer = ValidateRequestHeaderLayer::accept("application/json");

    let app = build_app().await;

    let app = app
        .with_state(state)
        .layer(
            ServiceBuilder::new() //order matters
                .layer(trace_layer)
                .layer(RequestBodyLimitLayer::new(10 * 1024 * 1024)) // 10 MB limit
                .layer(cors_layer)
                .layer(compression_layer) //(uses zstd with gzip as backup)
                .layer(rate_limit_layer) // 100 requests per minute
                .layer(timeout_layer) // 30 seconds timeout
                // .layer(bearer_auth_layer)
                .layer(content_accept_layer),
        )
        .fallback(not_found);
    // bind & serve locally
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 6942)); // could also use [0, 0, 0, 0]

    let service: axum::extract::connect_info::IntoMakeServiceWithConnectInfo<Router, SocketAddr> =
        app.into_make_service_with_connect_info::<SocketAddr>();

    let listener = TcpListener::bind(addr).await.unwrap();
    tracing::info!("listening on {}", addr);
    axum::serve(listener, service)
        .with_graceful_shutdown(signal_shutdown())
        .await
        .unwrap()
}

async fn build_app() -> axum::Router<AppState> {
    // Routes
    let login_route = Router::new()
        .route("/login/username", post(login_by_username))
        .route("/login/email", post(login_by_email))
        // .route(
        //     "/profile-image/{user_id}",
        //     get(retrieve_profile_image).layer(compression_layer.clone()),
        // )
        // .route(
        //     "/profile-image/update/{user_id}",
        //     patch(update_profile_image).layer(compression_layer.clone()),
        // )
        .route("/logout", post(logout))
        .route("/audit/{user_id}", get(audit_user));

    let registration_route = Router::new().route("/register", post(register));
    // .route("/register-json", post(register_json));
    let router = Router::new()
        .route("/", get(hello_world))
        .nest("/api/user", registration_route)
        .nest("/user", login_route);

    router.into()
}

//Signal for graceful shutdown
async fn signal_shutdown() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[axum::debug_handler]
async fn register(
    State(state): State<AppState>,
    Json(mut payload): Json<RegistrationRequest>,
) -> Result<impl IntoResponse, ErrorResponse> {
    // let minimum_password_length = 8;

    // let now = chrono::Utc::now().naive_utc();

    let info_errors = validate_information(&mut payload);
    if let Err(errors) = info_errors {
        tracing::error!("Validation failed: {}", errors);
        return Err(ErrorResponse(StatusCode::BAD_REQUEST, errors));
    }

    println!("Passed validation, before query");

    println!("{:?}", payload);

    // After validation and sanitation checks, create the User and Credentials objects
    let user = User {
        first_name: payload.first_name,
        middle_name: payload.middle_name,
        last_name: payload.last_name,
        birthday: payload.birthday,
        role_type: payload.role_type,
        image: None,
    };

    let credentials = Credentials {
        // user_id: None,
        username: payload.username.clone(),
        email: payload.email,
        password: hash_password(payload.password).await,
    };

    let user_id: i64 = sqlx::query_scalar(
        "SELECT schema.register_user($1,$2,$3,$4,$5,$6,$7,$8,$9::bytea)",
    )
    .bind(&credentials.username)
    .bind(&user.first_name)
    .bind(&user.middle_name)
    .bind(&user.last_name)
    .bind(&credentials.email)
    .bind(credentials.password)
    .bind(payload.birthday)
    .bind(&user.role_type)
    .bind(&payload.image) // Option<Vec<u8>> or Vec<u8>; cast above ensures bytea
    .fetch_one(state.db.as_ref())
    .await
    .map_err(|e| {
        tracing::error!(error = ?e, username = %payload.username, "Failed to register user");
        ErrorResponse(StatusCode::INTERNAL_SERVER_ERROR, format!("Failed: {}", e))
    })?;

    println!("Passed query");

    println!("Value of user id: {}", user_id);

    tracing::info!("Registration successful.");
    Ok((
        StatusCode::OK,
        // "Registration successful. Please check your email for verification.",
        "Registration successful.",
    ))
}

fn validate_information(info: &mut RegistrationRequest) -> Result<(), String> {
    let minimum_password_length = 8;
    let mut errors = Vec::new();
    let name_regex = Regex::new(r"^[a-zA-Z]+(([',. -][a-zA-Z ])?[a-zA-Z]*)*$").unwrap();
    let username_regex = Regex::new(r"^[a-zA-Z0-9._-]{3,}$").unwrap();
    let password_regex =
        Regex::new(r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$")
            .unwrap();

    //credentials sanitization
    let sanitization_regex = Regex::new(r"<[^>]*>").unwrap();
    info.username = sanitization_regex
        .replace_all(&info.username, "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&#x27;")
        .replace("'", "&#x27;")
        .replace("/", "&#x2F;");

    //validate credentials and check for blank (empty) content
    if info.username.trim().is_empty() {
        tracing::error!("Username is required");
        errors.push("Username is required");
    }

    if !username_regex.is_match(&info.username).unwrap_or(false) {
        tracing::error!(username = %info.username, "Username must be at least 3 characters long and can only contain letters, numbers, dots, hyphens, or underscores");
        errors.push("Username must be at least 3 characters long and can only contain letters, numbers, dots, hyphens, or underscores");
    }

    if info.email.trim().is_empty() {
        tracing::error!("Email is required");
        errors.push("Email is required");
    }

    if !info.email.contains('@') || !info.email.contains('.') {
        tracing::error!("Email is not valid");
        errors.push("Email is not valid");
    }

    if info.password.trim().is_empty() {
        tracing::error!(username = %info.username, "Password is required");
        errors.push("Password is required");
    }

    if info.password.len() < minimum_password_length {
        tracing::error!(username = %info.username, "Password must be at least 8 characters long");
        errors.push("Password must be at least 8 characters long");
    }

    if !password_regex.is_match(&info.password).unwrap_or(false) {
        tracing::error!(username = %info.username, "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character");
        errors.push("Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character");
    }

    if info.first_name.trim().is_empty() {
        tracing::error!("First name is required");
        errors.push("First name is required");
    }

    if !name_regex.is_match(&info.first_name).unwrap_or(false) {
        tracing::error!("First name is not valid");
        errors.push("First name is not valid");
    }

    if let Some(middle_name) = &info.middle_name
        && !middle_name.trim().is_empty()
        && !name_regex.is_match(middle_name).unwrap_or(false)
    {
        tracing::error!("Middle name is not valid");
        errors.push("Middle name is not valid");
    }

    if let Some(last_name) = &info.last_name
        && !last_name.trim().is_empty()
        && !name_regex.is_match(last_name).unwrap_or(false)
    {
        tracing::error!("Last name is not valid");
        errors.push("Last name is not valid");
    }

    if info.role_type.trim().is_empty() {
        tracing::error!("Role type is required");
        errors.push("Role type is required");
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join(", "))
    }
}

async fn hash_password(password: String) -> String {
    let argon2 = Argon2::default(); //uses Argon2id instead of Argon2i, with default arguments and parameters

    // let params = Params::new(65536, 2, 1, None).unwrap(); // memory size in KB, iterations, parallelism, output length

    // let argon2 = Argon2::new(
    //     argon2::Algorithm::Argon2i,      //algorithm
    //     argon2::Version::V0x13,  // version, not sure which one was used in the original
    //     params,      // parameters
    // );

    // SaltString::generate uses a CSPRNG (rand_core::OsRng)
    let salt = SaltString::generate(&mut OsRng);

    // let mut output_password: Vec<u8> = vec![0u8; 32]; // 32 bytes output for Argon2
    let hashed_password = argon2
        // .hash_password_into(password.as_bytes(), &[], &mut output_password)\
        .hash_password(password.as_bytes(), &salt)
        .unwrap();
    // output_password
    //     .iter()
    //     .map(|b| format!("{:02x}", b))
    //     .collect()
    hashed_password.to_string()
}

// Login section
async fn login_by_username(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<UsernameLoginPayload>,
) -> Result<Json<LoginResponse>, ErrorResponse> {
    let username = payload.username;
    let password = payload.password;

    let browser_info = headers
        .get("User-Agent")
        .ok_or_else(|| {
            //use ok_or_else because we are passing the result of a function call (headers.get())
            tracing::error!("Missing User-Agent header");
            ErrorResponse(StatusCode::BAD_REQUEST, "Missing User-Agent header".into())
        })?
        .to_str()
        .map_err(|_| {
            tracing::error!("Invalid User-Agent header");
            ErrorResponse(StatusCode::BAD_REQUEST, "Invalid User-Agent header".into())
        })?;

    let ip_address = headers
        .get("X-Forwarded-For")
        .ok_or_else(|| {
            tracing::error!("Missing X-Forwarded-For header");
            ErrorResponse(
                StatusCode::BAD_REQUEST,
                "Missing X-Forwarded-For header".into(),
            )
        })?
        .to_str()
        .map_err(|_| {
            tracing::error!("Invalid X-Forwarded-For header");
            ErrorResponse(
                StatusCode::BAD_REQUEST,
                "Invalid X-Forwarded-For header".into(),
            )
        })?;

    // unimplemented!("Validation for login data");

    let (user_id, hashed_password) = get_user_id_and_hashed_password_by_username(&username, &state)
        .await
        .map_err(|e| {
            tracing::error!("Unauthorized: {}", e);
            ErrorResponse(StatusCode::UNAUTHORIZED, e)
        })?
        .ok_or_else(|| {
            tracing::error!("Invalid credentials");
            ErrorResponse(StatusCode::UNAUTHORIZED, "Invalid credentials".into())
        })?;

    if !verify_password(password.clone(), hashed_password.clone()).await {
        tracing::error!("Invalid credentials");
        return Err(ErrorResponse(
            StatusCode::UNAUTHORIZED,
            "Invalid credentials".into(),
        ));
    }

    //Generate JWT and session
    let jwt_token = generate_jwt(user_id).await.map_err(|e| {
        tracing::error!("Unauthorized: {}", e);
        ErrorResponse(StatusCode::UNAUTHORIZED, e)
    })?;

    let session_id = Uuid::new_v4().to_string(); //different from the original implementation of 16-length byte random string

    update_session(
        user_id,
        Some(session_id.clone()),
        Some(jwt_token.clone()),
        &state,
    )
    .await
    .map_err(|e| {
        tracing::error!("Internal Server Error: {}", e);
        ErrorResponse(StatusCode::INTERNAL_SERVER_ERROR, e)
    })?;

    // Log the login attempt
    insert_audit_log(user_id, browser_info, &state)
        .await
        .map_err(|e| {
            tracing::error!("Internal Server Error: {}", e);
            ErrorResponse(StatusCode::INTERNAL_SERVER_ERROR, e)
        })?;

    println!(
        "User {} logged in from IP: {}, Browser: {}",
        user_id, ip_address, browser_info
    );

    Ok(Json(LoginResponse {
        user_id,
        content: username,
        session_id,
        jwt_token,
    }))
}

async fn login_by_email(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<EmailLoginPayload>,
) -> Result<Json<LoginResponse>, ErrorResponse> {
    let email = payload.email;
    let password = payload.password;

    let browser_info = headers
        .get("User-Agent")
        .ok_or_else(|| {
            //use ok_or_else because we are passing the result of a function call (headers.get())
            tracing::error!("Missing User-Agent header");
            ErrorResponse(StatusCode::BAD_REQUEST, "Missing User-Agent header".into())
        })?
        .to_str()
        .map_err(|_| {
            tracing::error!("Invalid User-Agent header");
            ErrorResponse(StatusCode::BAD_REQUEST, "Invalid User-Agent header".into())
        })?;

    let ip_address = headers
        .get("X-Forwarded-For")
        .ok_or_else(|| {
            tracing::error!("Missing X-Forwarded-For header");
            ErrorResponse(
                StatusCode::BAD_REQUEST,
                "Missing X-Forwarded-For header".into(),
            )
        })?
        .to_str()
        .map_err(|_| {
            tracing::error!("Invalid X-Forwarded-For header");
            ErrorResponse(
                StatusCode::BAD_REQUEST,
                "Invalid X-Forwarded-For header".into(),
            )
        })?;

    // unimplemented!("Validation for login data");

    let (user_id, hashed_password) = get_user_id_and_hashed_password_by_email(&email, &state)
        .await
        .map_err(|e| {
            tracing::error!("Unauthorized: {}", e);
            ErrorResponse(StatusCode::UNAUTHORIZED, e)
        })?
        .ok_or_else(|| {
            tracing::error!("Invalid credentials");
            ErrorResponse(StatusCode::UNAUTHORIZED, "Invalid credentials".into())
        })?;

    if !verify_password(password.clone(), hashed_password.clone()).await {
        tracing::error!("Invalid credentials");
        return Err(ErrorResponse(
            StatusCode::UNAUTHORIZED,
            "Invalid credentials".into(),
        ));
    }

    //Generate JWT and session
    let jwt_token = generate_jwt(user_id).await.map_err(|e| {
        tracing::error!("Unauthorized: {}", e);
        ErrorResponse(StatusCode::INTERNAL_SERVER_ERROR, e)
    })?;

    let session_id = Uuid::new_v4().to_string(); //different from the original implementation of 16-length byte random string

    update_session(
        user_id,
        Some(session_id.clone()),
        Some(jwt_token.clone()),
        &state,
    )
    .await
    .map_err(|e| {
        tracing::error!("Internal Server Error: {}", e);
        ErrorResponse(StatusCode::INTERNAL_SERVER_ERROR, e)
    })?;

    // Log the login attempt
    insert_audit_log(user_id, browser_info, &state)
        .await
        .map_err(|e| {
            tracing::error!("Internal Server Error: {}", e);
            ErrorResponse(StatusCode::INTERNAL_SERVER_ERROR, e)
        })?;

    println!(
        "User {} logged in from IP: {}, Browser: {}",
        user_id, ip_address, browser_info
    );

    Ok(Json(LoginResponse {
        user_id,
        content: email,
        session_id,
        jwt_token,
    }))
}

async fn get_user_id_and_hashed_password(
    content: &str,
    query: &str,
    state: &AppState,
) -> Result<Option<(i64, String)>, String> {
    let row = state
        .db
        .fetch_optional(sqlx::query(query).bind(content))
        .await
        .map_err(|e| format!("Failed to fetch user: {}", e))?;

    if let Some(row) = row {
        let user_id: i64 = row.get("user_id");
        let hashed_password: String = row.get("password");
        Ok(Some((user_id, hashed_password)))
    } else {
        Ok(None)
    }
}

async fn get_user_id_and_hashed_password_by_username(
    username: &str,
    state: &AppState,
) -> Result<Option<(i64, String)>, String> {
    get_user_id_and_hashed_password(
        username,
        "SELECT user_id, password FROM schema.credentials WHERE username = $1",
        state,
    )
    .await
}

async fn get_user_id_and_hashed_password_by_email(
    email: &str,
    state: &AppState,
) -> Result<Option<(i64, String)>, String> {
    get_user_id_and_hashed_password(
        email,
        "SELECT user_id, password FROM schema.credentials WHERE email = $1",
        state,
    )
    .await
}

async fn generate_jwt(user_id: i64) -> Result<String, String> {
    // let secret_key = env::var("JWT_SECRET").map_err(|_| "JWT_SECRET env var must be set")?;
    // let secret_key = secret_key.as_bytes();
    // let expiration = chrono::Utc::now()
    //     .checked_add_signed(chrono::Duration::hours(24))
    //     .ok_or("Invalid expiration time")?
    //     .timestamp();
    // let claims = Claims {
    //     sub: user_id,
    //     exp: expiration as usize,
    // };
    // encode(&Header::default(), &claims, &EncodingKey::from_secret(secret_key))
    //     .map_err(|e| format!("Failed to generate JWT: {}", e))

    let secret_token = env::var("SECRET_TOKEN").map_err(|_| "SECRET_TOKEN env var must be set")?;

    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &Claims {
            user_id,
            iat: chrono::Utc::now().timestamp() as usize,
        },
        &jsonwebtoken::EncodingKey::from_secret(secret_token.as_bytes()),
    )
    .map_err(|e| format!("Failed to generate JWT: {}", e))?;

    Ok(token)
}

async fn insert_audit_log(
    user_id: i64,
    browser_info: &str,
    state: &AppState,
) -> Result<(), String> {
    // let now = chrono::Utc::now().naive_utc();
    // let user_agent = user_agent_parser::UserAgentParser::new();
    // let parsed_ua = user_agent.parse(browser_info);

    // let browser = parsed_ua.family;
    // let os = parsed_ua.os.family;
    // let device = parsed_ua.device.family;

    // let ip_address = local_ipaddress::get().unwrap_or_else(|| "Unknown".to_string());

    // // Insert the audit log into the database
    // // Assuming you have a table named 'audit_logs' with appropriate columns
    // // Adjust the SQL query according to your actual table schema
    // // Here we just print the log for demonstration purposes

    // println!(
    //     "Audit Log - User ID: {}, IP Address: {}, Browser: {}, OS: {}, Device: {}, Timestamp: {}",
    //     user_id, ip_address, browser, os, device, now
    // );

    let now = chrono::Utc::now().naive_utc();
    let browser = browser_info.to_string();

    state
        .db
        .execute(
            sqlx::query("INSERT INTO schema.audit_trail (user_id, occured_at, browser) VALUES ($1, $2, $3) RETURNING id, user_id, occured_at, browser")
                .bind(user_id)
                .bind(now)
                .bind(browser),
        )
        .await
        .map_err(|e| format!("Failed to insert audit log: {}", e))?;

    Ok(())
}

async fn update_session(
    user_id: i64,
    session_id: Option<String>,
    jwt_token: Option<String>,
    state: &AppState,
) -> Result<(), String> {
    state
        .db
        .execute(
            sqlx::query(
                "UPDATE schema.sessions SET session_id = $1, jwt_token = $2 WHERE user_id = $3",
            )
            .bind(session_id)
            .bind(jwt_token)
            .bind(user_id),
        )
        .await
        .map_err(|e| format!("Failed to update session: {}", e))?;
    Ok(())
}

async fn verify_password(password: String, hashed_password: String) -> bool {
    let argon2 = Argon2::default();

    let parsed_hash = match PasswordHash::new(&hashed_password) {
        Ok(hash) => hash,
        Err(_) => return false,
    };

    argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

async fn logout(
    Path(user_id): Path<i32>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let result = state
        .db
        .execute(
            sqlx::query(
                "UPDATE schema.credentials SET session_id = NULL, jwt_token = NULL WHERE user_id = $1",
            )
            .bind(user_id),
        )
        .await
        .map_err(|e| {
            ErrorResponse(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to logout user: {}", e),
            )
        })?;

    if result.rows_affected() == 0 {
        return Err(ErrorResponse(
            StatusCode::NOT_FOUND,
            format!("User with id {} not found", user_id),
        ));
    }

    Ok((StatusCode::OK, "User logged out successfully"))
}

async fn audit_user(
    Path(user_id): Path<i32>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let result = state
        .db
        .fetch_all(
            sqlx::query(
                "SELECT * FROM schema.audit_trail WHERE user_id = $1 ORDER BY occured_at DESC",
            )
            .bind(user_id),
        )
        .await
        .map_err(|e| {
            ErrorResponse(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to audit user: {}", e),
            )
        })?;

    if result.is_empty() {
        return Err(ErrorResponse(
            StatusCode::NOT_FOUND,
            format!("User with id {} not found", user_id),
        ));
    }

    Ok((StatusCode::OK, "User audited successfully"))
}
