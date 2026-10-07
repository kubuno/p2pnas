use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum P2pError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("not found")]
    NotFound,
    #[error("invalid request: {0}")]
    BadRequest(String),
    #[error("database error")]
    Db(#[from] sqlx::Error),
    #[error("storage error")]
    Store(#[from] p2pnas_store::StoreError),
}

impl IntoResponse for P2pError {
    fn into_response(self) -> Response {
        let (status, msg) = match &self {
            P2pError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".to_string()),
            P2pError::Forbidden => (StatusCode::FORBIDDEN, "forbidden".to_string()),
            P2pError::NotFound => (StatusCode::NOT_FOUND, "not found".to_string()),
            P2pError::BadRequest(m) => (StatusCode::BAD_REQUEST, m.clone()),
            P2pError::Db(e) => {
                // Never leak SQL details to the client; log them instead.
                tracing::error!(error = %e, "database error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string())
            }
            P2pError::Store(p2pnas_store::StoreError::NotFound) => {
                (StatusCode::NOT_FOUND, "not found".to_string())
            }
            P2pError::Store(e) => {
                tracing::error!(error = %e, "storage error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string())
            }
        };
        (status, Json(json!({ "error": msg }))).into_response()
    }
}

pub type Result<T> = std::result::Result<T, P2pError>;
