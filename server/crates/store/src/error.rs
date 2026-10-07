use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("core error: {0}")]
    Core(#[from] p2pnas_core::CoreError),
    #[error("not found")]
    NotFound,
    #[error("integrity error: {0}")]
    Integrity(String),
    #[error("invalid fragment id")]
    InvalidFragmentId,
}

pub type Result<T> = std::result::Result<T, StoreError>;
