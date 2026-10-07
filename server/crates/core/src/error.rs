use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("crypto error: {0}")]
    Crypto(&'static str),
    #[error("compression error: {0}")]
    Compression(String),
    #[error("erasure coding error: {0}")]
    Erasure(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
