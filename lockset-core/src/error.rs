#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    Refused(String),
    #[error("{0}")]
    Failed(String),
    /// A mutation stopped part-way and could not be fully undone. Never a
    /// success: the caller reports the files and the recovery step.
    #[error("{0}")]
    Partial(String),
}

impl Error {
    pub fn invalid(msg: impl Into<String>) -> Self {
        Self::Invalid(msg.into())
    }
    pub fn refused(msg: impl Into<String>) -> Self {
        Self::Refused(msg.into())
    }
    pub fn failed(msg: impl Into<String>) -> Self {
        Self::Failed(msg.into())
    }
    pub fn partial(msg: impl Into<String>) -> Self {
        Self::Partial(msg.into())
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
