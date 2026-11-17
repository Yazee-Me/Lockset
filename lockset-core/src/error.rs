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
    /// Input changed, or another process holds the repository: nothing was
    /// written and the command can be retried.
    #[error("{0}")]
    Conflict(String),
    /// There is no usable identity, or the custody store failed or refused.
    #[error("{0}")]
    Custody(String),
    /// An external tool (sops) failed.
    #[error("{0}")]
    Tool(String),
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
    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::Conflict(msg.into())
    }
    pub fn custody(msg: impl Into<String>) -> Self {
        Self::Custody(msg.into())
    }
    pub fn tool(msg: impl Into<String>) -> Self {
        Self::Tool(msg.into())
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
