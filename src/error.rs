pub type Result<T> = std::result::Result<T, FlossError>;

#[derive(thiserror::Error, Debug)]
pub enum FlossError {
    #[error("{0}")]
    WorkspaceLoadError(String),
    #[error("{0}")]
    InvalidResultsFile(String),
    #[error("{0}")]
    InvalidLoadConfig(String),
    #[error("Unexpected architecture: {0}")]
    UnexpectedArchitecture(i32),
    #[error("Stack size too big: {0}")]
    StackSizeTooBig(i32),
    #[error("{0}")]
    InvalidAddress(String),
    #[error("{0}")]
    IOError(#[from] std::io::Error),
    #[error("{0}")]
    GoblinError(#[from] goblin::error::Error),
    #[error("Could not find the stack segment")]
    StackSegmentNotFound,
    #[error("Could not find the signatures directory")]
    MissingSignatures
}
