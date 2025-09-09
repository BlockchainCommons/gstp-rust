use thiserror::Error;

/// Errors that can occur in GSTP operations.
#[derive(Debug, Error)]
pub enum Error {
    /// Missing required encryption key.
    #[error("sender must have an encryption key")]
    SenderMissingEncryptionKey,

    /// Missing required encryption key for recipient.
    #[error("recipient must have an encryption key")]
    RecipientMissingEncryptionKey,

    /// Missing required verification key for sender.
    #[error("sender must have a verification key")]
    SenderMissingVerificationKey,

    /// Continuation has expired.
    #[error("continuation expired")]
    ContinuationExpired,

    /// Continuation ID is invalid.
    #[error("continuation ID invalid")]
    ContinuationIdInvalid,

    /// Peer continuation must be encrypted.
    #[error("peer continuation must be encrypted")]
    PeerContinuationNotEncrypted,

    /// Requests must contain a peer continuation.
    #[error("requests must contain a peer continuation")]
    MissingPeerContinuation,

    /// Error from bc-envelope operations.
    #[error(transparent)]
    Envelope(#[from] bc_envelope::Error),

    /// Error from bc-xid operations.
    #[error(transparent)]
    XID(#[from] bc_xid::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
