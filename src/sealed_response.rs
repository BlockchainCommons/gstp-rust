use anyhow::{ bail, Result };
use bc_components::{ PrivateKeys, ARID };
use bc_xid::XIDDocument;
use dcbor::{ prelude::*, Date };
use bc_envelope::{prelude::*, Signer};

use super::Continuation;

#[derive(Debug, Clone, PartialEq)]
pub struct SealedResponse {
    response: Response,
    sender: XIDDocument,
    // This is the continuation we're going to self-encrypt and send to the peer.
    state: Option<Envelope>,
    // This is a continuation we previously received from the peer and want to send back to them.
    peer_continuation: Option<Envelope>,
}

impl std::fmt::Display for SealedResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SealedResponse({}, state: {}, peer_continuation: {})",
            self.response.summary(),
            self.state.as_ref().map_or("None".to_string(), |state| state.format_flat()),
            self.peer_continuation.clone().map_or_else(
                || "None".to_string(),
                |_| "Some".to_string()
            )
        )
    }
}

impl SealedResponse {
    //
    // Success Composition
    //

    pub fn new_success(id: ARID, sender: impl AsRef<XIDDocument>) -> Self {
        Self {
            response: Response::new_success(id),
            sender: sender.as_ref().clone(),
            state: None,
            peer_continuation: None,
        }
    }

    //
    // Failure Composition
    //

    pub fn new_failure(id: ARID, sender: impl AsRef<XIDDocument>) -> Self {
        Self {
            response: Response::new_failure(id),
            sender: sender.as_ref().clone(),
            state: None,
            peer_continuation: None,
        }
    }

    /// An early failure takes place before the message has been decrypted,
    /// and therefore the ID and sender public key are not known.
    pub fn new_early_failure(sender: impl AsRef<XIDDocument>) -> Self {
        Self {
            response: Response::new_early_failure(),
            sender: sender.as_ref().clone(),
            state: None,
            peer_continuation: None,
        }
    }
}

pub trait SealedResponseBehavior: ResponseBehavior {
    //
    // Composition
    //

    /// Adds state to the request that the peer may return at some future time.
    fn with_state(self, state: impl EnvelopeEncodable) -> Self;

    fn with_optional_state(self, state: Option<impl EnvelopeEncodable>) -> Self;

    /// Adds a continuation we previously received from the recipient and want to send back to them.
    fn with_peer_continuation(self, peer_continuation: Option<&Envelope>) -> Self;

    //
    // Parsing
    //

    fn sender(&self) -> &XIDDocument;

    fn state(&self) -> Option<&Envelope>;

    fn peer_continuation(&self) -> Option<&Envelope>;
}

impl SealedResponseBehavior for SealedResponse {
    //
    // Composition
    //

    /// Adds state to the request that the peer may return at some future time.
    fn with_state(mut self, state: impl EnvelopeEncodable) -> Self {
        if self.response.is_ok() {
            self.state = Some(state.into_envelope());
        } else {
            panic!("Cannot set state on a failed response");
        }
        self
    }

    fn with_optional_state(mut self, state: Option<impl EnvelopeEncodable>) -> Self {
        if let Some(state) = state {
            self.with_state(state)
        } else {
            self.state = None;
            self
        }
    }

    /// Adds a continuation we previously received from the recipient and want to send back to them.
    fn with_peer_continuation(mut self, peer_continuation: Option<&Envelope>) -> Self {
        self.peer_continuation = peer_continuation.cloned();
        self
    }

    //
    // Parsing
    //

    fn sender(&self) -> &XIDDocument {
        self.sender.as_ref()
    }

    fn state(&self) -> Option<&Envelope> {
        self.state.as_ref()
    }

    fn peer_continuation(&self) -> Option<&Envelope> {
        self.peer_continuation.as_ref()
    }
}

impl ResponseBehavior for SealedResponse {
    fn with_result(mut self, result: impl EnvelopeEncodable) -> Self {
        self.response = self.response.with_result(result);
        self
    }

    /// If the result is `None`, the value of the response will be the null envelope.
    fn with_optional_result(mut self, result: Option<impl EnvelopeEncodable>) -> Self {
        self.response = self.response.with_optional_result(result);
        self
    }

    /// If no error is provided, the value of the response will be the unknown value.
    fn with_error(mut self, error: impl EnvelopeEncodable) -> Self {
        self.response = self.response.with_error(error);
        self
    }

    /// If the error is `None`, the value of the response will be the unknown value.
    fn with_optional_error(mut self, error: Option<impl EnvelopeEncodable>) -> Self {
        self.response = self.response.with_optional_error(error);
        self
    }

    fn is_ok(&self) -> bool {
        self.response.is_ok()
    }

    fn is_err(&self) -> bool {
        self.response.is_err()
    }

    fn ok(&self) -> Option<&(ARID, Envelope)> {
        self.response.ok()
    }

    fn err(&self) -> Option<&(Option<ARID>, Envelope)> {
        self.response.err()
    }

    fn id(&self) -> Option<ARID> {
        self.response.id()
    }

    fn expect_id(&self) -> ARID {
        self.response.expect_id()
    }

    fn result(&self) -> Result<&Envelope> {
        self.response.result()
    }

    fn extract_result<T>(&self) -> Result<T> where T: TryFrom<CBOR, Error = dcbor::Error> + 'static {
        self.response.extract_result()
    }

    fn error(&self) -> Result<&Envelope> {
        self.response.error()
    }

    fn extract_error<T>(&self) -> Result<T> where T: TryFrom<CBOR, Error = dcbor::Error> + 'static {
        self.response.extract_error()
    }
}

impl SealedResponse {
    pub fn to_envelope(
        &self,
        valid_until: Option<&Date>,
        sender: Option<&dyn Signer>,
        recipient: Option<&XIDDocument>
    ) -> Result<Envelope> {
        let sender_continuation: Option<Envelope>;
        if let Some(state) = &self.state {
            let continuation = Continuation::new(state).with_optional_valid_until(valid_until);
            let sender_encryption_key = self.sender.encryption_key()
                .ok_or_else(|| anyhow::anyhow!("Sender must have an encryption key"))?;
            sender_continuation = Some(continuation.to_envelope(Some(sender_encryption_key)));
        } else {
            sender_continuation = None;
        }

        let mut result = self.response
            .clone()
            .into_envelope()
            .add_assertion(known_values::SENDER, self.sender.to_envelope())
            .add_optional_assertion(known_values::SENDER_CONTINUATION, sender_continuation)
            .add_optional_assertion(
                known_values::RECIPIENT_CONTINUATION,
                self.peer_continuation.clone()
            );

        if let Some(sender_private_key) = sender {
            result = result.sign(sender_private_key);
        }

        if let Some(recipient) = recipient {
            let recipient_encryption_key = recipient.encryption_key()
                .ok_or_else(|| anyhow::anyhow!("Recipient must have an encryption key"))?;
            result = result.encrypt_to_recipient(recipient_encryption_key);
        }

        Ok(result)
    }

    pub fn try_from_encrypted_envelope(
        encrypted_envelope: &Envelope,
        expected_id: Option<ARID>,
        now: Option<&Date>,
        recipient_private_key: &PrivateKeys
    ) -> Result<Self> {
        let signed_envelope = encrypted_envelope.decrypt_to_recipient(recipient_private_key)?;
        let sender: XIDDocument = signed_envelope
            .unwrap_envelope()?
            .object_for_predicate(known_values::SENDER)?
            .try_into()?;
        let sender_verification_key = sender.verification_key()
            .ok_or_else(|| anyhow::anyhow!("Sender must have a verification key"))?;
        let response_envelope = signed_envelope.verify(sender_verification_key)?;
        let peer_continuation = response_envelope.optional_object_for_predicate(
            known_values::SENDER_CONTINUATION
        )?;
        if let Some(some_peer_continuation) = peer_continuation.clone() {
            if !some_peer_continuation.subject().is_encrypted() {
                bail!("Peer continuation must be encrypted");
            }
        }
        let encrypted_continuation = response_envelope.optional_object_for_predicate(
            known_values::RECIPIENT_CONTINUATION
        )?;
        let state: Option<Envelope>;
        if let Some(encrypted_continuation) = encrypted_continuation {
            let continuation = Continuation::try_from_envelope(
                &encrypted_continuation,
                expected_id,
                now,
                Some(recipient_private_key),
            )?;
            if continuation.state().is_null() {
                state = None;
            } else {
                state = Some(continuation.state().clone());
            }
        } else {
            state = None;
        }
        let response = Response::try_from(response_envelope)?;
        Ok(Self {
            response,
            sender,
            state,
            peer_continuation,
        })
    }
}
