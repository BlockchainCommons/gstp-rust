use bc_components::{ARID, PrivateKeys};
use bc_envelope::{Signer, prelude::*};
use bc_xid::{
    XIDGeneratorOptions, XIDPrivateKeyOptions, XIDDocument, XIDSigningOptions,
};

use crate::{Continuation, Error, Result};

#[derive(Debug, Clone, PartialEq)]
pub struct SealedRequest {
    request: Request,
    sender: XIDDocument,
    // This is the continuation we're going to self-encrypt and send to the
    // peer.
    state: Option<Envelope>,
    // This is a continuation we previously received from the peer and want to
    // send back to them.
    peer_continuation: Option<Envelope>,
}

impl std::fmt::Display for SealedRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SealedRequest({}, state: {}, peer_continuation: {})",
            self.request.summary(),
            self.state.clone().map_or_else(
                || "None".to_string(),
                |state| state.format_flat()
            ),
            self.peer_continuation
                .clone()
                .map_or_else(|| "None".to_string(), |_| "Some".to_string())
        )
    }
}

//
// Composition
//
impl SealedRequest {
    pub fn new(
        function: impl Into<Function>,
        id: ARID,
        sender: impl AsRef<XIDDocument>,
    ) -> Self {
        Self {
            request: Request::new(function, id),
            sender: sender.as_ref().clone(),
            state: None,
            peer_continuation: None,
        }
    }

    pub fn new_with_body(
        body: Expression,
        id: ARID,
        sender: impl AsRef<XIDDocument>,
    ) -> Self {
        Self {
            request: Request::new_with_body(body, id),
            sender: sender.as_ref().clone(),
            state: None,
            peer_continuation: None,
        }
    }
}

impl ExpressionBehavior for SealedRequest {
    fn with_parameter(
        mut self,
        parameter: impl Into<Parameter>,
        value: impl EnvelopeEncodable,
    ) -> Self {
        self.request = self.request.with_parameter(parameter, value);
        self
    }

    fn with_optional_parameter(
        mut self,
        parameter: impl Into<Parameter>,
        value: Option<impl EnvelopeEncodable>,
    ) -> Self {
        self.request = self.request.with_optional_parameter(parameter, value);
        self
    }

    fn function(&self) -> &Function {
        self.request.function()
    }

    fn expression_envelope(&self) -> &Envelope {
        self.request.expression_envelope()
    }

    fn object_for_parameter(
        &self,
        param: impl Into<Parameter>,
    ) -> bc_envelope::Result<Envelope> {
        self.request.body().object_for_parameter(param)
    }

    fn objects_for_parameter(
        &self,
        param: impl Into<Parameter>,
    ) -> Vec<Envelope> {
        self.request.body().objects_for_parameter(param)
    }

    fn extract_object_for_parameter<T>(
        &self,
        param: impl Into<Parameter>,
    ) -> bc_envelope::Result<T>
    where
        T: TryFrom<CBOR, Error = dcbor::Error> + 'static,
    {
        self.request.body().extract_object_for_parameter(param)
    }

    fn extract_optional_object_for_parameter<
        T: TryFrom<CBOR, Error = dcbor::Error> + 'static,
    >(
        &self,
        param: impl Into<Parameter>,
    ) -> bc_envelope::Result<Option<T>> {
        self.request
            .body()
            .extract_optional_object_for_parameter(param)
    }

    fn extract_objects_for_parameter<T>(
        &self,
        param: impl Into<Parameter>,
    ) -> bc_envelope::Result<Vec<T>>
    where
        T: TryFrom<CBOR, Error = dcbor::Error> + 'static,
    {
        self.request.body().extract_objects_for_parameter(param)
    }
}

impl RequestBehavior for SealedRequest {
    fn with_note(mut self, note: impl Into<String>) -> Self {
        self.request = self.request.with_note(note);
        self
    }

    fn with_date(mut self, date: impl AsRef<Date>) -> Self {
        self.request = self.request.with_date(date);
        self
    }

    fn body(&self) -> &Expression {
        self.request.body()
    }

    fn id(&self) -> ARID {
        self.request.id()
    }

    fn note(&self) -> &str {
        self.request.note()
    }

    fn date(&self) -> Option<&Date> {
        self.request.date()
    }
}

pub trait SealedRequestBehavior: RequestBehavior {
    //
    // Composition
    //

    /// Adds state to the request that the receiver must return in the response.
    fn with_state(self, state: impl EnvelopeEncodable) -> Self;

    /// Adds state to the request that the receiver must return in the response.
    fn with_optional_state(self, state: Option<impl EnvelopeEncodable>)
    -> Self;

    /// Adds a continuation we previously received from the recipient and want
    /// to send back to them.
    fn with_peer_continuation(self, peer_continuation: Envelope) -> Self;

    /// Adds a continuation we previously received from the recipient and want
    /// to send back to them.
    fn with_optional_peer_continuation(
        self,
        peer_continuation: Option<Envelope>,
    ) -> Self;

    //
    // Parsing
    //

    /// Returns the request.
    fn request(&self) -> &Request;

    /// Returns the sender of the request.
    fn sender(&self) -> &XIDDocument;

    /// Returns the continuation we're going to self-encrypt and send to the
    /// recipient.
    fn state(&self) -> Option<&Envelope>;

    /// Returns the continuation we previously received from the recipient and
    /// want to send back to them.
    fn peer_continuation(&self) -> Option<&Envelope>;
}

impl SealedRequestBehavior for SealedRequest {
    fn with_state(mut self, state: impl EnvelopeEncodable) -> Self {
        self.state = Some(state.into_envelope());
        self
    }

    fn with_optional_state(
        mut self,
        state: Option<impl EnvelopeEncodable>,
    ) -> Self {
        self.state = state.map(|state| state.into_envelope());
        self
    }

    fn with_peer_continuation(mut self, peer_continuation: Envelope) -> Self {
        self.peer_continuation = Some(peer_continuation);
        self
    }

    fn with_optional_peer_continuation(
        mut self,
        peer_continuation: Option<Envelope>,
    ) -> Self {
        self.peer_continuation = peer_continuation;
        self
    }

    fn request(&self) -> &Request {
        &self.request
    }

    fn sender(&self) -> &XIDDocument {
        &self.sender
    }

    fn state(&self) -> Option<&Envelope> {
        self.state.as_ref()
    }

    fn peer_continuation(&self) -> Option<&Envelope> {
        self.peer_continuation.as_ref()
    }
}

impl From<SealedRequest> for Request {
    fn from(sealed_request: SealedRequest) -> Self {
        sealed_request.request
    }
}

impl From<SealedRequest> for Expression {
    fn from(sealed_request: SealedRequest) -> Self {
        sealed_request.request.into()
    }
}

impl SealedRequest {
    pub fn to_envelope(
        &self,
        valid_until: Option<&Date>,
        sender: Option<&dyn Signer>,
        recipient: Option<&XIDDocument>,
    ) -> Result<Envelope> {
        // Even if no state is provided, requests always include a continuation
        // that at least specifies the required valid response ID.
        let state = self.state.clone().unwrap_or(Envelope::null());
        let continuation = Continuation::new(state)
            .with_valid_id(self.id())
            .with_optional_valid_until(valid_until);
        let sender_encryption_key = self
            .sender
            .encryption_key()
            .ok_or(Error::SenderMissingEncryptionKey)?;
        let sender_continuation =
            continuation.to_envelope(Some(sender_encryption_key));

        let mut result = self
            .request
            .clone()
            .into_envelope()
            .add_assertion(
                known_values::SENDER,
                self.sender
                    .to_envelope(
                        XIDPrivateKeyOptions::default(),
                        XIDGeneratorOptions::default(),
                        XIDSigningOptions::default(),
                    )
                    .unwrap(),
            )
            .add_assertion(
                known_values::SENDER_CONTINUATION,
                sender_continuation,
            )
            .add_optional_assertion(
                known_values::RECIPIENT_CONTINUATION,
                self.peer_continuation.clone(),
            );

        if let Some(sender_private_key) = sender {
            result = result.sign(sender_private_key);
        }

        if let Some(recipient) = recipient {
            let recipient_encryption_key = recipient
                .encryption_key()
                .ok_or(Error::RecipientMissingEncryptionKey)?;

            result = result.encrypt_to_recipient(recipient_encryption_key);
        }

        Ok(result)
    }

    pub fn try_from_envelope(
        encrypted_envelope: &Envelope,
        id: Option<ARID>,
        now: Option<&Date>,
        recipient: &PrivateKeys,
    ) -> Result<Self> {
        let signed_envelope =
            encrypted_envelope.decrypt_to_recipient(recipient)?;
        let sender: XIDDocument = signed_envelope
            .try_unwrap()?
            .object_for_predicate(known_values::SENDER)?
            .try_into()?;
        let sender_verification_key = sender
            .verification_key()
            .ok_or(Error::SenderMissingVerificationKey)?;
        let request_envelope =
            signed_envelope.verify(sender_verification_key)?;
        let peer_continuation = request_envelope
            .optional_object_for_predicate(known_values::SENDER_CONTINUATION)?;
        if let Some(some_peer_continuation) = peer_continuation.clone() {
            if !some_peer_continuation.subject().is_encrypted() {
                return Err(Error::PeerContinuationNotEncrypted);
            }
        } else {
            return Err(Error::MissingPeerContinuation);
        }
        let encrypted_continuation = request_envelope
            .optional_object_for_predicate(
                known_values::RECIPIENT_CONTINUATION,
            )?;
        let state: Option<Envelope>;
        if let Some(encrypted_continuation) = encrypted_continuation {
            let continuation = Continuation::try_from_envelope(
                &encrypted_continuation,
                id,
                now,
                Some(recipient),
            )?;
            state = Some(continuation.state().clone());
        } else {
            state = None;
        }
        let request = Request::try_from(request_envelope)?;
        Ok(Self { request, sender, state, peer_continuation })
    }
}
