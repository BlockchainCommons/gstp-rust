use bc_components::{ARID, Encrypter, PrivateKeys};
use bc_envelope::{Signer, prelude::*};
use bc_xid::{
    XIDDocument, XIDGeneratorOptions, XIDPrivateKeyOptions, XIDSigningOptions,
};

use crate::{Continuation, Error, Result};

#[derive(Debug, Clone, PartialEq)]
pub struct SealedEvent<T>
where
    T: EnvelopeEncodable
        + TryFrom<Envelope>
        + std::fmt::Debug
        + Clone
        + PartialEq,
{
    event: Event<T>,
    sender: XIDDocument,
    // This is the continuation we're going to self-encrypt and send to the
    // peer.
    state: Option<Envelope>,
    // This is a continuation we previously received from the peer and want to
    // send back to them.
    peer_continuation: Option<Envelope>,
}

impl<T> std::fmt::Display for SealedEvent<T>
where
    T: EnvelopeEncodable
        + TryFrom<Envelope>
        + std::fmt::Debug
        + Clone
        + PartialEq,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SealedRequest({}, state: {}, peer_continuation: {})",
            self.event.summary(),
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
impl<T> SealedEvent<T>
where
    T: EnvelopeEncodable
        + TryFrom<Envelope>
        + std::fmt::Debug
        + Clone
        + PartialEq,
{
    pub fn new(
        content: impl Into<T>,
        id: ARID,
        sender: impl AsRef<XIDDocument>,
    ) -> Self {
        Self {
            event: Event::new(content, id),
            sender: sender.as_ref().clone(),
            state: None,
            peer_continuation: None,
        }
    }
}

impl<T> EventBehavior<T> for SealedEvent<T>
where
    T: EnvelopeEncodable
        + TryFrom<Envelope>
        + std::fmt::Debug
        + Clone
        + PartialEq,
{
    fn with_note(self, note: impl Into<String>) -> Self {
        Self {
            event: self.event.with_note(note),
            sender: self.sender,
            state: self.state,
            peer_continuation: self.peer_continuation,
        }
    }

    fn with_date(self, date: Date) -> Self {
        Self {
            event: self.event.with_date(date),
            sender: self.sender,
            state: self.state,
            peer_continuation: self.peer_continuation,
        }
    }

    fn content(&self) -> &T { self.event.content() }

    fn id(&self) -> ARID { self.event.id() }

    fn note(&self) -> &str { self.event.note() }

    fn date(&self) -> Option<Date> { self.event.date() }
}

pub trait SealedEventBehavior<T>: EventBehavior<T>
where
    T: EnvelopeEncodable
        + TryFrom<Envelope>
        + std::fmt::Debug
        + Clone
        + PartialEq,
{
    //
    // Composition
    //

    /// Adds state to the event that the receiver must return in the response.
    fn with_state(self, state: impl EnvelopeEncodable) -> Self;

    /// Adds state to the event that the receiver must return in the response.
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

    /// Returns the event.
    fn event(&self) -> &Event<T>;

    /// Returns the sender of the event.
    fn sender(&self) -> &XIDDocument;

    /// Returns the continuation we're going to self-encrypt and send to the
    /// recipient.
    fn state(&self) -> Option<&Envelope>;

    /// Returns the continuation we previously received from the recipient and
    /// want to send back to them.
    fn peer_continuation(&self) -> Option<&Envelope>;
}

impl<T> SealedEventBehavior<T> for SealedEvent<T>
where
    T: EnvelopeEncodable
        + TryFrom<Envelope>
        + std::fmt::Debug
        + Clone
        + PartialEq,
{
    fn with_state(mut self, state: impl EnvelopeEncodable) -> Self {
        self.state = Some(state.into_envelope());
        self
    }

    fn with_optional_state(
        mut self,
        state: Option<impl EnvelopeEncodable>,
    ) -> Self {
        if let Some(state) = state {
            self.with_state(state)
        } else {
            self.state = None;
            self
        }
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

    fn event(&self) -> &Event<T> { &self.event }

    fn sender(&self) -> &XIDDocument { &self.sender }

    fn state(&self) -> Option<&Envelope> { self.state.as_ref() }

    fn peer_continuation(&self) -> Option<&Envelope> {
        self.peer_continuation.as_ref()
    }
}

impl<T> From<SealedEvent<T>> for Event<T>
where
    T: EnvelopeEncodable
        + TryFrom<Envelope>
        + std::fmt::Debug
        + Clone
        + PartialEq,
{
    fn from(sealed_event: SealedEvent<T>) -> Self { sealed_event.event }
}

impl<T> SealedEvent<T>
where
    T: EnvelopeEncodable
        + TryFrom<Envelope>
        + std::fmt::Debug
        + Clone
        + PartialEq,
{
    /// Creates an envelope that can be decrypted by zero or one recipient.
    pub fn to_envelope(
        &self,
        valid_until: Option<Date>,
        sender: Option<&dyn Signer>,
        recipient: Option<&XIDDocument>,
    ) -> Result<Envelope> {
        let recipients: Vec<&XIDDocument> = recipient.into_iter().collect();
        self.to_envelope_for_recipients(valid_until, sender, &recipients)
    }

    /// Creates an envelope that can be decrypted by zero or more recipients.
    pub fn to_envelope_for_recipients(
        &self,
        valid_until: Option<Date>,
        sender: Option<&dyn Signer>,
        recipients: &[&XIDDocument],
    ) -> Result<Envelope> {
        let sender_encryption_key = self
            .sender
            .encryption_key()
            .ok_or(Error::SenderMissingEncryptionKey)?;
        let sender_continuation: Option<Envelope> =
            if let Some(state) = &self.state {
                Some(
                    Continuation::new(state.clone())
                        .with_optional_valid_until(valid_until)
                        .to_envelope(Some(sender_encryption_key)),
                )
            } else {
                valid_until.map(|valid_until| {
                    Continuation::new(Envelope::null())
                        .with_valid_until(valid_until)
                        .to_envelope(Some(sender_encryption_key))
                })
            };

        let mut result = self
            .event
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
            .add_optional_assertion(
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

        if !recipients.is_empty() {
            let recipient_keys = recipients
                .iter()
                .map(|recipient| {
                    recipient
                        .encryption_key()
                        .ok_or(Error::RecipientMissingEncryptionKey)
                        .map(|key| key as &dyn Encrypter)
                })
                .collect::<Result<Vec<&dyn Encrypter>>>()?;
            result = result
                .wrap()
                .encrypt_subject_to_recipients(&recipient_keys)?;
        }

        Ok(result)
    }

    pub fn try_from_envelope(
        encrypted_envelope: &Envelope,
        expected_id: Option<ARID>,
        now: Option<Date>,
        recipient_private_key: &PrivateKeys,
    ) -> Result<Self> {
        let signed_envelope =
            encrypted_envelope.decrypt_to_recipient(recipient_private_key)?;
        let sender: XIDDocument = signed_envelope
            .try_unwrap()?
            .object_for_predicate(known_values::SENDER)?
            .try_into()?;
        let sender_verification_key = sender
            .verification_key()
            .ok_or(Error::SenderMissingVerificationKey)?;
        let event_envelope = signed_envelope.verify(sender_verification_key)?;
        let peer_continuation = event_envelope
            .optional_object_for_predicate(known_values::SENDER_CONTINUATION)?;
        if let Some(some_peer_continuation) = peer_continuation.clone()
            && !some_peer_continuation.subject().is_encrypted()
        {
            return Err(Error::PeerContinuationNotEncrypted);
        }
        let encrypted_continuation = event_envelope
            .optional_object_for_predicate(
                known_values::RECIPIENT_CONTINUATION,
            )?;
        let state: Option<Envelope>;
        if let Some(encrypted_continuation) = encrypted_continuation {
            let continuation = Continuation::try_from_envelope(
                &encrypted_continuation,
                expected_id,
                now,
                Some(recipient_private_key),
            )?;
            state = Some(continuation.state().clone());
        } else {
            state = None;
        }
        let event = Event::<T>::try_from(event_envelope)?;
        Ok(Self { event, sender, state, peer_continuation })
    }
}
