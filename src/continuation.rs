use dcbor::Date;
use bc_components::{Encrypter, PrivateKeyBase, ARID};
use bc_envelope::prelude::*;
use anyhow::{bail, Result};

#[derive(Clone, Debug)]
pub struct Continuation {
    state: Envelope,
    valid_id: Option<ARID>,
    valid_until: Option<Date>,
}

impl PartialEq for Continuation {
    fn eq(&self, other: &Self) -> bool {
        self.state == other.state
            && self.valid_id == other.valid_id
            && self.valid_until == other.valid_until
    }
}

//
// Composition
//
impl Continuation {
    pub fn new(state: impl EnvelopeEncodable) -> Self {
        Self {
            state: state.into_envelope(),
            valid_id: None,
            valid_until: None,
        }
    }

    pub fn with_valid_id(mut self, valid_id: impl AsRef<ARID>) -> Self {
        self.valid_id = Some(valid_id.as_ref().clone());
        self
    }

    pub fn with_optional_valid_id(self, valid_id: Option<impl AsRef<ARID>>) -> Self {
        if let Some(valid_id) = valid_id {
            return self.with_valid_id(valid_id);
        }
        self
    }

    pub fn with_valid_until(mut self, valid_until: impl AsRef<Date>) -> Self {
        self.valid_until = Some(valid_until.as_ref().clone());
        self
    }

    pub fn with_optional_valid_until(self, valid_until: Option<impl AsRef<Date>>) -> Self {
        if let Some(valid_until) = valid_until {
            return self.with_valid_until(valid_until);
        }
        self
    }

    pub fn with_valid_duration(self, duration: std::time::Duration) -> Self {
        self.with_valid_until(Date::now() + duration)
    }
}

//
// Parsing
//
impl Continuation {
    pub fn state(&self) -> &Envelope {
        &self.state
    }

    pub fn id(&self) -> Option<&ARID> {
        self.valid_id.as_ref()
    }

    pub fn valid_until(&self) -> Option<&Date> {
        self.valid_until.as_ref()
    }

    pub fn is_valid_date(&self, now: Option<&Date>) -> bool {
        match now {
            Some(now) => self.valid_until().map_or(true, |valid_until| valid_until > now),
            None => true,
        }
    }

    pub fn is_valid_id(&self, id: Option<&ARID>) -> bool {
        match id {
            Some(expected_id) => self.valid_id.as_ref().map_or(true, |id| id == expected_id),
            None => true,
        }
    }

    pub fn is_valid(&self, now: Option<&Date>, id: Option<&ARID>) -> bool {
        self.is_valid_date(now) && self.is_valid_id(id)
    }
}

impl Continuation {
    pub fn to_envelope(&self, sender_encryption_key: Option<&dyn Encrypter>) -> Envelope {
        let mut result = self.state
            .wrap_envelope()
            .add_optional_assertion(known_values::ID, self.valid_id.clone())
            .add_optional_assertion(known_values::VALID_UNTIL, self.valid_until.clone());

        if let Some(sender) = sender_encryption_key {
            result = result.encrypt_to_recipient(sender);
        }

        result
    }

    pub fn try_from_envelope(encrypted_envelope: &Envelope, id: Option<&ARID>, now: Option<&Date>, recipient: Option<&PrivateKeyBase>) -> Result<Self> {
        let envelope = if let Some(recipient) = recipient {
            encrypted_envelope.decrypt_to_recipient(recipient)?
        } else {
            encrypted_envelope.clone()
        };
        let continuation = Self {
            state: envelope.unwrap_envelope()?,
            valid_id: envelope.extract_optional_object_for_predicate(known_values::ID)?,
            valid_until: envelope.extract_optional_object_for_predicate(known_values::VALID_UNTIL)?,
        };
        if !continuation.is_valid_date(now) {
            bail!("Continuation expired");
        }
        if !continuation.is_valid_id(id) {
            bail!("Continuation ID invalid");
        }
        Ok(continuation)
    }
}
