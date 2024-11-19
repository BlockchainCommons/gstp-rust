mod continuation;
pub use continuation::Continuation;
mod sealed_request;
pub use sealed_request::{SealedRequest, SealedRequestBehavior};
mod sealed_response;
pub use sealed_response::{SealedResponse, SealedResponseBehavior};

pub mod prelude;


#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use anyhow::Result;
    use bc_components::{PrivateKeyBase, ARID};
    use dcbor::Date;
    use hex_literal::hex;
    use indoc::indoc;
    use std::time::Duration;
    use bc_envelope::prelude::*;

    fn request_id() -> ARID {
        ARID::from_data(hex!("c66be27dbad7cd095ca77647406d07976dc0f35f0d4d654bb0e96dd227a1e9fc"))
    }

    fn request_date() -> Date {
        Date::try_from("2024-07-04T11:11:11Z").unwrap()
    }

    fn request_continuation() -> Continuation {
        let valid_duration = Duration::from_secs(60);
        let valid_until = request_date() + valid_duration;
        Continuation::new("The state of things.")
            .with_valid_id(request_id())
            .with_valid_until(valid_until)
    }

    fn response_continuation() -> Continuation {
        let valid_duration = Duration::from_secs(60 * 60);
        let valid_until = request_date() + valid_duration;
        Continuation::new("The state of things.")
            .with_valid_until(valid_until)
    }

    #[test]
    fn test_request_continuation() -> Result<()> {
        bc_envelope::register_tags();

        let continuation = request_continuation();
        let envelope = continuation.to_envelope(None);

        // println!("{}", envelope.format());
        assert_eq!(envelope.format(), indoc!{r#"
            {
                "The state of things."
            } [
                'id': ARID(c66be27d)
                'validUntil': 2024-07-04T11:12:11Z
            ]
        "#}.trim());

        let parsed_continuation = Continuation::try_from_envelope(&envelope, Some(&request_id()), None, None)?;
        assert_eq!(continuation.state(), parsed_continuation.state());
        assert_eq!(continuation.id(), parsed_continuation.id());
        assert_eq!(continuation.valid_until(), parsed_continuation.valid_until());
        assert_eq!(continuation, parsed_continuation);

        Ok(())
    }

    #[test]
    fn test_response_continuation() -> Result<()> {
        bc_envelope::register_tags();

        let continuation = response_continuation();
        let envelope = continuation.to_envelope(None);

        // println!("{}", envelope.format());
        assert_eq!(envelope.format(), indoc!{r#"
            {
                "The state of things."
            } [
                'validUntil': 2024-07-04T12:11:11Z
            ]
        "#}.trim());

        let parsed_continuation = Continuation::try_from_envelope(&envelope, None, None, None)?;
        assert_eq!(continuation.state(), parsed_continuation.state());
        assert_eq!(continuation.id(), parsed_continuation.id());
        assert_eq!(continuation.valid_until(), parsed_continuation.valid_until());
        assert_eq!(continuation, parsed_continuation);

        Ok(())
    }

    #[test]
    fn test_encrypted_continuation() -> Result<()> {
        bc_envelope::register_tags();

        let sender_private_key = PrivateKeyBase::new();
        let sender_public_key = sender_private_key.schnorr_public_key_base();

        let continuation = request_continuation();
        let envelope = continuation.to_envelope(Some(&sender_public_key));

        // println!("{}", envelope.format());
        assert_eq!(envelope.format(), indoc!{r#"
            ENCRYPTED [
                'hasRecipient': SealedMessage
            ]
        "#}.trim());

        let valid_now = Some(request_date() + Duration::from_secs(30));
        let parsed_continuation = Continuation::try_from_envelope(&envelope, Some(&request_id()), valid_now.as_ref(), Some(&sender_private_key))?;
        assert_eq!(continuation.state(), parsed_continuation.state());
        assert_eq!(continuation.id(), parsed_continuation.id());
        assert_eq!(continuation.valid_until(), parsed_continuation.valid_until());
        assert_eq!(continuation, parsed_continuation);

        let invalid_now = Some(request_date() + Duration::from_secs(90));
        let invalid_continuation_error = Continuation::try_from_envelope(&envelope, Some(&request_id()), invalid_now.as_ref(), Some(&sender_private_key));
        assert!(invalid_continuation_error.is_err());

        let invalid_id = ARID::new();
        let invalid_continuation_error = Continuation::try_from_envelope(&envelope, Some(&invalid_id), valid_now.as_ref(), Some(&sender_private_key));
        assert!(invalid_continuation_error.is_err());

        Ok(())
    }

    #[test]
    fn test_sealed_request() -> Result<()> {
        bc_envelope::register_tags();

        //
        // Generate keypairs for the server and client.
        //

        let server_private_key = PrivateKeyBase::new();
        let server_public_key = server_private_key.schnorr_public_key_base();

        let client_private_key = PrivateKeyBase::new();
        let client_public_key = client_private_key.schnorr_public_key_base();

        let now = Date::try_from("2024-07-04T11:11:11Z")?;

        //
        // The server has previously sent the client this continuation. To the
        // client, it is just an encrypted envelope and cannot be read or
        // modified; it can only be sent back to the server.
        //

        // The server sent this response 30 seconds ago.
        let server_response_date = now.clone() - Duration::from_secs(30);
        // And its continuation is valid for 60 seconds.
        let server_continuation_valid_until = server_response_date + Duration::from_secs(60);
        let server_state = Expression::new("nextPage")
            .with_parameter("fromRecord", 100)
            .with_parameter("toRecord", 199);
        // Normally you'll never need to compose a `Continuation` struct directly.
        // It is indirectly constructed using the `state` attribute of a `SealedRequest`
        // or `SealedResponse` struct.
        let server_continuation = Continuation::new(server_state).with_valid_until(
            server_continuation_valid_until
        );
        let server_continuation = server_continuation.to_envelope(Some(&server_public_key));

        //
        // The client composes a request to the server, returning to it the
        // continuation the server previously sent. The client is also going to
        // include its own continuation ("state"), which the server will return
        // in its response.
        //

        // The client's continuation is valid for 60 seconds from now.
        let client_continuation_valid_until = now.clone() + Duration::from_secs(60);
        let client_request = SealedRequest::new("test", request_id(), &client_public_key)
            .with_parameter("param1", 42)
            .with_parameter("param2", "hello")
            .with_note("This is a test")
            .with_date(&now)
            .with_state("The state of things.")
            .with_peer_continuation(server_continuation);

        //
        // We examine the form of the request envelope after it is signed by the
        // client, but before it is encrypted to the server. In production you
        // would skip this and go straight to the next step.
        //

        let signed_client_request_envelope = client_request.to_envelope(
            Some(&client_continuation_valid_until),
            Some(&client_private_key),
            None,
        );
        // println!("{}", envelope.format());
        assert_eq!(signed_client_request_envelope.format(), (indoc! {r#"
            {
                request(ARID(c66be27d)) [
                    'body': «"test"» [
                        ❰"param1"❱: 42
                        ❰"param2"❱: "hello"
                    ]
                    'date': 2024-07-04T11:11:11Z
                    'note': "This is a test"
                    'recipientContinuation': ENCRYPTED [
                        'hasRecipient': SealedMessage
                    ]
                    'sender': PublicKeyBase
                    'senderContinuation': ENCRYPTED [
                        'hasRecipient': SealedMessage
                    ]
                ]
            } [
                'signed': Signature
            ]
        "#}).trim()
        );

        //
        // Create the ready-to-send request envelope, signed by the client and
        // encrypted to the server.
        //

        let sealed_client_request_envelope = client_request.to_envelope(
            Some(&client_continuation_valid_until),
            Some(&client_private_key),
            Some(&server_public_key),
        );

        //
        // The server receives and parses the envelope. No expected ID is
        // provided because the server didn't know what the client's request ID
        // would be. The current date is provided so that the server can check that
        // any returned continuation has not expired.
        //

        let parsed_client_request = SealedRequest::try_from_envelope(
            &sealed_client_request_envelope,
            None,
            Some(&now),
            &server_private_key,
        )?;
        assert_eq!(*parsed_client_request.function(), Into::<Function>::into("test"));
        assert_eq!(parsed_client_request.extract_object_for_parameter::<i32>("param1")?, 42);
        assert_eq!(
            parsed_client_request.extract_object_for_parameter::<String>("param2")?,
            "hello"
        );
        assert_eq!(parsed_client_request.note(), "This is a test");
        assert_eq!(parsed_client_request.date(), Some(&now));

        //
        // The server can now use the continuation state amd execute the request.
        //

        let state = parsed_client_request.state().unwrap();
        // println!("{}", state.format());
        assert_eq!(state.format(), (indoc! {r#"
            «"nextPage"» [
                ❰"fromRecord"❱: 100
                ❰"toRecord"❱: 199
            ]
        "#}).trim());

        //
        // Now the server constructs its successful response to the client.
        //

        // The state we're sending to ourselves is the continuation of this retrival.
        let state = Expression::new("nextPage")
            .with_parameter("fromRecord", 200)
            .with_parameter("toRecord", 299);
        // The state we're sending back to the client is whatever they sent us.
        let peer_continuation = parsed_client_request.peer_continuation();

        let server_response = SealedResponse::new_success(
            parsed_client_request.id(),
            server_public_key
        )
            .with_result("Records retrieved: 100-199")
            .with_state(state)
            .with_peer_continuation(peer_continuation);

        //
        // We examine the form of the response envelope after it is signed by the
        // server, but before it is encrypted to the client. In production you
        // would skip this and go straight to the next step.
        //

        let server_continuation_valid_until = now.clone() + Duration::from_secs(60);
        let signed_server_response_envelope = server_response.to_envelope(
            Some(&server_continuation_valid_until),
            Some(&server_private_key),
            None,
        );
        // println!("{}", signed_server_response_envelope.format());
        assert_eq!(signed_server_response_envelope.format(), (indoc! {r#"
            {
                response(ARID(c66be27d)) [
                    'recipientContinuation': ENCRYPTED [
                        'hasRecipient': SealedMessage
                    ]
                    'result': "Records retrieved: 100-199"
                    'sender': PublicKeyBase
                    'senderContinuation': ENCRYPTED [
                        'hasRecipient': SealedMessage
                    ]
                ]
            } [
                'signed': Signature
            ]
        "#}).trim());

        //
        // Create the ready-to-send response envelope, signed by the server and encrypted
        // to the client.
        //

        let sealed_server_response_envelope = server_response.to_envelope(
            Some(&server_continuation_valid_until),
            Some(&server_private_key),
            Some(&client_public_key),
        );

        //
        // The server receives and parses the envelope. The ID of the original
        // request is provided so the client can match the response to the
        // request. The current date is provided so that the client can check
        // that any returned continuation has not expired.
        //

        let parsed_server_response = SealedResponse::try_from_encrypted_envelope(
            &sealed_server_response_envelope,
            Some(parsed_client_request.id()),
            Some(&now),
            &client_private_key,
        )?;

        // println!("{}", parsed_server_response.result()?.format());
        assert_eq!(parsed_server_response.result()?.format(), (indoc! {r#"
            "Records retrieved: 100-199"
        "#}).trim());

        //
        // The client can now use the continuation state and take the next action based on the result.
        //

        // println!("{}", parsed_server_response.state().unwrap().format());
        assert_eq!(parsed_server_response.state().unwrap().format(), (indoc! {r#"
            "The state of things."
        "#}).trim());

        Ok(())
    }
}
