use std::time::Duration;

use bc_components::{ARID, EncapsulationScheme, SignatureScheme, keypair_opt};
use bc_envelope::prelude::*;
use bc_xid::{XIDDocument, XIDGenesisMarkOptions, XIDInceptionKeyOptions};
use gstp::prelude::*;
use hex_literal::hex;
use indoc::indoc;

fn request_id() -> ARID {
    ARID::from_data(hex!(
        "c66be27dbad7cd095ca77647406d07976dc0f35f0d4d654bb0e96dd227a1e9fc"
    ))
}
fn request_date() -> Date { Date::try_from("2024-07-04T11:11:11Z").unwrap() }

fn request_continuation() -> Continuation {
    let valid_duration = Duration::from_secs(60);
    let valid_until = request_date() + valid_duration;
    Continuation::new("The state of things.")
        .with_valid_id(request_id())
        .with_valid_until(valid_until)
}

#[test]
fn test_encrypted_continuation() {
    bc_envelope::register_tags();

    let (sender_private_keys, sender_public_keys) =
        keypair_opt(SignatureScheme::MLDSA44, EncapsulationScheme::MLKEM512);

    let continuation = request_continuation();
    let envelope = continuation.to_envelope(Some(&sender_public_keys));

    #[rustfmt::skip]
    assert_eq!(envelope.format(), (indoc! {r#"
        ENCRYPTED [
            'hasRecipient': SealedMessage(MLKEM512)
        ]
    "#}).trim());

    let valid_now = Some(request_date() + Duration::from_secs(30));
    let parsed_continuation = Continuation::try_from_envelope(
        &envelope,
        Some(request_id()),
        valid_now,
        Some(&sender_private_keys),
    )
    .unwrap();
    assert_eq!(continuation.state(), parsed_continuation.state());
    assert_eq!(continuation.id(), parsed_continuation.id());
    assert_eq!(
        continuation.valid_until(),
        parsed_continuation.valid_until()
    );
    assert_eq!(continuation, parsed_continuation);

    let invalid_now = Some(request_date() + Duration::from_secs(90));
    let invalid_continuation_error = Continuation::try_from_envelope(
        &envelope,
        Some(request_id()),
        invalid_now,
        Some(&sender_private_keys),
    );
    assert!(invalid_continuation_error.is_err());

    let invalid_id = ARID::new();
    let invalid_continuation_error = Continuation::try_from_envelope(
        &envelope,
        Some(invalid_id),
        valid_now,
        Some(&sender_private_keys),
    );
    assert!(invalid_continuation_error.is_err());
}

#[test]
fn test_sealed_request() {
    bc_envelope::register_tags();

    //
    // Generate keypairs for the server and client.
    //

    let (server_private_keys, server_public_keys) =
        keypair_opt(SignatureScheme::MLDSA44, EncapsulationScheme::MLKEM512);
    let server = XIDDocument::new(
        XIDInceptionKeyOptions::PublicAndPrivateKeys(
            server_public_keys.clone(),
            server_private_keys.clone(),
        ),
        XIDGenesisMarkOptions::None,
    );

    let (client_private_keys, client_public_keys) =
        keypair_opt(SignatureScheme::MLDSA44, EncapsulationScheme::MLKEM512);
    let client = XIDDocument::new(
        XIDInceptionKeyOptions::PublicAndPrivateKeys(
            client_public_keys.clone(),
            client_private_keys.clone(),
        ),
        XIDGenesisMarkOptions::None,
    );

    let now = Date::try_from("2024-07-04T11:11:11Z").unwrap();

    //
    // The server has previously sent the client this continuation. To the
    // client, it is just an encrypted envelope and cannot be read or
    // modified; it can only be sent back to the server.
    //

    // The server sent this response 30 seconds ago.
    let server_response_date = now - Duration::from_secs(30);
    // And its continuation is valid for 60 seconds.
    let server_continuation_valid_until =
        server_response_date + Duration::from_secs(60);
    let server_state = Expression::new("nextPage")
        .with_parameter("fromRecord", 100)
        .with_parameter("toRecord", 199);
    // Normally you'll never need to compose a `Continuation` struct directly.
    // It is indirectly constructed using the `state` attribute of a
    // `SealedRequest` or `SealedResponse` struct.
    let server_continuation = Continuation::new(server_state)
        .with_valid_until(server_continuation_valid_until);
    let server_continuation =
        server_continuation.to_envelope(Some(&server_public_keys));

    //
    // The client composes a request to the server, returning to it the
    // continuation the server previously sent. The client is also going to
    // include its own continuation ("state"), which the server will return
    // in its response.
    //

    // The client's continuation is valid for 60 seconds from now.
    let client_continuation_valid_until = now + Duration::from_secs(60);
    let client_request = SealedRequest::new("test", request_id(), &client)
        .with_parameter("param1", 42)
        .with_parameter("param2", "hello")
        .with_note("This is a test")
        .with_date(now)
        .with_state("The state of things.")
        .with_peer_continuation(server_continuation);

    //
    // We examine the form of the request envelope after it is signed by the
    // client, but before it is encrypted to the server. In production you
    // would skip this and go straight to the next step.
    //

    let _signed_client_request_envelope = client_request
        .to_envelope(
            Some(client_continuation_valid_until),
            Some(&client_private_keys),
            None,
        )
        .unwrap();
    // println!("{}", _signed_client_request_envelope.format());

    //
    // Create the ready-to-send request envelope, signed by the client and
    // encrypted to the server.
    //

    let sealed_client_request_envelope = client_request
        .to_envelope(
            Some(client_continuation_valid_until),
            Some(&client_private_keys),
            Some(&server),
        )
        .unwrap();

    //
    // The server receives and parses the envelope. No expected ID is
    // provided because the server didn't know what the client's request ID
    // would be. The current date is provided so that the server can check that
    // any returned continuation has not expired.
    //

    let parsed_client_request = SealedRequest::try_from_envelope(
        &sealed_client_request_envelope,
        None,
        Some(now),
        &server_private_keys,
    )
    .unwrap();
    assert_eq!(
        *parsed_client_request.function(),
        Into::<Function>::into("test")
    );
    assert_eq!(
        parsed_client_request
            .extract_object_for_parameter::<i32>("param1")
            .unwrap(),
        42
    );
    assert_eq!(
        parsed_client_request
            .extract_object_for_parameter::<String>("param2")
            .unwrap(),
        "hello"
    );
    assert_eq!(parsed_client_request.note(), "This is a test");
    assert_eq!(parsed_client_request.date(), Some(now));

    //
    // The server can now use the continuation state amd execute the request.
    //

    let state = parsed_client_request.state().unwrap();
    // println!("{}", state.format());
    #[rustfmt::skip]
    assert_eq!(state.format(), (indoc! {r#"
        «"nextPage"» [
            ❰"fromRecord"❱: 100
            ❰"toRecord"❱: 199
        ]
    "#}).trim());

    //
    // Now the server constructs its successful response to the client.
    //

    // The state we're sending to ourselves is the continuation of this
    // retrival.
    let state = Expression::new("nextPage")
        .with_parameter("fromRecord", 200)
        .with_parameter("toRecord", 299);
    // The state we're sending back to the client is whatever they sent us.
    let peer_continuation = parsed_client_request.peer_continuation();

    let server_response =
        SealedResponse::new_success(parsed_client_request.id(), server)
            .with_result("Records retrieved: 100-199")
            .with_state(state)
            .with_peer_continuation(peer_continuation);

    //
    // We examine the form of the response envelope after it is signed by the
    // server, but before it is encrypted to the client. In production you
    // would skip this and go straight to the next step.
    //

    let server_continuation_valid_until = now + Duration::from_secs(60);
    let _signed_server_response_envelope = server_response
        .to_envelope(
            Some(server_continuation_valid_until),
            Some(&server_private_keys),
            None,
        )
        .unwrap();
    // println!("{}", _signed_server_response_envelope.format());

    //
    // Create the ready-to-send response envelope, signed by the server and
    // encrypted to the client.
    //

    let sealed_server_response_envelope = server_response
        .to_envelope(
            Some(server_continuation_valid_until),
            Some(&server_private_keys),
            Some(&client),
        )
        .unwrap();

    //
    // The server receives and parses the envelope. The ID of the original
    // request is provided so the client can match the response to the
    // request. The current date is provided so that the client can check
    // that any returned continuation has not expired.
    //

    let parsed_server_response = SealedResponse::try_from_encrypted_envelope(
        &sealed_server_response_envelope,
        Some(parsed_client_request.id()),
        Some(now),
        &client_private_keys,
    )
    .unwrap();

    // println!("{}", parsed_server_response.result().unwrap().format());
    #[rustfmt::skip]
    assert_eq!(parsed_server_response.result().unwrap().format(), (indoc! {r#"
        "Records retrieved: 100-199"
    "#}).trim());

    //
    // The client can now use the continuation state and take the next action
    // based on the result.
    //

    // println!("{}", parsed_server_response.state().unwrap().format());
    #[rustfmt::skip]
    assert_eq!(parsed_server_response.state().unwrap().format(), (indoc! {r#"
        "The state of things."
    "#}).trim());
}

#[test]
fn test_sealed_event() {
    bc_envelope::register_tags();

    //
    // Generate keypairs for the peers.
    //

    let (sender_private_keys, sender_public_keys) =
        keypair_opt(SignatureScheme::MLDSA44, EncapsulationScheme::MLKEM512);
    let sender = XIDDocument::new(
        XIDInceptionKeyOptions::PublicAndPrivateKeys(
            sender_public_keys.clone(),
            sender_private_keys.clone(),
        ),
        XIDGenesisMarkOptions::None,
    );

    let (recipient_private_keys, recipient_public_keys) =
        keypair_opt(SignatureScheme::MLDSA44, EncapsulationScheme::MLKEM512);
    let recipient = XIDDocument::new(
        XIDInceptionKeyOptions::PublicAndPrivateKeys(
            recipient_public_keys.clone(),
            recipient_private_keys.clone(),
        ),
        XIDGenesisMarkOptions::None,
    );

    let now = Date::try_from("2024-07-04T11:11:11Z").unwrap();

    //
    // We're sending to a specific recipient, but we're not using a
    // continuation as we're not expecting a response.
    //

    let event = SealedEvent::<String>::new("test", request_id(), &sender)
        .with_note("This is a test")
        .with_date(now);

    //
    // We examine the form of the event envelope after it is signed by the
    // sender, but before it is encrypted to the recipient. If this is a
    // broadcast event, this would be the final form of the envelope.
    //

    let _signed_event_envelope = event
        .to_envelope(None, Some(&sender_private_keys), None)
        .unwrap();

    //
    // We're not using a continuation, or a valid until date, so the envelope
    // will not contain a sender continuation. We still support using both
    // sender and recipient continuations, but they are not required.
    //

    // println!("{}", _signed_event_envelope.format());

    //
    // Create the ready-to-send event envelope, signed by the sender and
    // encrypted to the recipient.
    //

    let sealed_event_envelope = event
        .to_envelope(None, Some(&sender_private_keys), Some(&recipient))
        .unwrap();

    //
    // The peer receives and parses the envelope.
    //

    // let sender_inception_key =
    // sender.inception_key().unwrap().signing_public_key(); println!("{:?}"
    // , sender_inception_key);

    let parsed_event = SealedEvent::<String>::try_from_envelope(
        &sealed_event_envelope,
        None,
        None,
        &recipient_private_keys,
    )
    .unwrap();
    assert_eq!(parsed_event.content(), "test");
    assert_eq!(parsed_event.note(), "This is a test");
    assert_eq!(parsed_event.date(), Some(now));
}
