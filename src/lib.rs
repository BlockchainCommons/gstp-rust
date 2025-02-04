#![doc(html_root_url = "https://docs.rs/gstp/0.4.0")]
#![warn(rust_2018_idioms)]

//! # Introduction
//!
//! Gordian Sealed Transaction Protocol (GSTP) is a secure, transport-agnostic
//! communication method enabling encrypted and signed data exchange between
//! multiple parties. Built upon the Gordian Envelope specification, GSTP
//! supports various transport mediums—including HTTP, raw TCP/IP, air-gapped
//! protocols using QR codes, and NFC cards—by implementing its own encryption
//! and signing protocols. A key feature of GSTP is Encrypted State
//! Continuations (ESC), which embed encrypted state data directly into
//! messages, eliminating the need for local state storage and enhancing
//! security for devices with limited storage or requiring distributed state
//! management. It facilitates both client-server and peer-to-peer
//! architectures, ensuring secure and flexible communication across diverse
//! platforms.
//!
//! # Getting Started
//!
//! ```toml
//! [dependencies]
//! gstp = "0.4.0"
//! ```
//!
//! # Examples
//!
//! See the unit tests in the source code for examples of how to use this
//! library.

mod continuation;
pub use continuation::Continuation;
mod sealed_request;
pub use sealed_request::{ SealedRequest, SealedRequestBehavior };
mod sealed_response;
pub use sealed_response::{ SealedResponse, SealedResponseBehavior };
mod sealed_event;
pub use sealed_event::{ SealedEvent, SealedEventBehavior };

pub mod prelude;

#[cfg(test)]
mod tests {
    #[test]
    fn test_readme_deps() {
        version_sync::assert_markdown_deps_updated!("README.md");
    }

    #[test]
    fn test_html_root_url() {
        version_sync::assert_html_root_url_updated!("src/lib.rs");
    }
}
