//! User-owned AirDrop transport, discovery, contacts and control service.
#![forbid(unsafe_code)]
pub mod archive;
pub mod ble;
pub mod contact_book;
pub mod discovery;
pub mod identity;
pub mod service;
pub mod transfer;
pub mod visibility;
pub use owl_ipc::timeouts;
mod contacts;
mod link;
mod mdns;
mod session;
mod transport;
