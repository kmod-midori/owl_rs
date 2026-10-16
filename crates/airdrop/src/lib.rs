//! User-owned AirDrop transport, discovery, contacts and control service.
#![forbid(unsafe_code)]

#[cfg(all(feature = "tray-ksni", feature = "tray-gtk"))]
compile_error!(
    "tray backends `tray-ksni` and `tray-gtk` are mutually exclusive; use --no-default-features --features tray-gtk for GTK"
);
#[cfg(all(
    feature = "tray",
    not(any(feature = "tray-ksni", feature = "tray-gtk"))
))]
compile_error!("select a tray backend with --features tray-ksni or --features tray-gtk");

mod appledouble;
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
mod progress;
mod session;
mod transport;
#[cfg(feature = "tray")]
mod tray;
