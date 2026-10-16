// SPDX-License-Identifier: GPL-3.0-or-later
//! AirDrop daemon control protocol and Unix socket client.
#![forbid(unsafe_code)]
pub mod control;
pub mod visibility;
pub use owl_ipc::timeouts;
