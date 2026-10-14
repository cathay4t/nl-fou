// SPDX-License-Identifier: MIT

//! This crate provides methods to manage FOU (foo over UDP) listeners via
//! the generic netlink protocol, as the `ip fou` command of
//! [iproute2](https://git.kernel.org/pub/scm/network/iproute2/iproute2.git)
//! does.
//!
//! To add a FOU listener which encapsulates UDP to port 5555:
//!
//! ```no_run
//! use nl_fou::FouConfig;
//!
//! async fn add_fou_listener() -> Result<(), Box<dyn std::error::Error>> {
//!     let (conn, mut handle, _) = nl_fou::new_connection()?;
//!     tokio::spawn(conn);
//!
//!     let mut config = FouConfig::new(5555);
//!     config.ipproto = Some(17);
//!     handle.add(&config).await?;
//!     Ok(())
//! }
//! ```
//!
//! To list all FOU listeners, [FouHandle::get_all] turns every listener of
//! the kernel reply into a [FouConfig]:
//!
//! ```no_run
//! async fn show_fou_listeners() -> Result<(), Box<dyn std::error::Error>> {
//!     let (conn, mut handle, _) = nl_fou::new_connection()?;
//!     tokio::spawn(conn);
//!
//!     for listener in handle.get_all().await? {
//!         println!("{listener:?}");
//!     }
//!     Ok(())
//! }
//! ```
//!
//! To delete a FOU listener, its local port, address family and addresses
//! identify it, [FouConfig::new] sets the defaults of `ip fou del`:
//!
//! ```no_run
//! use nl_fou::FouConfig;
//!
//! async fn delete_fou_listener() -> Result<(), Box<dyn std::error::Error>> {
//!     let (conn, mut handle, _) = nl_fou::new_connection()?;
//!     tokio::spawn(conn);
//!
//!     handle.delete(&FouConfig::new(5555)).await?;
//!     Ok(())
//! }
//! ```
//!
//! A [FouConfig] which [FouHandle::get_all] returned describes a listener
//! of the kernel, [FouHandle::add] accepts it again.

mod config;
mod connection;
mod error;
mod handle;

#[doc(no_inline)]
pub use netlink_packet_fou::{
    FouAddressFamily, FouAttribute, FouCmd, FouEncap, FouMessage,
};

#[cfg(feature = "tokio_socket")]
pub use self::connection::new_connection;
pub use self::{
    config::FouConfig,
    connection::new_connection_with_socket,
    error::{ErrorKind, FouError},
    handle::FouHandle,
};

// Compile the examples of the README as doc tests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
