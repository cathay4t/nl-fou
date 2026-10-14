// SPDX-License-Identifier: MIT

use netlink_packet_core::NetlinkMessage;
use netlink_packet_fou::FouMessage;
use netlink_packet_generic::GenlMessage;

/// Kind of a [FouError].
///
/// This enum is `#[non_exhaustive]`, a `match` on it needs a wildcard arm.
/// Otherwise every new error kind would break the code of every user.
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
#[non_exhaustive]
pub enum ErrorKind {
    Bug,
    NetlinkError,
    DecodeError,
    /// Invalid input from the caller, e.g. missing required property.
    InvalidInput,
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Bug => "bug",
                Self::NetlinkError => "netlink_error",
                Self::DecodeError => "decode_error",
                Self::InvalidInput => "invalid_input",
            }
        )
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct FouError {
    pub kind: ErrorKind,
    pub msg: String,
    pub netlink_msg: Option<NetlinkMessage<GenlMessage<FouMessage>>>,
}

impl std::fmt::Display for FouError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(nl_msg) = self.netlink_msg.as_ref() {
            write!(
                f,
                "{}: {}, netlink message: {:?}",
                self.kind, self.msg, nl_msg
            )
        } else {
            write!(f, "{}: {}", self.kind, self.msg)
        }
    }
}

impl std::error::Error for FouError {}

impl FouError {
    /// Create a new [FouError].
    pub fn new(
        kind: ErrorKind,
        msg: String,
        netlink_msg: Option<NetlinkMessage<GenlMessage<FouMessage>>>,
    ) -> Self {
        Self {
            kind,
            msg,
            netlink_msg,
        }
    }
}
