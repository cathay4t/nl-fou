// SPDX-License-Identifier: MIT

use std::net::IpAddr;

use netlink_packet_fou::{
    FouAddressFamily, FouAttribute, FouCmd, FouEncap, FouMessage,
};

use crate::{ErrorKind, FouError};

/// The configuration of a FOU listener, as accepted by `ip fou add` and
/// `ip fou del` of iproute2, and as `ip fou show` reports it.
///
/// Properties the kernel reports as unset are `None`, use
/// [FouConfig::build] to turn the configuration back into a
/// [FouMessage].
#[derive(Clone, Debug, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct FouConfig {
    /// The local UDP port, a non-zero `u16`.
    pub port: Option<u16>,
    /// The address family, IPv4 by default.
    pub family: Option<FouAddressFamily>,
    /// The encapsulation type, [FouEncap::Direct] by default.
    pub encap: Option<FouEncap>,
    /// The L4 protocol to receive, e.g. 17 for UDP.
    pub ipproto: Option<u8>,
    /// The local address the listener binds to.
    pub local: Option<IpAddr>,
    /// The peer address.
    pub peer: Option<IpAddr>,
    /// The peer port, must be set together with [FouConfig::peer].
    pub peer_port: Option<u16>,
    /// Receive checksum not partial.
    pub remcsum_nopartial: bool,
    /// The index of the interface the listener is bound to.
    pub ifindex: Option<i32>,
}

impl FouConfig {
    /// Create a IPv4 FOU config with [FouEncap::Direct] encapsulation.
    pub fn new(port: u16) -> Self {
        Self {
            port: Some(port),
            family: Some(FouAddressFamily::Ipv4),
            encap: Some(FouEncap::Direct),
            ..Default::default()
        }
    }

    /// Build the [FouMessage] of the `cmd` request for this configuration.
    ///
    /// The address family defaults to
    /// [FouAddressFamily::Ipv4] and the encapsulation to
    /// [FouEncap::Direct] when they are not set, as `ip fou` does.
    ///
    /// The configuration is validated as `ip fou` does: [FouCmd::Add]
    /// requires either a non-zero `ipproto` or [FouEncap::Gue], the two can
    /// not be combined, and a peer address and a peer port come in pairs.
    pub fn build(&self, cmd: FouCmd) -> Result<FouMessage, FouError> {
        let port = self
            .port
            .ok_or_else(|| invalid_input("`port` is required"))?;
        if port == 0 {
            return Err(invalid_input("port must not be zero"));
        }

        let family = self.family.unwrap_or(FouAddressFamily::Ipv4);
        let encap = self.encap.unwrap_or(FouEncap::Direct);

        if self.ipproto == Some(0) {
            return Err(invalid_input("ipproto must not be zero"));
        }

        if cmd == FouCmd::Add {
            match (self.ipproto, encap) {
                (None, FouEncap::Direct) => {
                    return Err(invalid_input(
                        "either ipproto or gue is required to add a listener",
                    ));
                }
                (Some(_), FouEncap::Gue) => {
                    return Err(invalid_input(
                        "ipproto and gue can not be set together",
                    ));
                }
                _ => (),
            }
        }

        if self.peer_port == Some(0) {
            return Err(invalid_input("peer port must not be zero"));
        }

        let mut attributes = vec![
            FouAttribute::Port(port),
            FouAttribute::Family(family),
            FouAttribute::Encap(encap),
        ];

        if self.remcsum_nopartial {
            attributes.push(FouAttribute::RemcsumNopartial);
        }

        if let Some(ipproto) = self.ipproto {
            attributes.push(FouAttribute::Ipproto(ipproto));
        }

        if let Some(local) = self.local {
            match (family, local) {
                (FouAddressFamily::Ipv4, IpAddr::V4(addr)) => {
                    attributes.push(FouAttribute::LocalV4(addr));
                }
                (FouAddressFamily::Ipv6, IpAddr::V6(addr)) => {
                    attributes.push(FouAttribute::LocalV6(addr));
                }
                (_, _) => {
                    return Err(invalid_input(
                        "local address does not match the address family",
                    ));
                }
            }
        }

        if let Some(peer) = self.peer {
            if self.peer_port.is_none() {
                return Err(invalid_input(
                    "both peer and peer port must be set",
                ));
            }
            match (family, peer) {
                (FouAddressFamily::Ipv4, IpAddr::V4(addr)) => {
                    attributes.push(FouAttribute::PeerV4(addr));
                }
                (FouAddressFamily::Ipv6, IpAddr::V6(addr)) => {
                    attributes.push(FouAttribute::PeerV6(addr));
                }
                (_, _) => {
                    return Err(invalid_input(
                        "peer address does not match the address family",
                    ));
                }
            }
        }

        if let Some(peer_port) = self.peer_port {
            if self.peer.is_none() {
                return Err(invalid_input(
                    "both peer and peer port must be set",
                ));
            }
            attributes.push(FouAttribute::PeerPort(peer_port));
        }

        if let Some(ifindex) = self.ifindex {
            attributes.push(FouAttribute::IfIndex(ifindex));
        }

        Ok(FouMessage { cmd, attributes })
    }
}

impl From<FouMessage> for FouConfig {
    fn from(msg: FouMessage) -> Self {
        let mut ret = Self::default();
        for attr in msg.attributes {
            match attr {
                FouAttribute::Port(v) => ret.port = Some(v),
                FouAttribute::Family(v) => ret.family = Some(v),
                FouAttribute::Encap(v) => ret.encap = Some(v),
                FouAttribute::Ipproto(v) => ret.ipproto = Some(v),
                FouAttribute::RemcsumNopartial => ret.remcsum_nopartial = true,
                // The kernel reports an unspecified address, a zero peer
                // port and a zero interface index for a listener which does
                // not use them, `ip fou show` hides them as well.
                FouAttribute::LocalV4(v) if !v.is_unspecified() => {
                    ret.local = Some(IpAddr::V4(v))
                }
                FouAttribute::LocalV6(v) if !v.is_unspecified() => {
                    ret.local = Some(IpAddr::V6(v))
                }
                FouAttribute::PeerV4(v) if !v.is_unspecified() => {
                    ret.peer = Some(IpAddr::V4(v))
                }
                FouAttribute::PeerV6(v) if !v.is_unspecified() => {
                    ret.peer = Some(IpAddr::V6(v))
                }
                FouAttribute::PeerPort(v) if v != 0 => ret.peer_port = Some(v),
                FouAttribute::IfIndex(v) if v != 0 => ret.ifindex = Some(v),
                FouAttribute::LocalV4(_)
                | FouAttribute::LocalV6(_)
                | FouAttribute::PeerV4(_)
                | FouAttribute::PeerV6(_)
                | FouAttribute::PeerPort(_)
                | FouAttribute::IfIndex(_) => (),
                _ => {
                    log::debug!("Unsupported FouAttribute {attr:?}");
                }
            }
        }
        // The kernel reports an ipproto of zero for a GUE listener, the
        // encapsulation carries the protocol of the payload.
        if ret.encap == Some(FouEncap::Gue) {
            ret.ipproto = None;
        }
        ret
    }
}

fn invalid_input(msg: &str) -> FouError {
    FouError::new(ErrorKind::InvalidInput, msg.to_string(), None)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn build_ipv4_config() {
        let config = FouConfig {
            port: Some(5555),
            ipproto: Some(17),
            local: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            peer: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            peer_port: Some(6666),
            ifindex: Some(3),
            ..FouConfig::new(5555)
        };

        assert_eq!(
            config.build(FouCmd::Add).unwrap(),
            FouMessage {
                cmd: FouCmd::Add,
                attributes: vec![
                    FouAttribute::Port(5555),
                    FouAttribute::Family(FouAddressFamily::Ipv4),
                    FouAttribute::Encap(FouEncap::Direct),
                    FouAttribute::Ipproto(17),
                    FouAttribute::LocalV4(Ipv4Addr::new(10, 0, 0, 1)),
                    FouAttribute::PeerV4(Ipv4Addr::new(10, 0, 0, 2)),
                    FouAttribute::PeerPort(6666),
                    FouAttribute::IfIndex(3),
                ],
            }
        );
    }

    #[test]
    fn build_ipv6_gue_config() {
        let config = FouConfig {
            port: Some(5555),
            family: Some(FouAddressFamily::Ipv6),
            encap: Some(FouEncap::Gue),
            local: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            remcsum_nopartial: true,
            ..FouConfig::new(5555)
        };

        assert_eq!(
            config.build(FouCmd::Add).unwrap(),
            FouMessage {
                cmd: FouCmd::Add,
                attributes: vec![
                    FouAttribute::Port(5555),
                    FouAttribute::Family(FouAddressFamily::Ipv6),
                    FouAttribute::Encap(FouEncap::Gue),
                    FouAttribute::RemcsumNopartial,
                    FouAttribute::LocalV6(Ipv6Addr::LOCALHOST),
                ],
            }
        );
    }

    #[test]
    fn reject_mismatched_address_family() {
        let config = FouConfig {
            ipproto: Some(17),
            local: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            ..FouConfig::new(5555)
        };
        assert!(config.build(FouCmd::Add).is_err());
    }

    #[test]
    fn reject_peer_without_peer_port() {
        let config = FouConfig {
            ipproto: Some(17),
            peer: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            ..FouConfig::new(5555)
        };
        assert!(config.build(FouCmd::Add).is_err());
    }

    #[test]
    fn reject_peer_port_without_peer() {
        let config = FouConfig {
            ipproto: Some(17),
            peer_port: Some(6666),
            ..FouConfig::new(5555)
        };
        assert!(config.build(FouCmd::Add).is_err());
    }

    #[test]
    fn reject_direct_without_ipproto() {
        assert!(FouConfig::new(5555).build(FouCmd::Add).is_err());
        // Deleting a listener does not need the protocol.
        assert!(FouConfig::new(5555).build(FouCmd::Del).is_ok());
    }

    #[test]
    fn reject_ipproto_with_gue() {
        let config = FouConfig {
            encap: Some(FouEncap::Gue),
            ipproto: Some(17),
            ..FouConfig::new(5555)
        };
        assert!(config.build(FouCmd::Add).is_err());
        // The kernel ignores the protocol of a GUE listener on delete.
        assert!(config.build(FouCmd::Del).is_ok());
    }

    #[test]
    fn reject_zero_ipproto() {
        let config = FouConfig {
            ipproto: Some(0),
            ..FouConfig::new(5555)
        };
        assert!(config.build(FouCmd::Add).is_err());
    }

    #[test]
    fn reject_zero_peer_port() {
        let config = FouConfig {
            ipproto: Some(17),
            peer: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            peer_port: Some(0),
            ..FouConfig::new(5555)
        };
        assert!(config.build(FouCmd::Add).is_err());
    }

    #[test]
    fn reject_zero_port() {
        assert!(FouConfig::new(0).build(FouCmd::Add).is_err());
    }

    #[test]
    fn reject_missing_port() {
        assert!(FouConfig::default().build(FouCmd::Add).is_err());
    }

    #[test]
    fn parse_message() {
        let config = FouConfig::from(FouMessage {
            cmd: FouCmd::Get,
            attributes: vec![
                FouAttribute::Port(5555),
                FouAttribute::Family(FouAddressFamily::Ipv6),
                FouAttribute::Encap(FouEncap::Direct),
                FouAttribute::RemcsumNopartial,
                FouAttribute::Ipproto(17),
                FouAttribute::LocalV6(Ipv6Addr::LOCALHOST),
                FouAttribute::PeerV6(Ipv6Addr::LOCALHOST),
                FouAttribute::PeerPort(6666),
                FouAttribute::IfIndex(3),
            ],
        });

        assert_eq!(
            config,
            FouConfig {
                port: Some(5555),
                family: Some(FouAddressFamily::Ipv6),
                encap: Some(FouEncap::Direct),
                ipproto: Some(17),
                local: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
                peer: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
                peer_port: Some(6666),
                remcsum_nopartial: true,
                ifindex: Some(3),
            }
        );
    }

    #[test]
    fn parse_gue_dump_hides_unset_properties() {
        // The kernel reports these attributes for every listener of a dump,
        // for a GUE listener they hold an unset value.
        let config = FouConfig::from(FouMessage {
            cmd: FouCmd::Get,
            attributes: vec![
                FouAttribute::Family(FouAddressFamily::Ipv4),
                FouAttribute::Port(5555),
                FouAttribute::PeerPort(0),
                FouAttribute::Ipproto(0),
                FouAttribute::Encap(FouEncap::Gue),
                FouAttribute::IfIndex(0),
                FouAttribute::LocalV4(Ipv4Addr::UNSPECIFIED),
                FouAttribute::PeerV4(Ipv4Addr::UNSPECIFIED),
            ],
        });

        assert_eq!(
            config,
            FouConfig {
                port: Some(5555),
                family: Some(FouAddressFamily::Ipv4),
                encap: Some(FouEncap::Gue),
                ..Default::default()
            }
        );
    }

    #[test]
    fn message_can_be_applied_again() {
        let message = FouConfig {
            port: Some(5555),
            ipproto: Some(17),
            local: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            peer: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            peer_port: Some(6666),
            ifindex: Some(3),
            ..FouConfig::new(5555)
        }
        .build(FouCmd::Add)
        .unwrap();

        assert_eq!(
            FouConfig::from(message.clone()).build(FouCmd::Add).unwrap(),
            message
        );
    }
}
