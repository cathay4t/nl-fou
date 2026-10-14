// SPDX-License-Identifier: MIT

//! Integration tests exercising the kernel FOU generic netlink API.
//!
//! These tests need `CAP_NET_ADMIN` and the `fou` kernel module, they add
//! and remove FOU listeners in the current network namespace. Therefore
//! they are `#[ignore]`d by default. Build the test binary as an
//! unprivileged user and run it as root, for example:
//!
//! ```bash
//! cargo test --test fou_kernel --no-run
//! sudo ./target/debug/deps/fou_kernel-* --ignored --nocapture
//! ```

use std::process::Command;

use netlink_packet_fou::FouAddressFamily;
use nl_fou::{FouConfig, FouEncap, FouHandle};

/// Ports unlikely to be used by another listener. Every test uses its own
/// port so that they can run in parallel.
const DIRECT_PORT: u16 = 15631;
const GUE_PORT: u16 = 15632;
const REPLAY_PORT: u16 = 15633;
const DUPLICATE_PORT: u16 = 15634;

/// Direct FOU which encapsulates UDP, the listener of `ip fou add port PORT
/// ipproto 17`.
fn direct_config(port: u16) -> FouConfig {
    let mut config = FouConfig::new(port);
    config.ipproto = Some(17);
    config
}

/// GUE listener of `ip fou add port PORT gue`, GUE carries the protocol of
/// the payload.
fn gue_config(port: u16) -> FouConfig {
    let mut config = FouConfig::new(port);
    config.encap = Some(FouEncap::Gue);
    config
}

/// The `fou` generic netlink family does not auto-load when the family is
/// resolved, load the module explicitly.
fn load_fou_module() {
    let status = Command::new("modprobe")
        .arg("fou")
        .status()
        .expect("failed to run modprobe");
    assert!(status.success(), "modprobe fou failed");
}

async fn connect() -> FouHandle {
    let (connection, handle, _) =
        nl_fou::new_connection().expect("failed to open netlink socket");
    tokio::spawn(connection);
    handle
}

fn find_port(listeners: &[FouConfig], port: u16) -> Option<&FouConfig> {
    listeners
        .iter()
        .find(|listener| listener.port == Some(port))
}

#[tokio::test]
#[ignore = "needs root and the fou kernel module"]
async fn add_get_delete() {
    load_fou_module();
    let mut handle = connect().await;

    // Remove listeners left over by an interrupted test run.
    let _ = handle.delete(&direct_config(DIRECT_PORT)).await;
    let _ = handle.delete(&gue_config(GUE_PORT)).await;

    handle
        .add(&direct_config(DIRECT_PORT))
        .await
        .expect("failed to add listener");
    handle
        .add(&gue_config(GUE_PORT))
        .await
        .expect("failed to add listener");

    let listeners = handle.get_all().await.expect("failed to dump");
    let direct =
        find_port(&listeners, DIRECT_PORT).expect("direct listener not dumped");
    assert_eq!(direct.family, Some(FouAddressFamily::Ipv4));
    assert_eq!(direct.encap, Some(FouEncap::Direct));
    assert_eq!(direct.ipproto, Some(17));
    assert_eq!(direct.local, None);
    assert_eq!(direct.peer, None);

    let gue = find_port(&listeners, GUE_PORT).expect("gue listener not dumped");
    assert_eq!(gue.family, Some(FouAddressFamily::Ipv4));
    assert_eq!(gue.encap, Some(FouEncap::Gue));
    // The kernel reports an ipproto of zero for GUE, the parser hides it.
    assert_eq!(gue.ipproto, None);

    handle
        .delete(&direct_config(DIRECT_PORT))
        .await
        .expect("failed to delete listener");
    handle
        .delete(&gue_config(GUE_PORT))
        .await
        .expect("failed to delete listener");

    let listeners = handle.get_all().await.expect("failed to dump");
    assert!(find_port(&listeners, DIRECT_PORT).is_none());
    assert!(find_port(&listeners, GUE_PORT).is_none());
}

#[tokio::test]
#[ignore = "needs root and the fou kernel module"]
async fn config_can_be_applied_again() {
    load_fou_module();
    let mut handle = connect().await;

    let _ = handle.delete(&direct_config(REPLAY_PORT)).await;
    handle
        .add(&direct_config(REPLAY_PORT))
        .await
        .expect("failed to add listener");

    let listeners = handle.get_all().await.expect("failed to dump");
    let config = find_port(&listeners, REPLAY_PORT)
        .expect("listener not dumped")
        .clone();

    handle
        .delete(&direct_config(REPLAY_PORT))
        .await
        .expect("failed to delete listener");

    // The config describes the kernel state, the kernel accepts it again.
    handle
        .add(&config)
        .await
        .expect("failed to apply the config");

    let listeners = handle.get_all().await.expect("failed to dump");
    assert_eq!(find_port(&listeners, REPLAY_PORT), Some(&config));

    handle
        .delete(&direct_config(REPLAY_PORT))
        .await
        .expect("failed to delete listener");
}

#[tokio::test]
#[ignore = "needs root and the fou kernel module"]
async fn add_duplicate_fails() {
    load_fou_module();
    let mut handle = connect().await;

    let _ = handle.delete(&direct_config(DUPLICATE_PORT)).await;
    handle
        .add(&direct_config(DUPLICATE_PORT))
        .await
        .expect("failed to add listener");

    let err = handle
        .add(&direct_config(DUPLICATE_PORT))
        .await
        .expect_err("adding the same listener twice should fail");
    assert_eq!(err.kind, nl_fou::ErrorKind::NetlinkError);

    handle
        .delete(&direct_config(DUPLICATE_PORT))
        .await
        .expect("failed to delete listener");
}
