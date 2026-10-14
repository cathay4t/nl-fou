# Rust crate for linux FOU netlink management

## To add a FOU listener

```rust
use nl_fou::FouConfig;

async fn add_fou_listener() -> Result<(), Box<dyn std::error::Error>> {
    let (conn, mut handle, _) = nl_fou::new_connection()?;
    tokio::spawn(conn);

    let mut config = FouConfig::new(5555);
    config.ipproto = Some(17);
    handle.add(&config).await?;
    Ok(())
}
```

## To list all FOU listeners

`FouHandle::get_all()` returns one `FouConfig` per listener:

```rust
async fn show_fou_listeners() -> Result<(), Box<dyn std::error::Error>> {
    let (conn, mut handle, _) = nl_fou::new_connection()?;
    tokio::spawn(conn);

    for listener in handle.get_all().await? {
        println!("{listener:?}");
    }
    Ok(())
}
```

## To delete a FOU listener

The local port, the address family and the addresses identify a listener,
`FouConfig::new()` sets the defaults of `ip fou del`:

```rust
use nl_fou::FouConfig;

async fn delete_fou_listener() -> Result<(), Box<dyn std::error::Error>> {
    let (conn, mut handle, _) = nl_fou::new_connection()?;
    tokio::spawn(conn);

    handle.delete(&FouConfig::new(5555)).await?;
    Ok(())
}
```

## Notes

- `FouConfig::new(port)` creates a listener with the IPv4 address family
  and direct FOU encapsulation, the encapsulation type of
  `ip fou add port 5555`.
- `FouHandle::add()` validates the configuration as `ip fou` does: a
  direct listener needs `ipproto`, a GUE listener must not set it, and a
  peer address and a peer port come in pairs.
- `FouHandle::add()` fails when a listener which holds the same local
  port, address family and addresses exists, delete it first to replace
  it.
- `FouConfig` is `#[non_exhaustive]`, it can not be built with a struct
  literal outside of this crate. Use `Default::default()` or
  `FouConfig::new()` and assign the properties instead.
- `FouConfig::build()` validates the configuration and turns it into a
  `FouMessage`, for example for `FouHandle::request()`.
- `FouHandle::get_all()` parses every attribute the kernel reports, the
  result of a dump can be applied again with `FouHandle::add()`.
- The `fou` kernel module does not auto-load when the generic netlink
  family is resolved, load it with `modprobe fou` before adding a
  listener.
