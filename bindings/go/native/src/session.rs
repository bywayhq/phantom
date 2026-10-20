//! Encrypted session bytes use the core codec, bounds and compatibility rules.

use crate::{
    client,
    error::Failure,
    operations::{self, session::SessionLease},
};
use phantom::{SessionSnapshot, SessionSnapshotError, SessionSnapshotErrorKind};
use serde::Deserialize;
use serde_json::{Value, json};
use zeroize::Zeroizing;

pub(super) const MAX_SNAPSHOT: usize = 32 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceivingRoute {
    proxy: Option<String>,
    proxy_credentials: Option<client::ProxyCredentials>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Export {
        client: u64,
    },
    Copy {
        operation: u64,
    },
    Restore {
        client: u64,
        receiving_routes: Vec<ReceivingRoute>,
    },
}

fn snapshot_error(error: SessionSnapshotError) -> Failure {
    Failure::new(match error.kind() {
        SessionSnapshotErrorKind::TooLarge => "session_snapshot_too_large",
        SessionSnapshotErrorKind::Allocation => "session_snapshot_allocation",
        SessionSnapshotErrorKind::InvalidSnapshot => "session_snapshot_invalid_snapshot",
        SessionSnapshotErrorKind::Authentication => "session_snapshot_authentication",
        SessionSnapshotErrorKind::Incompatible => "session_snapshot_incompatible",
        SessionSnapshotErrorKind::Disabled => "session_snapshot_disabled",
        SessionSnapshotErrorKind::Capacity => "session_snapshot_capacity",
        SessionSnapshotErrorKind::Unsupported => "session_snapshot_unsupported",
        SessionSnapshotErrorKind::Tickets => "session_snapshot_tickets",
        SessionSnapshotErrorKind::Cookies => "session_snapshot_cookies",
        SessionSnapshotErrorKind::AltSvc => "session_snapshot_alt_svc",
        SessionSnapshotErrorKind::Backend => "session_snapshot_backend",
        _ => "session_snapshot_unknown",
    })
}

fn key(bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>, Failure> {
    if bytes.len() != 32 {
        return Err(Failure::new("session_snapshot_invalid_key_length"));
    }
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(bytes);
    Ok(key)
}

fn success(value: Value) -> Result<Vec<u8>, Failure> {
    let bytes =
        serde_json::to_vec(&json!({"value": value})).map_err(|_| Failure::new("internal"))?;
    if bytes.len() > operations::MAX_METADATA {
        return Err(Failure::new("metadata_limit"));
    }
    Ok(bytes)
}

pub(super) fn dispatch(
    input: &[u8],
    secret: &[u8],
    bytes: &[u8],
    capacity: usize,
) -> (Vec<u8>, Option<SessionSnapshot>) {
    let result = (|| {
        let command: Command =
            serde_json::from_slice(input).map_err(|_| Failure::new("invalid_command"))?;
        match command {
            Command::Export { client } => {
                if !bytes.is_empty() || capacity != 0 {
                    return Err(Failure::new("invalid_command"));
                }
                let key = key(secret)?;
                let lease = SessionLease::new(client)?;
                let snapshot = lease
                    .source
                    .client
                    .export_session(&key)
                    .map_err(snapshot_error)?;
                let reply = success(lease.publish_snapshot(snapshot)?)?;
                lease.retain_snapshot();
                Ok((reply, None))
            }
            Command::Copy { operation } => {
                if !secret.is_empty() || !bytes.is_empty() {
                    return Err(Failure::new("invalid_command"));
                }
                let snapshot = operations::session::take_snapshot(operation, capacity)?;
                let reply = success(json!({"length": snapshot.as_bytes().len()}))?;
                Ok((reply, Some(snapshot)))
            }
            Command::Restore {
                client,
                receiving_routes,
            } => {
                if capacity != 0 {
                    return Err(Failure::new("invalid_command"));
                }
                if receiving_routes.len() > 256 {
                    return Err(Failure::new("input_limit"));
                }
                let key = key(secret)?;
                let routes = receiving_routes
                    .into_iter()
                    .map(|route| client::route(route.proxy.as_deref(), route.proxy_credentials))
                    .collect::<Result<Vec<_>, _>>()?;
                let mut lease = SessionLease::new(client)?;
                let snapshot = SessionSnapshot::from_bytes(bytes).map_err(snapshot_error)?;
                let restored = lease
                    .source
                    .client
                    .restore_session(&snapshot, &key, &routes)
                    .map_err(snapshot_error)?;
                let owner = lease.source.restored(restored);
                let reply = success(lease.publish_client(owner)?)?;
                lease.accept_client();
                Ok((reply, None))
            }
        }
    })();
    match result {
        Ok(result) => result,
        Err(error) => (operations::failure(error), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_reject_unknown_fields_and_key_never_enters_json() -> Result<(), serde_json::Error> {
        assert!(
            serde_json::from_str::<Command>(r#"{"kind":"export","client":1,"key":[0]}"#).is_err()
        );
        assert!(serde_json::from_str::<Command>(r#"{"kind":"restore","client":1,"receiving_routes":[{"proxy":null,"unknown":true}]}"#).is_err());
        let _ = serde_json::from_str::<Command>(
            r#"{"kind":"restore","client":1,"receiving_routes":[{}, {"proxy":"http://127.0.0.1:80","proxy_credentials":{"username":"user","password":"password"}}]}"#,
        )?;
        assert_eq!(
            key(&[0; 31]).err().map(|error| error.kind),
            Some("session_snapshot_invalid_key_length")
        );
        for (count, kind) in [(256, "client_closed"), (257, "input_limit")] {
            let command = serde_json::to_vec(&json!({
                "kind": "restore", "client": 0,
                "receiving_routes": vec![json!({}); count],
            }))?;
            let (reply, _) = dispatch(&command, &[0; 32], b"opaque", 0);
            let reply: Value = serde_json::from_slice(&reply)?;
            assert_eq!(reply["error"]["kind"].as_str(), Some(kind));
        }
        Ok(())
    }
}
