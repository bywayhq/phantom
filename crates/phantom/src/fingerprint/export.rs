//! Bounded encoding into the existing custom-profile document.

use super::{FingerprintImportError, FingerprintImportErrorKind as Kind, Result};
use phantom_profile::ClientProfile;
use serde_json::{Map, Value};
use std::{
    io,
    num::{NonZeroU8, NonZeroU32, NonZeroUsize},
    time::Duration,
};

macro_rules! object {
    ($encoder:expr, $field:expr, $($key:literal => $value:expr),* $(,)?) => {{
        let encoder = &mut *$encoder;
        let field = $field;
        encoder.claim(field, 1, 0)?;
        let mut values = serde_json::Map::new();
        $(values.insert($key.into(), $crate::fingerprint::export::Encode::encode(
            $value, encoder, &format!("{field}.{}", $key))?);)*
        Ok(serde_json::Value::Object(values))
    }};
}

macro_rules! record {
    ($ty:ty, $($member:ident),+ $(,)?) => {
        impl super::Encode for $ty {
            fn encode(&self, encoder: &mut super::Encoder, field: &str) -> super::Result<serde_json::Value> {
                let Self { $($member),+ } = self;
                encoder.claim(field, 1, 0)?;
                let mut values = serde_json::Map::new();
                $(values.insert(stringify!($member).into(), super::Encode::encode(
                    $member, encoder, &format!("{field}.{}", stringify!($member)))?);)+
                Ok(serde_json::Value::Object(values))
            }
        }
    };
}

macro_rules! tokens {
    ($ty:ty, $($variant:ident),+ $(,)?) => {
        impl super::Encode for $ty {
            fn encode(&self, encoder: &mut super::Encoder, field: &str) -> super::Result<serde_json::Value> {
                let value = match self { $(Self::$variant => stringify!($variant),)+
                    _ => return Err(super::FingerprintImportError::new(super::Kind::UnsupportedSetting, field)),
                };
                super::Encode::encode(value, encoder, field)
            }
        }
    };
}

mod client_hints;
mod cookie;
mod dns_cache;
mod http1;
mod http2;
mod http3;
mod proxy_connect;
mod quic;
mod request_template;
mod tcp;
mod tls;
mod udp;
mod websocket;

trait Encode {
    fn encode(&self, encoder: &mut Encoder, field: &str) -> Result<Value>;
}

#[derive(Default)]
struct Encoder {
    nodes: usize,
    bytes: usize,
}

impl Encoder {
    fn claim(&mut self, field: &str, nodes: usize, bytes: usize) -> Result<()> {
        // Bound allocation before cloning caller-owned strings or arrays.
        if nodes > super::json::MAX_NODES.saturating_sub(self.nodes)
            || bytes > super::json::MAX_BYTES.saturating_sub(self.bytes)
        {
            return Err(FingerprintImportError::new(Kind::TooLarge, field));
        }
        self.nodes += nodes;
        self.bytes += bytes;
        Ok(())
    }
}

impl Encode for str {
    fn encode(&self, encoder: &mut Encoder, field: &str) -> Result<Value> {
        if self.len() > super::json::MAX_STRING {
            return Err(FingerprintImportError::new(Kind::TooLarge, field));
        }
        encoder.claim(field, 1, self.len())?;
        Ok(Value::String(self.into()))
    }
}
impl<T: Encode + ?Sized> Encode for Box<T> {
    fn encode(&self, encoder: &mut Encoder, field: &str) -> Result<Value> {
        self.as_ref().encode(encoder, field)
    }
}
impl<T: Encode> Encode for [T] {
    fn encode(&self, encoder: &mut Encoder, field: &str) -> Result<Value> {
        if self.len() > super::json::MAX_ARRAY {
            return Err(FingerprintImportError::new(Kind::TooLarge, field));
        }
        encoder.claim(field, 1, 0)?;
        self.iter()
            .enumerate()
            .map(|(index, value)| value.encode(encoder, &format!("{field}[{index}]")))
            .collect::<Result<Vec<_>>>()
            .map(Value::Array)
    }
}
impl<T: Encode> Encode for Vec<T> {
    fn encode(&self, encoder: &mut Encoder, field: &str) -> Result<Value> {
        self.as_slice().encode(encoder, field)
    }
}
impl<T: Encode> Encode for Option<T> {
    fn encode(&self, encoder: &mut Encoder, field: &str) -> Result<Value> {
        match self {
            Some(value) => value.encode(encoder, field),
            None => {
                encoder.claim(field, 1, 0)?;
                Ok(Value::Null)
            }
        }
    }
}
macro_rules! scalar {
    ($($ty:ty),+ $(,)?) => { $(impl Encode for $ty {
        fn encode(&self, encoder: &mut Encoder, field: &str) -> Result<Value> {
            encoder.claim(field, 1, 0)?;
            Ok(Value::from(*self))
        }
    })+ };
}
scalar!(bool, u8, u16, u32, u64, usize);
macro_rules! nonzero {
    ($($ty:ty),+ $(,)?) => { $(impl Encode for $ty {
        fn encode(&self, encoder: &mut Encoder, field: &str) -> Result<Value> {
            self.get().encode(encoder, field)
        }
    })+ };
}
nonzero!(NonZeroU8, NonZeroU32, NonZeroUsize);
impl Encode for Duration {
    fn encode(&self, encoder: &mut Encoder, field: &str) -> Result<Value> {
        object!(encoder, field, "seconds" => &self.as_secs(), "nanoseconds" => &self.subsec_nanos())
    }
}

impl Encode for ClientProfile {
    fn encode(&self, encoder: &mut Encoder, field: &str) -> Result<Value> {
        object!(encoder, field,
            "tls" => self.tls(), "tcp" => &self.tcp(), "udp" => &self.udp(),
            "dns_cache" => &self.dns_cache(), "http1" => &self.http1(),
            "http2" => &self.http2(), "http3" => &self.http3(),
            "client_hints" => &self.client_hints(), "websocket" => &self.websocket(),
            "proxy_connect" => &self.proxy_connect(), "cookie_placement" => self.cookie_placement(),
            "request_template" => &self.request_template())
    }
}
impl<T: Encode + ?Sized> Encode for &T {
    fn encode(&self, encoder: &mut Encoder, field: &str) -> Result<Value> {
        (*self).encode(encoder, field)
    }
}

struct BoundedOutput(Vec<u8>);
impl io::Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > super::json::MAX_BYTES.saturating_sub(self.0.len()) {
            return Err(io::Error::other(
                "custom-profile document exceeds size bound",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn describe(profile: &ClientProfile) -> Result<(Value, Vec<u8>)> {
    let mut encoder = Encoder::default();
    let mut document = Map::new();
    document.insert("format".into(), Value::from("phantom.custom-profile"));
    document.insert("version".into(), Value::from(1));
    document.insert("profile".into(), profile.encode(&mut encoder, "profile")?);
    let document = Value::Object(document);
    let mut output = BoundedOutput(Vec::new());
    serde_json::to_writer_pretty(&mut output, &document)
        .map_err(|_| FingerprintImportError::new(Kind::TooLarge, "document"))?;
    // Use the same schema, resource bounds and native validators as edited input.
    let restored = super::import_profile_json(&output.0)?;
    if restored != *profile {
        return Err(FingerprintImportError::new(
            Kind::UnsupportedSetting,
            "profile",
        ));
    }
    Ok((document, output.0))
}
