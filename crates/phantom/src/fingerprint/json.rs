//! Bounded structured JSON input; protocol rules remain with native validators.

use super::{FingerprintImportError as ImportError, FingerprintImportErrorKind as Kind, Result};
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use std::{
    fmt,
    num::{NonZeroU32, NonZeroUsize},
    time::Duration,
};

pub(super) const MAX_BYTES: usize = 16 * 1024 * 1024;
const MAX_DEPTH: usize = 16;
pub(super) const MAX_STRING: usize = 64 * 1024;
const MAX_MEMBERS: usize = 64;
pub(super) const MAX_ARRAY: usize = 65_535;
pub(super) const MAX_NODES: usize = 1_048_576;

#[derive(Debug)]
pub(super) enum Value {
    Object(Vec<(Box<str>, Value)>),
    Array(Vec<Value>),
    Text(Box<str>),
    Number(u64),
    Bool(bool),
    Null,
}
#[derive(Default)]
struct Budget {
    nodes: usize,
    failure: Option<Kind>,
}
struct Seed<'a> {
    budget: &'a mut Budget,
    depth: usize,
    permitted: bool,
}
impl Budget {
    fn fail<E: serde::de::Error>(&mut self, kind: Kind) -> E {
        self.failure = Some(kind);
        E::custom("custom-profile input violates its format")
    }
}
impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<Value, D::Error> {
        if !self.permitted || self.depth > MAX_DEPTH || self.budget.nodes >= MAX_NODES {
            return Err(self.budget.fail(Kind::TooLarge));
        }
        self.budget.nodes += 1;
        deserializer.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a bounded custom-profile JSON value")
    }
    fn visit_u64<E: serde::de::Error>(self, value: u64) -> std::result::Result<Value, E> {
        Ok(Value::Number(value))
    }
    fn visit_i64<E: serde::de::Error>(self, _value: i64) -> std::result::Result<Value, E> {
        Err(self.budget.fail(Kind::InvalidValue))
    }
    fn visit_f64<E: serde::de::Error>(self, _value: f64) -> std::result::Result<Value, E> {
        Err(self.budget.fail(Kind::InvalidValue))
    }
    fn visit_bool<E: serde::de::Error>(self, value: bool) -> std::result::Result<Value, E> {
        Ok(Value::Bool(value))
    }
    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> std::result::Result<Value, E> {
        if value.len() > MAX_STRING {
            return Err(self.budget.fail(Kind::TooLarge));
        }
        Ok(Value::Text(value.into()))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> std::result::Result<Value, A::Error> {
        let mut values = Vec::new();
        loop {
            let next = access.next_element_seed(Seed {
                budget: &mut *self.budget,
                depth: self.depth + 1,
                permitted: values.len() < MAX_ARRAY,
            })?;
            let Some(value) = next else { break };
            if values.len() == MAX_ARRAY {
                return Err(self.budget.fail(Kind::TooLarge));
            }
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> std::result::Result<Value, A::Error> {
        let mut fields: Vec<(Box<str>, Value)> = Vec::new();
        while let Some(name) = access.next_key_seed(KeySeed {
            budget: &mut *self.budget,
            permitted: fields.len() < MAX_MEMBERS,
        })? {
            if fields.len() == MAX_MEMBERS {
                return Err(self.budget.fail(Kind::TooLarge));
            }
            if fields.iter().any(|(previous, _)| *previous == name) {
                return Err(self.budget.fail(Kind::DuplicateField));
            }
            let value = access.next_value_seed(Seed {
                budget: &mut *self.budget,
                depth: self.depth + 1,
                permitted: true,
            })?;
            fields.push((name, value));
        }
        Ok(Value::Object(fields))
    }
}
struct KeySeed<'a> {
    budget: &'a mut Budget,
    permitted: bool,
}
impl<'de> DeserializeSeed<'de> for KeySeed<'_> {
    type Value = Box<str>;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        d: D,
    ) -> std::result::Result<Box<str>, D::Error> {
        d.deserialize_str(self)
    }
}
impl<'de> Visitor<'de> for KeySeed<'_> {
    type Value = Box<str>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a bounded object key")
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> std::result::Result<Box<str>, E> {
        if !self.permitted || value.len() > MAX_STRING {
            return Err(self.budget.fail(Kind::TooLarge));
        }
        Ok(value.into())
    }
}
pub(super) fn parse(input: &[u8]) -> Result<Value> {
    if input.len() > MAX_BYTES {
        return Err(ImportError::new(Kind::TooLarge, "document"));
    }
    let mut budget = Budget::default();
    let mut d = serde_json::Deserializer::from_slice(input);
    let value = Seed {
        budget: &mut budget,
        depth: 0,
        permitted: true,
    }
    .deserialize(&mut d)
    .map_err(|_| ImportError::new(budget.failure.unwrap_or(Kind::MalformedJson), "document"))?;
    d.end()
        .map_err(|_| ImportError::new(Kind::MalformedJson, "document"))?;
    Ok(value)
}
impl Value {
    pub(super) fn record(&self, keys: &[&str], field: &str) -> Result<()> {
        let Self::Object(values) = self else {
            return Err(ImportError::new(Kind::InvalidValue, field));
        };
        if values.iter().any(|(key, _)| !keys.contains(&key.as_ref())) {
            return Err(ImportError::new(Kind::UnsupportedSetting, field));
        }
        if keys
            .iter()
            .any(|key| !values.iter().any(|(name, _)| name.as_ref() == *key))
        {
            return Err(ImportError::new(Kind::MissingField, field));
        }
        Ok(())
    }
    pub(super) fn member(&self, key: &str, field: &str) -> Result<&Self> {
        let Self::Object(values) = self else {
            return Err(ImportError::new(Kind::InvalidValue, field));
        };
        values
            .iter()
            .find(|(name, _)| name.as_ref() == key)
            .map(|(_, v)| v)
            .ok_or_else(|| ImportError::new(Kind::MissingField, field))
    }
    pub(super) fn text(&self, field: &str) -> Result<&str> {
        match self {
            Self::Text(v) => Ok(v),
            _ => Err(ImportError::new(Kind::InvalidValue, field)),
        }
    }
    pub(super) fn boolean(&self, field: &str) -> Result<bool> {
        match self {
            Self::Bool(v) => Ok(*v),
            _ => Err(ImportError::new(Kind::InvalidValue, field)),
        }
    }
    pub(super) fn number(&self, field: &str) -> Result<u64> {
        match self {
            Self::Number(v) => Ok(*v),
            _ => Err(ImportError::new(Kind::InvalidValue, field)),
        }
    }
    pub(super) fn integer<T: TryFrom<u64>>(&self, field: &str) -> Result<T> {
        T::try_from(self.number(field)?).map_err(|_| ImportError::new(Kind::InvalidValue, field))
    }
    pub(super) fn array(&self, field: &str) -> Result<&[Self]> {
        match self {
            Self::Array(v) => Ok(v),
            _ => Err(ImportError::new(Kind::InvalidValue, field)),
        }
    }
    pub(super) fn list<T>(
        &self,
        field: &str,
        mut parse: impl FnMut(&Self) -> Result<T>,
    ) -> Result<Vec<T>> {
        self.array(field)?.iter().map(&mut parse).collect()
    }
    pub(super) fn bytes(&self, field: &str) -> Result<Box<[u8]>> {
        Ok(self
            .list(field, |value| value.integer::<u8>(field))?
            .into_boxed_slice())
    }
    pub(super) fn optional<T>(&self, parse: impl FnOnce(&Self) -> Result<T>) -> Result<Option<T>> {
        if matches!(self, Self::Null) {
            Ok(None)
        } else {
            parse(self).map(Some)
        }
    }
    pub(super) fn null(&self, field: &str) -> Result<()> {
        if matches!(self, Self::Null) {
            Ok(())
        } else {
            Err(ImportError::new(Kind::InvalidValue, field))
        }
    }
    pub(super) fn duration(&self, field: &str) -> Result<Duration> {
        self.record(&["seconds", "nanoseconds"], field)?;
        let seconds = self.member("seconds", field)?.number(field)?;
        let nanos = self.member("nanoseconds", field)?.integer::<u32>(field)?;
        if nanos >= 1_000_000_000 {
            return Err(ImportError::new(Kind::InvalidValue, field));
        }
        Ok(Duration::new(seconds, nanos))
    }
    pub(super) fn nonzero_usize(&self, field: &str) -> Result<NonZeroUsize> {
        NonZeroUsize::new(self.integer(field)?)
            .ok_or_else(|| ImportError::new(Kind::InvalidValue, field))
    }
    pub(super) fn nonzero_u32(&self, field: &str) -> Result<NonZeroU32> {
        NonZeroU32::new(self.integer(field)?)
            .ok_or_else(|| ImportError::new(Kind::InvalidValue, field))
    }
}
pub(super) fn unsupported(field: &str) -> ImportError {
    ImportError::new(Kind::UnsupportedSetting, field)
}
pub(super) fn invalid(field: &str) -> ImportError {
    ImportError::new(Kind::InvalidValue, field)
}
