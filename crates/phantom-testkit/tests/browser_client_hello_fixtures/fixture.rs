use std::{collections::BTreeMap, io, net::SocketAddr};

const HEADER_FIELDS: &[&str] = &[
    "format",
    "captured_at_unix",
    "browser",
    "browser_version",
    "operating_system",
    "hostname",
    "listen_address",
    "launch_mode",
    "launch_arguments",
    "record_count",
];
const REQUIRED_SUMMARY_FIELDS: &[&str] = &["legacy_version", "cipher_suites"];
const OPTIONAL_SUMMARY_FIELDS: &[&str] = &[
    "extension_types",
    "supported_groups",
    "ec_point_formats",
    "signature_algorithms",
    "alpn_protocols_hex",
    "supported_versions",
    "key_share_groups",
    "server_name_hex",
];

pub(super) struct Fixture<'a> {
    fields: BTreeMap<&'a str, &'a str>,
    records: Vec<Vec<u8>>,
}

impl<'a> Fixture<'a> {
    pub(super) fn parse(text: &'a str) -> Result<Self, io::Error> {
        let mut lines = FixtureLines::new(text);
        let mut fields = BTreeMap::new();
        for &field in HEADER_FIELDS {
            let value = lines.value(field)?;
            require_single_line(field, value)?;
            if field != "launch_arguments" {
                require_nonempty(field, value)?;
            }
            fields.insert(field, value);
        }
        if fields["format"] != "phantom-client-hello-v2" {
            return Err(invalid_fixture("unexpected ClientHello fixture format"));
        }

        let captured_at = parse_number::<u64>(&fields, "captured_at_unix")?;
        if captured_at == 0 {
            return Err(invalid_fixture("captured_at_unix must be nonzero"));
        }
        let address = fields["listen_address"]
            .parse::<SocketAddr>()
            .map_err(|error| invalid_fixture(format!("invalid listen_address: {error}")))?;
        if !address.ip().is_loopback() {
            return Err(invalid_fixture("listen_address must be loopback"));
        }

        let record_count = parse_number::<usize>(&fields, "record_count")?;
        if !(1..=16).contains(&record_count) {
            return Err(invalid_fixture("record_count must be in 1..=16"));
        }
        let mut records = Vec::with_capacity(record_count);
        for index in 0..record_count {
            let field = format!("record_{index}_hex");
            let value = lines.value(&field)?;
            require_nonempty(&field, value)?;
            records.push(parse_hex(value, &field)?);
        }
        for &field in REQUIRED_SUMMARY_FIELDS {
            let value = lines.value(field)?;
            require_single_line(field, value)?;
            require_nonempty(field, value)?;
            fields.insert(field, value);
        }
        for &field in OPTIONAL_SUMMARY_FIELDS {
            let value = lines.value(field)?;
            require_single_line(field, value)?;
            fields.insert(field, value);
        }
        lines.finish()?;

        Ok(Self { fields, records })
    }

    pub(super) fn value(&self, field: &str) -> Result<&'a str, io::Error> {
        self.fields
            .get(field)
            .copied()
            .ok_or_else(|| invalid_fixture(format!("missing fixture field {field}")))
    }

    pub(super) fn records(&self) -> &[Vec<u8>] {
        &self.records
    }
}

struct FixtureLines<'a> {
    lines: std::iter::Enumerate<std::str::Lines<'a>>,
}

impl<'a> FixtureLines<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            lines: input.lines().enumerate(),
        }
    }

    fn value(&mut self, expected_key: &str) -> Result<&'a str, io::Error> {
        let (index, line) = self
            .lines
            .next()
            .ok_or_else(|| invalid_fixture(format!("missing fixture field {expected_key}")))?;
        let (actual_key, value) = line
            .split_once('=')
            .ok_or_else(|| invalid_fixture(format!("line {} is not key=value", index + 1)))?;
        if actual_key != expected_key {
            return Err(invalid_fixture(format!(
                "line {} has key {actual_key:?}; expected {expected_key:?}",
                index + 1
            )));
        }
        Ok(value)
    }

    fn finish(mut self) -> Result<(), io::Error> {
        if let Some((index, line)) = self.lines.next() {
            return Err(invalid_fixture(format!(
                "unexpected fixture line {}: {line:?}",
                index + 1
            )));
        }
        Ok(())
    }
}

fn require_nonempty(field: &str, value: &str) -> Result<(), io::Error> {
    if value.is_empty() {
        return Err(invalid_fixture(format!("empty fixture field {field}")));
    }
    Ok(())
}

fn require_single_line(field: &str, value: &str) -> Result<(), io::Error> {
    if value.contains(['\r', '\n']) {
        return Err(invalid_fixture(format!(
            "fixture field {field} must fit on one line"
        )));
    }
    Ok(())
}

fn parse_number<T>(fields: &BTreeMap<&str, &str>, field: &str) -> Result<T, io::Error>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    fields[field]
        .parse()
        .map_err(|error| invalid_fixture(format!("invalid {field}: {error}")))
}

fn parse_hex(value: &str, field: &str) -> Result<Vec<u8>, io::Error> {
    if value.len() % 2 != 0 {
        return Err(invalid_fixture(format!("{field} contains odd-length hex")));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?))
        .collect()
}

fn hex_nibble(byte: u8) -> Result<u8, io::Error> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(invalid_fixture(format!(
            "fixture contains non-lowercase-hex byte {byte:#04x}"
        ))),
    }
}

pub(super) fn u16_list(values: &[u16]) -> String {
    values
        .iter()
        .map(|value| format!("{value:#06x}"))
        .collect::<Vec<_>>()
        .join(",")
}

pub(super) fn u8_list(values: &[u8]) -> String {
    values
        .iter()
        .map(|value| format!("{value:#04x}"))
        .collect::<Vec<_>>()
        .join(",")
}

pub(super) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";

    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

pub(super) fn invalid_fixture(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::{Fixture, OPTIONAL_SUMMARY_FIELDS};

    const VALID: &str = crate::FIXTURE_TEXT;

    #[test]
    fn rejects_duplicate_and_misordered_fields() {
        let malformed = format!("{VALID}browser=duplicate\n");
        assert!(Fixture::parse(&malformed).is_err());

        let mut lines = VALID.lines().collect::<Vec<_>>();
        lines.swap(1, 2);
        assert!(Fixture::parse(&lines.join("\n")).is_err());
    }

    #[test]
    fn rejects_missing_and_empty_fields() {
        let missing = VALID
            .lines()
            .filter(|line| !line.starts_with("hostname="))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(Fixture::parse(&missing).is_err());

        let empty = VALID.replace("hostname=server.phantom.test", "hostname=");
        assert!(Fixture::parse(&empty).is_err());
    }

    #[test]
    fn allows_empty_launch_arguments_and_optional_semantic_vectors() {
        let without_launch_arguments = replace_value(VALID, "launch_arguments", "");
        assert!(Fixture::parse(&without_launch_arguments).is_ok());

        for &field in OPTIONAL_SUMMARY_FIELDS {
            let empty = replace_value(VALID, field, "");
            assert!(Fixture::parse(&empty).is_ok(), "field {field} was rejected");
        }
    }

    #[test]
    fn rejects_multiline_launch_arguments() {
        for separator in ['\r', '\n'] {
            let multiline = replace_value(VALID, "launch_arguments", &format!("a{separator}b"));
            assert!(Fixture::parse(&multiline).is_err());
        }
    }

    #[test]
    fn rejects_unknown_fields_and_record_count_mismatch() {
        let unknown = format!("{VALID}unknown=value\n");
        assert!(Fixture::parse(&unknown).is_err());

        let missing_record = VALID.replace("record_count=1", "record_count=2");
        assert!(Fixture::parse(&missing_record).is_err());
    }

    #[test]
    fn rejects_malformed_lines_and_hex() {
        let malformed_line = format!("{VALID}not-key-value\n");
        assert!(Fixture::parse(&malformed_line).is_err());

        let malformed_hex = VALID.replacen("record_0_hex=16", "record_0_hex=1z", 1);
        assert!(Fixture::parse(&malformed_hex).is_err());
    }

    fn replace_value(input: &str, field: &str, replacement: &str) -> String {
        let prefix = format!("{field}=");
        input
            .lines()
            .map(|line| {
                line.strip_prefix(&prefix)
                    .map_or_else(|| line.to_owned(), |_| format!("{prefix}{replacement}"))
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}
