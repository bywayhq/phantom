//! Independent fixture encoding; it never asks Phantom to construct a response.

use std::net::IpAddr;

use crate::support::tls::TestResult;

#[derive(Clone, Debug)]
pub(crate) struct Question {
    pub(crate) name: String,
    pub(crate) kind: u16,
    pub(crate) id: u16,
    question: Vec<u8>,
}

impl Question {
    pub(crate) fn read(query: &[u8]) -> TestResult<Self> {
        if query.len() > 65_535 || query.get(4..6) != Some(&[0, 1]) {
            return Err("fixture expected one bounded DNS question".into());
        }
        let id = query.get(..2).ok_or("missing query ID")?;
        let mut cursor = 12;
        let mut labels = Vec::new();
        loop {
            let length = usize::from(*query.get(cursor).ok_or("truncated question")?);
            cursor += 1;
            if length == 0 {
                break;
            }
            if length > 63 || cursor + length > query.len() || cursor + length > 267 {
                return Err("invalid bounded question label".into());
            }
            labels.push(std::str::from_utf8(&query[cursor..cursor + length])?);
            cursor += length;
        }
        let fields = query
            .get(cursor..cursor + 4)
            .ok_or("missing question fields")?;
        if fields[2..] != [0, 1] {
            return Err("fixture expected an IN question".into());
        }
        Ok(Self {
            name: labels.join("."),
            kind: u16::from_be_bytes([fields[0], fields[1]]),
            id: u16::from_be_bytes([id[0], id[1]]),
            question: query[12..cursor + 4].to_vec(),
        })
    }

    pub(crate) fn addresses(&self, addresses: &[IpAddr], ttl: u32) -> TestResult<Vec<u8>> {
        let count = u16::try_from(addresses.len())?;
        let mut message = self.response(0, count, 0);
        for address in addresses {
            let (kind, bytes) = match address {
                IpAddr::V4(address) => (1, address.octets().to_vec()),
                IpAddr::V6(address) => (28, address.octets().to_vec()),
            };
            if kind != self.kind {
                return Err("fixture address does not match question family".into());
            }
            record(&mut message, kind, ttl, &bytes)?;
        }
        bounded(message)
    }

    pub(crate) fn cname(&self, target: &str, ttl: u32) -> TestResult<Vec<u8>> {
        let mut message = self.response(0, 1, 0);
        let target = name(target)?;
        record(&mut message, 5, ttl, &target)?;
        bounded(message)
    }

    pub(crate) fn maximum_address_response(&self) -> TestResult<Vec<u8>> {
        let mut bytes = self.addresses(&[std::net::Ipv4Addr::LOCALHOST.into()], 60)?;
        bytes[10..12].copy_from_slice(&1_u16.to_be_bytes());
        // One root-owned additional NULL RR fills the exact DNS message
        // bound. It does not contribute an answer or a cache lifetime.
        let padding = 65_535_usize
            .checked_sub(bytes.len() + 11)
            .ok_or("maximum fixture overflow")?;
        record_at(&mut bytes, &[0], 10, 0, &vec![0; padding])?;
        if bytes.len() != 65_535 {
            return Err("maximum response missed exact bound".into());
        }
        bounded(bytes)
    }

    pub(crate) fn cname_addresses(
        &self,
        target: &str,
        alias_ttl: u32,
        address_ttl: u32,
    ) -> TestResult<Vec<u8>> {
        if self.kind != 1 {
            return Err("same-message fixture requires A".into());
        }
        let mut message = self.response(0, 2, 0);
        let target = name(target)?;
        record(&mut message, 5, alias_ttl, &target)?;
        record_at(&mut message, &target, 1, address_ttl, &[127, 0, 0, 1])?;
        bounded(message)
    }

    pub(crate) fn negative(&self, nx_domain: bool, soa: Option<(u32, u32)>) -> TestResult<Vec<u8>> {
        let mut message = self.response(u16::from(nx_domain) * 3, 0, u16::from(soa.is_some()));
        if let Some((ttl, minimum)) = soa {
            let mut data = vec![0, 0]; // Root MNAME and RNAME.
            for integer in [1_u32, 2, 3, 4, minimum] {
                data.extend_from_slice(&integer.to_be_bytes());
            }
            record(&mut message, 6, ttl, &data)?;
        }
        bounded(message)
    }

    pub(crate) fn server_failure(&self) -> Vec<u8> {
        self.response(2, 0, 0)
    }

    pub(crate) fn https(&self, ttl: u32, data: &[u8]) -> TestResult<Vec<u8>> {
        if self.kind != 65 {
            return Err("fixture expected an HTTPS question".into());
        }
        let mut message = self.response(0, 1, 0);
        record(&mut message, 65, ttl, data)?;
        bounded(message)
    }

    fn response(&self, code: u16, answers: u16, authorities: u16) -> Vec<u8> {
        let mut bytes = self.id.to_be_bytes().to_vec();
        bytes.extend_from_slice(&(0x8180_u16 | code).to_be_bytes());
        for count in [1_u16, answers, authorities, 0] {
            bytes.extend_from_slice(&count.to_be_bytes());
        }
        bytes.extend_from_slice(&self.question);
        bytes
    }
}

fn record(message: &mut Vec<u8>, kind: u16, ttl: u32, data: &[u8]) -> TestResult<()> {
    record_at(message, &[0xc0, 0x0c], kind, ttl, data)
}

fn record_at(
    message: &mut Vec<u8>,
    owner: &[u8],
    kind: u16,
    ttl: u32,
    data: &[u8],
) -> TestResult<()> {
    message.extend_from_slice(owner);
    message.extend_from_slice(&kind.to_be_bytes());
    message.extend_from_slice(&1_u16.to_be_bytes());
    message.extend_from_slice(&ttl.to_be_bytes());
    message.extend_from_slice(&u16::try_from(data.len())?.to_be_bytes());
    message.extend_from_slice(data);
    Ok(())
}

fn name(value: &str) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    for label in value.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 || !label.is_ascii() {
            return Err("invalid fixture DNS name".into());
        }
        bytes.push(u8::try_from(label.len())?);
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.push(0);
    if bytes.len() > 255 {
        return Err("fixture DNS name exceeds wire bound".into());
    }
    Ok(bytes)
}

fn bounded(bytes: Vec<u8>) -> TestResult<Vec<u8>> {
    if bytes.len() > 65_535 {
        return Err("fixture DNS response exceeds wire bound".into());
    }
    Ok(bytes)
}
