//! A TCP traversal and its weak DNS-record failure witness.

use std::{io, net::SocketAddr, sync::Arc};

use super::{
    DnsConfigurationToken,
    address_feedback::{AddressCursor, AddressRecord, SelectedAddress},
};
use crate::{SourceBinding, destination_policy::DestinationAdmission};

#[derive(Clone)]
pub(crate) struct TcpAddresses {
    addresses: Vec<SocketAddr>,
    record: Option<Arc<AddressRecord>>,
    port: u16,
    configuration: Option<DnsConfigurationToken>,
    source: Option<SourceBinding>,
    admission: Option<Arc<DestinationAdmission>>,
}

#[derive(Clone)]
pub(crate) struct TcpAddressCursor {
    addresses: std::vec::IntoIter<SocketAddr>,
    record: Option<AddressCursor>,
    port: u16,
    configuration: Option<DnsConfigurationToken>,
    source: Option<SourceBinding>,
    admission: Option<Arc<DestinationAdmission>>,
}

/// Only the socket-connect operation consumes this witness on failure.
pub(crate) struct TcpCandidate {
    address: SocketAddr,
    selected: Option<SelectedAddress>,
    configuration: Option<DnsConfigurationToken>,
}

impl From<Vec<SocketAddr>> for TcpAddresses {
    fn from(addresses: Vec<SocketAddr>) -> Self {
        Self {
            addresses,
            record: None,
            port: 0,
            configuration: None,
            source: None,
            admission: None,
        }
    }
}

impl TcpAddresses {
    pub(crate) fn cached(
        addresses: Vec<SocketAddr>,
        record: Option<Arc<AddressRecord>>,
        port: u16,
        configuration: Option<DnsConfigurationToken>,
    ) -> Self {
        Self {
            addresses,
            record,
            port,
            configuration,
            source: None,
            admission: None,
        }
    }

    pub(crate) fn with_source(mut self, source: Option<&SourceBinding>) -> io::Result<Self> {
        if let Some(source) = source {
            self.addresses = source.usable_addresses(self.addresses)?;
            self.source = Some(source.clone());
        }
        Ok(self)
    }

    pub(crate) fn with_destination_policy(
        mut self,
        policy: Option<&crate::DestinationPolicy>,
    ) -> Self {
        self.admission = policy.map(|policy| Arc::new(DestinationAdmission::new(policy.clone())));
        self
    }

    pub(crate) fn admission(&self) -> Option<Arc<DestinationAdmission>> {
        self.admission.clone()
    }

    pub(crate) fn cursor(&self) -> TcpAddressCursor {
        TcpAddressCursor {
            addresses: self.addresses.clone().into_iter(),
            record: self.record.as_ref().map(AddressRecord::cursor),
            port: self.port,
            configuration: self.configuration.clone(),
            source: self.source.clone(),
            admission: self.admission.clone(),
        }
    }
}

impl TcpAddressCursor {
    pub(crate) fn next(&mut self) -> Option<TcpCandidate> {
        self.next_matching(None)
    }

    pub(crate) fn next_matching(&mut self, ipv6: Option<bool>) -> Option<TcpCandidate> {
        loop {
            let candidate = self.next_unchecked(ipv6)?;
            if self
                .admission
                .as_ref()
                .is_none_or(|admission| admission.permits(candidate.address))
            {
                return Some(candidate);
            }
        }
    }

    fn next_unchecked(&mut self, ipv6: Option<bool>) -> Option<TcpCandidate> {
        let accepts = |address: &SocketAddr| {
            ipv6.is_none_or(|ipv6| address.is_ipv6() == ipv6)
                && self
                    .source
                    .as_ref()
                    .is_none_or(|source| source.permits(address))
        };
        match &mut self.record {
            Some(record) => {
                let selected = record.next_matching(accepts)?;
                let mut address = selected.address();
                address.set_port(self.port);
                Some(TcpCandidate {
                    address,
                    selected: Some(selected),
                    configuration: self.configuration.clone(),
                })
            }
            None => self.addresses.find(accepts).map(|address| TcpCandidate {
                address,
                selected: None,
                configuration: None,
            }),
        }
    }
}

impl TcpCandidate {
    pub(crate) const fn address(&self) -> SocketAddr {
        self.address
    }

    /// Call only after an actual connect, never socket creation/options/bind,
    /// TLS, proxy negotiation, authentication, or cancellation.
    pub(crate) fn failed_connect(&self) -> io::Result<()> {
        if self
            .configuration
            .as_ref()
            .is_some_and(|token| !token.is_current().unwrap_or(false))
        {
            return Ok(());
        }
        if let Some(selected) = &self.selected {
            selected.report_unusable().map_err(io::Error::other)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
