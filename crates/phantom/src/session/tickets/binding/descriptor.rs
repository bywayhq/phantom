//! Cache policy identity. This data grants no authenticated publication authority.

use std::fmt;

use phantom_net::{ClientCertificate, ServerAuthentication, ServerSpkiPins, SourceBinding};
use phantom_profile::{ClientProfile, QuicTransportParameterKind};
use zeroize::Zeroizing;

use crate::{Route, authority::Endpoint};

use super::{PreparationError, PreparedTicketPolicy, encoding::Encoder, quic, route, tls};

pub(crate) struct TicketClientContext<'a> {
    pub(crate) origin_authentication: ServerAuthentication,
    pub(crate) origin_roots: &'a [Box<[u8]>],
    pub(crate) origin_pins: Option<&'a ServerSpkiPins>,
    pub(crate) proxy_authentication: ServerAuthentication,
    pub(crate) proxy_roots: &'a [Box<[u8]>],
    pub(crate) proxy_pins: Option<&'a ServerSpkiPins>,
    pub(crate) default_certificate: Option<&'a ClientCertificate>,
    /// Already canonicalized with the builder's last mapping winning.
    pub(crate) certificate_origins: &'a [(Endpoint, ClientCertificate)],
    pub(crate) source_binding: &'a SourceBinding,
    pub(crate) http3_early_data: Option<bool>,
}

pub(super) struct ClientContext {
    origin_trust: Zeroizing<Vec<u8>>,
    proxy_trust: Zeroizing<Vec<u8>>,
    default_certificate: Option<[u8; 32]>,
    certificates: Vec<(String, u16, [u8; 32])>,
    source_binding: Zeroizing<Vec<u8>>,
    http3_early_data: Option<bool>,
    credential_subkey: Zeroizing<[u8; 32]>,
}

/// Shared origins retain normal and WebSocket offers in one cache policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TicketCacheLeg {
    Origin,
    HttpProxy,
    ConnectUdp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TicketCacheProtocol {
    Http1,
    Http2,
    Negotiated,
    Http3,
}

#[derive(Eq, PartialEq)]
pub(crate) struct PreparedCacheDescriptor {
    pub(super) policy: Zeroizing<Vec<u8>>,
    pub(super) witness: Zeroizing<Vec<u8>>,
}

impl PreparedCacheDescriptor {
    /// Borrow stable configured policy bytes without granting native authority.
    pub(in crate::session::tickets) fn policy(&self) -> &[u8] {
        &self.policy
    }

    /// Borrow the original configured draw witness without granting a permit.
    pub(in crate::session::tickets) fn source_witness(&self) -> &[u8] {
        &self.witness
    }
}

impl fmt::Debug for PreparedCacheDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedCacheDescriptor")
            .finish_non_exhaustive()
    }
}

fn trust(
    authentication: ServerAuthentication,
    roots: &[Box<[u8]>],
    pins: Option<&ServerSpkiPins>,
) -> Result<Zeroizing<Vec<u8>>, PreparationError> {
    let mut encoder = Encoder::new();
    encoder.bytes(b"phantom-ticket-server-trust")?;
    encoder.u16(2)?;
    match authentication {
        ServerAuthentication::WebPki => {
            encoder.u8(0)?;
            encoder.bytes(
                &phantom_net::bundled_server_root_identity()
                    .map_err(|_| PreparationError::Backend)?,
            )?;
        }
        #[cfg(feature = "danger-disable-verification")]
        ServerAuthentication::DangerDisabled => {
            return Err(PreparationError::Unsupported(
                "disabled server authentication",
            ));
        }
        _ => return Err(PreparationError::Unsupported("ServerAuthentication")),
    }
    encoder.list(roots, |e, der| e.bytes(der))?;
    encoder.option(pins, |e, pins| {
        e.list(pins.sha256_digests(), |e, hash| e.bytes(hash))
    })?;
    Ok(Zeroizing::new(encoder.finish()))
}

fn certificate(value: Option<&ClientCertificate>) -> Result<Option<[u8; 32]>, PreparationError> {
    value
        .map(ClientCertificate::certificate_chain_sha256)
        .transpose()
        .map_err(|_| PreparationError::Backend)
}

impl ClientContext {
    pub(super) fn capture(input: TicketClientContext<'_>) -> Result<Self, PreparationError> {
        let TicketClientContext {
            origin_authentication,
            origin_roots,
            origin_pins,
            proxy_authentication,
            proxy_roots,
            proxy_pins,
            default_certificate,
            certificate_origins,
            source_binding,
            http3_early_data,
        } = input;
        let origin_trust = trust(origin_authentication, origin_roots, origin_pins)?;
        let proxy_trust = trust(proxy_authentication, proxy_roots, proxy_pins)?;
        let default_certificate = certificate(default_certificate)?;
        // Bound every retained mapping, but include only the selected one in a cache descriptor.
        let mut mapping_bound = Encoder::new();
        mapping_bound.usize(certificate_origins.len())?;
        let mut certificates = Vec::new();
        if certificate_origins.len() > super::encoding::MAX_POLICY_BYTES / (4 + 2 + 4 + 32) {
            return Err(PreparationError::TooLarge);
        }
        certificates
            .try_reserve_exact(certificate_origins.len())
            .map_err(|_| PreparationError::Allocation)?;
        for (origin, value) in certificate_origins {
            let content = value
                .certificate_chain_sha256()
                .map_err(|_| PreparationError::Backend)?;
            mapping_bound.text(origin.host())?;
            mapping_bound.u16(origin.port())?;
            mapping_bound.bytes(&content)?;
            let mut host = String::new();
            host.try_reserve_exact(origin.host().len())
                .map_err(|_| PreparationError::Allocation)?;
            host.push_str(origin.host());
            certificates.push((host, origin.port(), content));
        }
        let mut source = Encoder::new();
        source.option(source_binding.ipv4_address().as_ref(), |e, address| {
            e.bytes(&address.octets())
        })?;
        source.option(source_binding.ipv6_address().as_ref(), |e, address| {
            e.bytes(&address.octets())
        })?;
        source.option(source_binding.interface().as_ref(), |e, name| e.text(name))?;
        let mut credential_subkey = Zeroizing::new([0; 32]);
        btls::rand::rand_bytes(&mut *credential_subkey).map_err(|_| PreparationError::Backend)?;
        Ok(Self {
            origin_trust,
            proxy_trust,
            default_certificate,
            certificates,
            source_binding: Zeroizing::new(source.finish()),
            http3_early_data,
            credential_subkey,
        })
    }

    fn selected_certificate(&self, origin: &Endpoint) -> Option<[u8; 32]> {
        self.certificates
            .iter()
            .find(|(host, port, _)| {
                *port == origin.port() && host.eq_ignore_ascii_case(origin.host())
            })
            .map(|(_, _, content)| *content)
            .or(self.default_certificate)
    }
}

impl PreparedTicketPolicy {
    /// Installs configured policy on the actual TCP or QUIC cache owner.
    pub(in crate::session::tickets) fn bind_transfer_policy(
        &self,
        cache: &phantom_net::SessionTicketCacheOwner,
        descriptor: &PreparedCacheDescriptor,
        server_name: &str,
        leg: TicketCacheLeg,
        protocol: TicketCacheProtocol,
        route: &Route,
    ) -> Result<btls::ssl::SessionPolicyBinding, PreparationError> {
        let policy = self.configured_policy(descriptor, leg, protocol, route)?;
        cache
            .bind_transfer_policy(server_name, policy)
            .map_err(native_preparation_error)
    }

    /// Prepares configured native policy without installing a recipient binding.
    pub(in crate::session::tickets) fn configured_policy(
        &self,
        descriptor: &PreparedCacheDescriptor,
        leg: TicketCacheLeg,
        protocol: TicketCacheProtocol,
        route: &Route,
    ) -> Result<btls::ssl::SessionTransferPolicy, PreparationError> {
        let supported = matches!(
            (leg, protocol, route),
            (
                TicketCacheLeg::Origin,
                TicketCacheProtocol::Http3,
                Route::Direct | Route::Socks5(_) | Route::ConnectUdp(_),
            ) | (
                TicketCacheLeg::Origin,
                TicketCacheProtocol::Http1
                    | TicketCacheProtocol::Http2
                    | TicketCacheProtocol::Negotiated,
                Route::Direct | Route::HttpProxy(_) | Route::Socks4(_) | Route::Socks5(_),
            ) | (
                TicketCacheLeg::HttpProxy,
                TicketCacheProtocol::Http1 | TicketCacheProtocol::Http2,
                Route::HttpProxy(_),
            ) | (
                TicketCacheLeg::ConnectUdp,
                TicketCacheProtocol::Http1
                    | TicketCacheProtocol::Http2
                    | TicketCacheProtocol::Http3,
                Route::ConnectUdp(_),
            )
        );
        if !supported {
            return Err(PreparationError::Unsupported("ticket route and protocol"));
        }

        self.validate_source_witness(&descriptor.witness)?;
        let context = self
            .context
            .as_ref()
            .ok_or(PreparationError::Unsupported("missing client context"))?;

        btls::ssl::SessionTransferPolicy::new(
            &descriptor.policy,
            &descriptor.witness,
            crate::route::transfer_credential(route)?,
            &context.credential_subkey,
        )
        .map_err(native_preparation_error)
    }

    pub(in crate::session::tickets) fn allows_early_data(
        &self,
        leg: TicketCacheLeg,
        protocol: TicketCacheProtocol,
        route: &Route,
    ) -> Result<bool, PreparationError> {
        let context = self
            .context
            .as_ref()
            .ok_or(PreparationError::Unsupported("missing client context"))?;
        Ok(match (leg, protocol) {
            (TicketCacheLeg::ConnectUdp, TicketCacheProtocol::Http3) => false,
            (
                _,
                TicketCacheProtocol::Http1
                | TicketCacheProtocol::Http2
                | TicketCacheProtocol::Negotiated,
            ) => {
                matches!(leg, TicketCacheLeg::Origin)
                    && matches!(route, Route::Direct)
                    && self.tcp_early_data
            }
            (_, TicketCacheProtocol::Http3) => {
                context.http3_early_data.unwrap_or(self.quic_early_data)
            }
        })
    }

    pub(crate) fn with_client_context(
        mut self,
        input: TicketClientContext<'_>,
    ) -> Result<Self, PreparationError> {
        self.context = Some(ClientContext::capture(input)?);
        Ok(self)
    }

    /// Uses cache origin and route identity, never its DNS or Alt-Svc dial location.
    pub(crate) fn prepare_cache_descriptor(
        &self,
        origin: &Endpoint,
        server_name: &str,
        leg: TicketCacheLeg,
        protocol: TicketCacheProtocol,
        route: &Route,
    ) -> Result<PreparedCacheDescriptor, PreparationError> {
        let context = self
            .context
            .as_ref()
            .ok_or(PreparationError::Unsupported("missing client context"))?;
        let mut encoder = Encoder::new();
        encoder.bytes(b"phantom-ticket-cache-policy")?;
        encoder.u16(2)?;
        encoder.text(origin.host())?;
        encoder.u16(origin.port())?;
        encoder.text(server_name)?;
        encoder.u8(match leg {
            TicketCacheLeg::Origin => 0,
            TicketCacheLeg::HttpProxy => 1,
            TicketCacheLeg::ConnectUdp => 2,
        })?;
        encoder.u8(match protocol {
            TicketCacheProtocol::Http1 => 0,
            TicketCacheProtocol::Http2 => 1,
            TicketCacheProtocol::Negotiated => 2,
            TicketCacheProtocol::Http3 => 3,
        })?;
        encoder.bytes(&self.canonical)?;
        encoder.bytes(&self.derived_offers)?;
        encoder.bytes(&context.origin_trust)?;
        encoder.bytes(&context.proxy_trust)?;
        let selected = match leg {
            TicketCacheLeg::Origin => context.selected_certificate(origin),
            // Existing proxy constructors never attach an origin client certificate.
            TicketCacheLeg::HttpProxy | TicketCacheLeg::ConnectUdp => None,
        };
        encoder.option(selected.as_ref(), |e, content| e.bytes(content))?;
        encoder.bytes(&context.source_binding)?;
        let early_data = self.allows_early_data(leg, protocol, route)?;
        encoder.bool(early_data)?;
        route::encode(&mut encoder, route)?;
        let mut witness = Encoder::new();
        witness.option(self.tcp_draw.as_ref(), |e, value| e.bytes(value))?;
        witness.option(self.quic_draw.as_ref(), |e, value| e.bytes(value))?;
        Ok(PreparedCacheDescriptor {
            policy: Zeroizing::new(encoder.finish()),
            witness: Zeroizing::new(witness.finish()),
        })
    }
}

fn native_preparation_error(error: btls::ssl::SessionTransferError) -> PreparationError {
    match error {
        btls::ssl::SessionTransferError::TooLarge => PreparationError::TooLarge,
        btls::ssl::SessionTransferError::Allocation => PreparationError::Allocation,
        btls::ssl::SessionTransferError::Policy => {
            PreparationError::Unsupported("native ticket transfer policy")
        }
        _ => PreparationError::Backend,
    }
}

/// Explicit permitted derived offers; selected per-client anchors remain separate.
pub(super) fn derived_offers(
    profile: &ClientProfile,
    tcp_anchors: Option<&phantom_profile::TrustAnchorIds>,
    quic_anchors: Option<&phantom_profile::TrustAnchorIds>,
) -> Result<Zeroizing<Vec<u8>>, PreparationError> {
    let mut encoder = Encoder::new();
    encoder.bytes(b"phantom-ticket-derived-offers")?;
    encoder.u16(1)?;
    tls::encode(&mut encoder, profile.tls(), tcp_anchors)?;
    #[cfg(feature = "websocket")]
    encoder.option(profile.websocket(), |e, settings| {
        let tls_settings = settings.connection.http1_tls_settings(profile.tls());
        tls::encode(e, &tls_settings, tcp_anchors)
    })?;
    #[cfg(not(feature = "websocket"))]
    encoder.u8(0)?;
    encoder.option(profile.http3(), |e, settings| {
        tls::encode(e, settings.tls(), quic_anchors)?;
        let mut outer = settings.quic_transport().clone();
        outer.early_data = false;
        outer
            .wire_parameters
            .retain(|parameter| parameter.kind != QuicTransportParameterKind::InitialRtt);
        quic::encode(e, &outer)
    })?;
    Ok(Zeroizing::new(encoder.finish()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_policy_is_identical_under_distinct_owner_keys()
    -> Result<(), Box<dyn std::error::Error>> {
        let profile = phantom_profile::browser::chrome::v154_windows();
        let source = SourceBinding::new();
        let prepare = |key| -> Result<PreparedTicketPolicy, PreparationError> {
            let mut prepared = super::super::BindingPlan::capture(&profile)?
                .complete(&profile)?
                .with_client_context(TicketClientContext {
                    origin_authentication: ServerAuthentication::WebPki,
                    origin_roots: &[],
                    origin_pins: None,
                    proxy_authentication: ServerAuthentication::WebPki,
                    proxy_roots: &[],
                    proxy_pins: None,
                    default_certificate: None,
                    certificate_origins: &[],
                    source_binding: &source,
                    http3_early_data: None,
                })?;
            prepared
                .context
                .as_mut()
                .ok_or(PreparationError::Backend)?
                .credential_subkey = Zeroizing::new(key);
            Ok(prepared)
        };
        let first = prepare([1; 32])?;
        let second = prepare([2; 32])?;
        let origin = Endpoint::new("origin.example:443".parse()?, 443)?;
        let mut password_bytes = [0_u8; 16];
        btls::rand::rand_bytes(&mut password_bytes)?;
        let password: String = password_bytes
            .into_iter()
            .flat_map(|byte| {
                [
                    char::from(b'a' + (byte >> 4)),
                    char::from(b'a' + (byte & 0x0f)),
                ]
            })
            .collect();
        let routes = [
            Route::Direct,
            Route::http_proxy(
                crate::HttpProxy::new("https://proxy.example")?
                    .with_basic_auth("user", &password)?,
            ),
            Route::http_proxy(
                crate::HttpProxy::new("https://proxy.example")?
                    .with_digest_auth("user", &password)?,
            ),
            Route::socks4(crate::Socks4Proxy::new("socks4a://proxy.example")?),
            Route::socks4(
                crate::Socks4Proxy::new("socks4a://proxy.example")?.with_user_id("user")?,
            ),
            Route::socks5(
                crate::Socks5Proxy::new("socks5h://proxy.example")?
                    .with_username_password("user", &password)?,
            ),
            Route::connect_udp(
                crate::ConnectUdpProxy::new(
                    "https://proxy.example/udp/{target_host}/{target_port}/",
                )?
                .with_basic_auth("user", &password)?,
            ),
        ];
        for route in routes {
            let descriptor = |prepared: &PreparedTicketPolicy| {
                prepared.prepare_cache_descriptor(
                    &origin,
                    origin.host(),
                    TicketCacheLeg::Origin,
                    TicketCacheProtocol::Http1,
                    &route,
                )
            };
            assert_eq!(descriptor(&first)?, descriptor(&second)?);
        }
        Ok(())
    }

    #[test]
    fn invalid_draw_witness_is_rejected_before_native_policy_installation()
    -> Result<(), Box<dyn std::error::Error>> {
        let profile = phantom_profile::browser::chrome::v154_windows();
        let source = SourceBinding::new();
        let prepared = super::super::BindingPlan::capture(&profile)?
            .complete(&profile)?
            .with_client_context(TicketClientContext {
                origin_authentication: ServerAuthentication::WebPki,
                origin_roots: &[],
                origin_pins: None,
                proxy_authentication: ServerAuthentication::WebPki,
                proxy_roots: &[],
                proxy_pins: None,
                default_certificate: None,
                certificate_origins: &[],
                source_binding: &source,
                http3_early_data: None,
            })?;
        let origin = Endpoint::new("origin.example:443".parse()?, 443)?;
        let connector = phantom_net::http1::Http1TlsConnector::new(profile.tls())?
            .with_isolated_session_cache();
        let owner = connector
            .session_ticket_cache()
            .ok_or("missing cache")?
            .upgrade()
            .ok_or("dead cache")?;
        let mut descriptor = prepared.prepare_cache_descriptor(
            &origin,
            origin.host(),
            TicketCacheLeg::Origin,
            TicketCacheProtocol::Http1,
            &Route::Direct,
        )?;
        let witness = std::mem::replace(&mut descriptor.witness, Zeroizing::new(vec![1]));
        assert!(matches!(
            prepared.bind_transfer_policy(
                &owner,
                &descriptor,
                origin.host(),
                TicketCacheLeg::Origin,
                TicketCacheProtocol::Http1,
                &Route::Direct
            ),
            Err(PreparationError::DrawMismatch)
        ));
        descriptor.witness = witness;
        prepared.bind_transfer_policy(
            &owner,
            &descriptor,
            origin.host(),
            TicketCacheLeg::Origin,
            TicketCacheProtocol::Http1,
            &Route::Direct,
        )?;
        Ok(())
    }
}
