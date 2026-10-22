use phantom_profile::{
    DnsAddressFailurePolicy, Http2CookieCrumbs, Http2FieldIndexing, Http2HuffmanCoding,
    Http2IndexingLimit, Http2NameReference, Http2PseudoHeader, Http2SensitiveProxyAuthorization,
    Http2StaticNameIndex, Http2TableSizeUpdates, Http2UnindexedMatch, Http3AltUsed,
    Http3AltUsedPort, Http3CookieCrumbs, Http3PseudoHeader, Http3QpackDecoderStream,
    Http3QpackEncoderStream, Http3QpackEncoding, Http3QpackStreamOrder, Http3SettingOrder,
    SystemDnsTtlPolicy, TcpAddressAdvance,
};

use super::{PreparationError, encoding::Encoder};

fn tcp_address_advance(e: &mut Encoder, value: &TcpAddressAdvance) -> Result<(), PreparationError> {
    e.u8(match value {
        TcpAddressAdvance::AfterAnyFailure => 0,
        TcpAddressAdvance::AfterRefusalOrTimeout => 1,
        _ => return Err(PreparationError::Unsupported("TcpAddressAdvance")),
    })
}

fn http2_pseudo_header(e: &mut Encoder, value: &Http2PseudoHeader) -> Result<(), PreparationError> {
    e.u8(match value {
        Http2PseudoHeader::Method => 0,
        Http2PseudoHeader::Authority => 1,
        Http2PseudoHeader::Scheme => 2,
        Http2PseudoHeader::Path => 3,
        Http2PseudoHeader::Protocol => 4,
        _ => return Err(PreparationError::Unsupported("Http2PseudoHeader")),
    })
}

fn http2_static_name_index(
    e: &mut Encoder,
    value: &Http2StaticNameIndex,
) -> Result<(), PreparationError> {
    e.u8(match value {
        Http2StaticNameIndex::Lowest => 0,
        Http2StaticNameIndex::Highest => 1,
        _ => return Err(PreparationError::Unsupported("Http2StaticNameIndex")),
    })
}

fn http2_huffman_coding(
    e: &mut Encoder,
    value: &Http2HuffmanCoding,
) -> Result<(), PreparationError> {
    e.u8(match value {
        Http2HuffmanCoding::Always => 0,
        Http2HuffmanCoding::WhenShorter => 1,
        Http2HuffmanCoding::WhenNotLonger => 2,
        Http2HuffmanCoding::AlwaysIncludingEmpty => 3,
        _ => return Err(PreparationError::Unsupported("Http2HuffmanCoding")),
    })
}

fn http2_cookie_crumbs(e: &mut Encoder, value: &Http2CookieCrumbs) -> Result<(), PreparationError> {
    e.u8(match value {
        Http2CookieCrumbs::Whole => 0,
        Http2CookieCrumbs::IndexAll => 1,
        Http2CookieCrumbs::NeverIndexShort => 2,
        _ => return Err(PreparationError::Unsupported("Http2CookieCrumbs")),
    })
}

fn http2_field_indexing(
    e: &mut Encoder,
    value: &Http2FieldIndexing,
) -> Result<(), PreparationError> {
    e.u8(match value {
        Http2FieldIndexing::Nghttp2 => 0,
        Http2FieldIndexing::All => 1,
        Http2FieldIndexing::NeverIndexAuthorization => 2,
        _ => return Err(PreparationError::Unsupported("Http2FieldIndexing")),
    })
}

fn http2_name_reference(
    e: &mut Encoder,
    value: &Http2NameReference,
) -> Result<(), PreparationError> {
    e.u8(match value {
        Http2NameReference::StaticUnlessSensitive => 0,
        Http2NameReference::StaticThenNewest => 1,
        Http2NameReference::OldestDynamic => 2,
        _ => return Err(PreparationError::Unsupported("Http2NameReference")),
    })
}

fn http2_unindexed_match(
    e: &mut Encoder,
    value: &Http2UnindexedMatch,
) -> Result<(), PreparationError> {
    e.u8(match value {
        Http2UnindexedMatch::Index => 0,
        Http2UnindexedMatch::Literal => 1,
        _ => return Err(PreparationError::Unsupported("Http2UnindexedMatch")),
    })
}

fn http2_indexing_limit(
    e: &mut Encoder,
    value: &Http2IndexingLimit,
) -> Result<(), PreparationError> {
    e.u8(match value {
        Http2IndexingLimit::ThreeQuarters => 0,
        Http2IndexingLimit::Half => 1,
        Http2IndexingLimit::Unlimited => 2,
        Http2IndexingLimit::FullTable => 3,
        _ => return Err(PreparationError::Unsupported("Http2IndexingLimit")),
    })
}

fn http2_table_size_updates(
    e: &mut Encoder,
    value: &Http2TableSizeUpdates,
) -> Result<(), PreparationError> {
    e.u8(match value {
        Http2TableSizeUpdates::WhenChanged => 0,
        Http2TableSizeUpdates::EverySetting => 1,
        _ => return Err(PreparationError::Unsupported("Http2TableSizeUpdates")),
    })
}

fn http2_sensitive_proxy_authorization(
    e: &mut Encoder,
    value: &Http2SensitiveProxyAuthorization,
) -> Result<(), PreparationError> {
    e.u8(match value {
        Http2SensitiveProxyAuthorization::NeverIndexed => 0,
        Http2SensitiveProxyAuthorization::FieldIndexing => 1,
        _ => {
            return Err(PreparationError::Unsupported(
                "Http2SensitiveProxyAuthorization",
            ));
        }
    })
}

fn http3_setting_order(e: &mut Encoder, value: &Http3SettingOrder) -> Result<(), PreparationError> {
    e.u8(match value {
        Http3SettingOrder::Fixed => 0,
        Http3SettingOrder::Ascending => 1,
        _ => return Err(PreparationError::Unsupported("Http3SettingOrder")),
    })
}

fn http3_qpack_encoding(
    e: &mut Encoder,
    value: &Http3QpackEncoding,
) -> Result<(), PreparationError> {
    e.u8(match value {
        Http3QpackEncoding::Stateless => 0,
        Http3QpackEncoding::Dynamic => 1,
        Http3QpackEncoding::DynamicUnmatchedNames => 2,
        _ => return Err(PreparationError::Unsupported("Http3QpackEncoding")),
    })
}

fn http3_qpack_decoder_stream(
    e: &mut Encoder,
    value: &Http3QpackDecoderStream,
) -> Result<(), PreparationError> {
    e.u8(match value {
        Http3QpackDecoderStream::Eager => 0,
        Http3QpackDecoderStream::OnFeedback => 1,
        _ => return Err(PreparationError::Unsupported("Http3QpackDecoderStream")),
    })
}

fn http3_qpack_stream_order(
    e: &mut Encoder,
    value: &Http3QpackStreamOrder,
) -> Result<(), PreparationError> {
    e.u8(match value {
        Http3QpackStreamOrder::EncoderFirst => 0,
        Http3QpackStreamOrder::DecoderFirst => 1,
        _ => return Err(PreparationError::Unsupported("Http3QpackStreamOrder")),
    })
}

fn http3_qpack_encoder_stream(
    e: &mut Encoder,
    value: &Http3QpackEncoderStream,
) -> Result<(), PreparationError> {
    e.u8(match value {
        Http3QpackEncoderStream::Eager => 0,
        Http3QpackEncoderStream::OnFirstInstruction => 1,
        _ => return Err(PreparationError::Unsupported("Http3QpackEncoderStream")),
    })
}

fn http3_pseudo_header(e: &mut Encoder, value: &Http3PseudoHeader) -> Result<(), PreparationError> {
    e.u8(match value {
        Http3PseudoHeader::Method => 0,
        Http3PseudoHeader::Authority => 1,
        Http3PseudoHeader::Scheme => 2,
        Http3PseudoHeader::Path => 3,
        Http3PseudoHeader::Protocol => 4,
        _ => return Err(PreparationError::Unsupported("Http3PseudoHeader")),
    })
}

fn http3_cookie_crumbs(e: &mut Encoder, value: &Http3CookieCrumbs) -> Result<(), PreparationError> {
    e.u8(match value {
        Http3CookieCrumbs::Whole => 0,
        Http3CookieCrumbs::Split => 1,
        _ => return Err(PreparationError::Unsupported("Http3CookieCrumbs")),
    })
}

fn http3_alt_used_port(e: &mut Encoder, value: &Http3AltUsedPort) -> Result<(), PreparationError> {
    e.u8(match value {
        Http3AltUsedPort::Explicit => 0,
        Http3AltUsedPort::OmitDefault => 1,
        _ => return Err(PreparationError::Unsupported("Http3AltUsedPort")),
    })
}

fn http3_alt_used(e: &mut Encoder, value: &Http3AltUsed) -> Result<(), PreparationError> {
    e.u8(match value {
        Http3AltUsed::Omit => 0,
        Http3AltUsed::Append => 1,
        Http3AltUsed::ValidatedMapping => 2,
        _ => return Err(PreparationError::Unsupported("Http3AltUsed")),
    })
}
use phantom_profile::{
    DnsCacheSettings, Http1IdleTimeout, Http1Settings, Http2HpackSettings, Http2IdleTimeout,
    Http2Priority, Http2Setting, Http2Settings, Http2StreamSettings, Http3RequestSettings,
    Http3Setting, Http3Settings, TcpAddressRacing, TcpAddressSelection, TcpBackupConnection,
    TcpKeepalive, TcpKeepalivePolicy, TcpKeepaliveSchedule, TcpPortRandomization, TcpSettings,
    UdpSettings,
};

pub(super) fn tcp(e: &mut Encoder, value: &TcpSettings) -> Result<(), PreparationError> {
    let TcpSettings {
        nodelay,
        send_buffer_size,
        keepalive,
        address_selection,
        port_randomization,
    } = value;
    e.bool(*nodelay)?;
    e.option(send_buffer_size.as_ref(), |e, value| e.u32(value.get()))?;
    match keepalive {
        TcpKeepalivePolicy::Unchanged => e.u8(0)?,
        TcpKeepalivePolicy::Fixed(value) => {
            let TcpKeepalive { idle, interval } = value;
            e.u8(1)?;
            e.duration(*idle)?;
            e.option(interval.as_ref(), |e, value| e.duration(*value))?;
        }
        TcpKeepalivePolicy::Schedule(value) => {
            let TcpKeepaliveSchedule {
                short_lived_idle,
                long_lived_idle,
                minimum_interval,
                short_lived_time,
                probe_count,
                set_interval,
                set_probe_count,
            } = value;
            e.u8(2)?;
            e.duration(*short_lived_idle)?;
            e.duration(*long_lived_idle)?;
            e.duration(*minimum_interval)?;
            e.duration(*short_lived_time)?;
            e.u32(*probe_count)?;
            e.bool(*set_interval)?;
            e.bool(*set_probe_count)?;
        }
        _ => return Err(PreparationError::Unsupported("keepalive")),
    }
    match address_selection {
        TcpAddressSelection::Sequential(value) => {
            e.u8(0)?;
            tcp_address_advance(e, value)?;
        }
        TcpAddressSelection::Racing(value) => {
            let TcpAddressRacing { fallback_delay } = value;
            e.u8(1)?;
            e.duration(*fallback_delay)?;
        }
        TcpAddressSelection::Backup(value) => {
            let TcpBackupConnection {
                delay,
                known_family_backup_timeout,
            } = value;
            e.u8(2)?;
            e.duration(*delay)?;
            e.option(known_family_backup_timeout.as_ref(), |e, value| {
                e.duration(*value)
            })?;
        }
        _ => return Err(PreparationError::Unsupported("address_selection")),
    }
    e.option(port_randomization.as_ref(), |e, value| {
        let TcpPortRandomization {
            minimum_windows_build,
        } = value;
        e.u32(*minimum_windows_build)
    })
}

pub(super) fn udp(e: &mut Encoder, value: &UdpSettings) -> Result<(), PreparationError> {
    let UdpSettings { port_randomization } = value;
    e.bool(*port_randomization)
}

pub(super) fn dns(e: &mut Encoder, value: &DnsCacheSettings) -> Result<(), PreparationError> {
    let DnsCacheSettings {
        address_failure_policy,
        max_entries,
        ttl,
        min_record_ttl,
        negative_ttl,
        system_ttl,
    } = value;
    match address_failure_policy {
        DnsAddressFailurePolicy::Ignore => e.u8(0)?,
        DnsAddressFailurePolicy::Record {
            max_unusable_addresses,
        } => {
            e.u8(1)?;
            e.usize(max_unusable_addresses.get())?;
        }
    }
    e.u8(match system_ttl {
        SystemDnsTtlPolicy::Ignore => 0,
        SystemDnsTtlPolicy::FirefoxWindows => 1,
    })?;
    e.usize(max_entries.get())?;
    e.duration(*ttl)?;
    e.duration(*min_record_ttl)?;
    e.option(negative_ttl.as_ref(), |e, value| e.duration(*value))
}

pub(super) fn http1(e: &mut Encoder, value: &Http1Settings) -> Result<(), PreparationError> {
    let Http1Settings {
        max_connections_per_origin,
        idle_timeout,
    } = value;
    e.usize(max_connections_per_origin.get())?;
    match idle_timeout {
        Http1IdleTimeout::Unlimited => e.u8(0),
        Http1IdleTimeout::CheckedOnRequest(value) => {
            e.u8(1)?;
            e.duration(*value)
        }
        Http1IdleTimeout::ClosedOnTimer(value) => {
            e.u8(2)?;
            e.duration(*value)
        }
        _ => Err(PreparationError::Unsupported("http1_idle")),
    }
}

pub(super) fn priority(e: &mut Encoder, value: &Http2Priority) -> Result<(), PreparationError> {
    let Http2Priority {
        dependency_stream_id,
        weight,
        exclusive,
    } = value;
    e.u32(*dependency_stream_id)?;
    e.u16(*weight)?;
    e.bool(*exclusive)
}

pub(super) fn http2(e: &mut Encoder, value: &Http2Settings) -> Result<(), PreparationError> {
    let Http2Settings {
        initial_settings,
        initial_connection_window_size,
        initial_stream_window_target,
        pseudo_header_order,
        extended_connect_pseudo_header_order,
        headers_priority,
        extended_connect_priority,
        hpack,
        streams,
        preface_ping_after,
        ping_timeout,
        ping_failure_retries,
        idle_ping_after,
        idle_ping_timeout,
        idle_timeout,
    } = value;
    e.list(initial_settings, http2_setting)?;
    e.u32(*initial_connection_window_size)?;
    e.option(initial_stream_window_target.as_ref(), |e, value| {
        e.u32(*value)
    })?;
    e.list(pseudo_header_order, http2_pseudo_header)?;
    e.option(extended_connect_pseudo_header_order.as_ref(), |e, value| {
        e.list(value, http2_pseudo_header)
    })?;
    e.option(headers_priority.as_ref(), priority)?;
    e.option(extended_connect_priority.as_ref(), priority)?;
    encode_hpack(e, hpack)?;
    encode_streams(e, streams)?;
    e.option(preface_ping_after.as_ref(), |e, value| e.duration(*value))?;
    e.option(ping_timeout.as_ref(), |e, value| e.duration(*value))?;
    e.u8(*ping_failure_retries)?;
    e.option(idle_ping_after.as_ref(), |e, value| e.duration(*value))?;
    e.option(idle_ping_timeout.as_ref(), |e, value| e.duration(*value))?;
    match idle_timeout {
        Http2IdleTimeout::Unlimited => e.u8(0)?,
        Http2IdleTimeout::ClosedOnTimer(value) => {
            e.u8(1)?;
            e.duration(*value)?;
        }
        _ => return Err(PreparationError::Unsupported("http2_idle")),
    }
    Ok(())
}

pub(super) fn encode_hpack(
    e: &mut Encoder,
    value: &Http2HpackSettings,
) -> Result<(), PreparationError> {
    let Http2HpackSettings {
        literal_pseudo_headers,
        static_name_index,
        huffman_coding,
        cookie_crumbs,
        field_indexing,
        name_reference,
        unindexed_match,
        indexing_limit,
        table_size_updates,
        sensitive_proxy_authorization,
    } = value;
    e.list(literal_pseudo_headers, http2_pseudo_header)?;
    http2_static_name_index(e, static_name_index)?;
    http2_huffman_coding(e, huffman_coding)?;
    http2_cookie_crumbs(e, cookie_crumbs)?;
    http2_field_indexing(e, field_indexing)?;
    http2_name_reference(e, name_reference)?;
    http2_unindexed_match(e, unindexed_match)?;
    http2_indexing_limit(e, indexing_limit)?;
    http2_table_size_updates(e, table_size_updates)?;
    http2_sensitive_proxy_authorization(e, sensitive_proxy_authorization)?;
    Ok(())
}

pub(super) fn encode_streams(
    e: &mut Encoder,
    value: &Http2StreamSettings,
) -> Result<(), PreparationError> {
    let Http2StreamSettings {
        first_stream_id,
        assumed_max_concurrent_streams,
        max_concurrent_streams_cap,
    } = value;
    e.u32(*first_stream_id)?;
    e.option(assumed_max_concurrent_streams.as_ref(), |e, value| {
        e.u32(*value)
    })?;
    e.option(max_concurrent_streams_cap.as_ref(), |e, value| {
        e.u32(*value)
    })?;
    Ok(())
}

pub(super) fn http3(e: &mut Encoder, value: &Http3Settings) -> Result<(), PreparationError> {
    let Http3Settings {
        initial_settings,
        setting_order,
        qpack_encoding,
        qpack_decoder_stream,
        qpack_encoder_stream,
        qpack_stream_order,
        reserved_frame_after_settings,
    } = value;
    e.list(initial_settings, http3_setting)?;
    http3_setting_order(e, setting_order)?;
    http3_qpack_encoding(e, qpack_encoding)?;
    http3_qpack_decoder_stream(e, qpack_decoder_stream)?;
    http3_qpack_encoder_stream(e, qpack_encoder_stream)?;
    http3_qpack_stream_order(e, qpack_stream_order)?;
    e.bool(*reserved_frame_after_settings)?;
    Ok(())
}

pub(super) fn http3_request(
    e: &mut Encoder,
    value: &Http3RequestSettings,
) -> Result<(), PreparationError> {
    let Http3RequestSettings {
        pseudo_header_order,
        extended_connect_pseudo_header_order,
        cookie_crumbs,
        alt_used,
        alt_used_port,
    } = value;
    e.list(pseudo_header_order, http3_pseudo_header)?;
    e.option(extended_connect_pseudo_header_order.as_ref(), |e, value| {
        e.list(value, http3_pseudo_header)
    })?;
    http3_cookie_crumbs(e, cookie_crumbs)?;
    http3_alt_used(e, alt_used)?;
    http3_alt_used_port(e, alt_used_port)?;
    Ok(())
}

fn http2_setting(e: &mut Encoder, value: &Http2Setting) -> Result<(), PreparationError> {
    match value {
        Http2Setting::HeaderTableSize(value) => {
            e.u8(0)?;
            e.u32(*value)
        }
        Http2Setting::EnablePush(value) => {
            e.u8(1)?;
            e.bool(*value)
        }
        Http2Setting::MaxConcurrentStreams(value) => {
            e.u8(2)?;
            e.u32(*value)
        }
        Http2Setting::InitialWindowSize(value) => {
            e.u8(3)?;
            e.u32(*value)
        }
        Http2Setting::MaxFrameSize(value) => {
            e.u8(4)?;
            e.u32(*value)
        }
        Http2Setting::MaxHeaderListSize(value) => {
            e.u8(5)?;
            e.u32(*value)
        }
        Http2Setting::EnableConnectProtocol(value) => {
            e.u8(6)?;
            e.bool(*value)
        }
        Http2Setting::NoRfc7540Priorities(value) => {
            e.u8(7)?;
            e.bool(*value)
        }
        _ => Err(PreparationError::Unsupported("Http2Setting")),
    }
}

fn http3_setting(e: &mut Encoder, value: &Http3Setting) -> Result<(), PreparationError> {
    match value {
        Http3Setting::QpackMaxTableCapacity(value) => {
            e.u8(0)?;
            e.u64(*value)
        }
        Http3Setting::MaxFieldSectionSize(value) => {
            e.u8(1)?;
            e.u64(*value)
        }
        Http3Setting::QpackBlockedStreams(value) => {
            e.u8(2)?;
            e.u64(*value)
        }
        Http3Setting::H3Datagram(value) => {
            e.u8(3)?;
            e.bool(*value)
        }
        Http3Setting::EnableConnectProtocol(value) => {
            e.u8(4)?;
            e.bool(*value)
        }
        Http3Setting::EnableWebTransportDraft02(value) => {
            e.u8(5)?;
            e.bool(*value)
        }
        Http3Setting::H3DatagramDraft04(value) => {
            e.u8(6)?;
            e.bool(*value)
        }
        Http3Setting::RandomizedGrease => e.u8(7),
        _ => Err(PreparationError::Unsupported("Http3Setting")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alt_used_policies_keep_distinct_canonical_tags() -> Result<(), PreparationError> {
        for (policy, tag) in [
            (Http3AltUsed::Omit, 0),
            (Http3AltUsed::Append, 1),
            (Http3AltUsed::ValidatedMapping, 2),
        ] {
            let mut encoder = Encoder::new();
            http3_alt_used(&mut encoder, &policy)?;
            assert_eq!(encoder.finish(), vec![tag]);
        }
        Ok(())
    }
}
