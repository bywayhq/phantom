#[cfg(test)]
mod tests {
    use std::{num::NonZeroUsize, time::Duration};

    use phantom::profile::{
        Http2StreamSettings, QuicAckFrequencyDraft, QuicConnectionIdLength, QuicTransportParameter,
        QuicTransportParameterKind, QuicVarIntWidth, browser::chrome,
    };
    use phantom::{
        Bytes, RequestBuilder, RequestError, Response, ResponseBody, ResponseInfo, StatusCode,
        StatusRetry, Uri,
    };

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn profile_fields_can_be_named_and_customized() -> TestResult {
        let mut http2 = chrome::v154_http2();
        http2.streams = Http2StreamSettings {
            first_stream_id: 3,
            ..http2.streams
        };
        http2.validate()?;
        assert_eq!(http2.streams.first_stream_id, 3);

        let mut quic = chrome::v154_quic();
        quic.initial_destination_connection_id = Some(QuicConnectionIdLength::Fixed(8));
        quic.min_ack_delay_us = Some(1_000);
        quic.wire_parameters.push(QuicTransportParameter {
            kind: QuicTransportParameterKind::MinAckDelay {
                draft: QuicAckFrequencyDraft::Draft07,
                value_width: QuicVarIntWidth::Two,
            },
            id_width: QuicVarIntWidth::Eight,
            length_width: QuicVarIntWidth::One,
        });
        quic.validate()?;
        assert_eq!(
            quic.initial_destination_connection_id,
            Some(QuicConnectionIdLength::Fixed(8))
        );
        Ok(())
    }

    #[test]
    fn status_policy_accepts_facade_status_codes() -> TestResult {
        let policy = StatusRetry::new(
            &[StatusCode::SERVICE_UNAVAILABLE],
            NonZeroUsize::MIN,
            Duration::ZERO,
        )?;
        assert!(policy.retries(StatusCode::SERVICE_UNAVAILABLE));
        assert!(!policy.retries(StatusCode::OK));
        Ok(())
    }

    #[test]
    fn response_errors_have_transferable_public_types() {
        fn assert_send<T: Send>() {}
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send::<phantom::StatusError>();
        assert_send_sync::<phantom::ResponseReadError>();
        assert_send_sync::<phantom::ResponseReadErrorKind>();
    }

    #[allow(dead_code)]
    async fn bounded_read(
        response: Response<ResponseBody>,
    ) -> Result<Response<Bytes>, phantom::ResponseReadError> {
        let response = match phantom::error_for_status(response) {
            Ok(response) => response,
            Err(error) => error.into_response(),
        };
        phantom::response_bytes(response, 1_024).await
    }

    #[cfg(feature = "json")]
    #[allow(dead_code)]
    async fn typed_read(
        response: Response<ResponseBody>,
    ) -> Result<Response<Vec<String>>, phantom::ResponseReadError> {
        phantom::response_json(response, 1_024).await
    }

    // Compile the asynchronous request/response workflow without opening a socket.
    #[allow(dead_code)]
    async fn upload(
        builder: RequestBuilder,
    ) -> Result<(StatusCode, Option<Uri>, Bytes), RequestError> {
        let response: Response<ResponseBody> =
            builder.body(Bytes::from_static(b"body")).send().await?;
        let status: StatusCode = response.status();
        let uri = response
            .extensions()
            .get::<ResponseInfo>()
            .map(|info| info.effective_uri().clone());
        let body: Bytes = response.into_body().collect_with_limit(1_024).await?;
        Ok((status, uri, body))
    }

    #[cfg(feature = "https-records")]
    #[test]
    fn parsed_ech_values_and_errors_can_be_named() -> TestResult {
        use phantom::dns::{
            EchCipherSuite, EchConfig, EchConfigExtension, EchConfigList, EchConfigListError,
            EchConfigListErrorKind,
        };

        let mut contents = vec![3, 0, 0x20, 0, 32];
        contents.extend_from_slice(&[7; 32]);
        contents.extend_from_slice(&[0, 4, 0, 1, 0, 1, 0, 1, b'a', 0, 5, 0, 1, 0, 1, 7]);
        let mut config = 0xfe0d_u16.to_be_bytes().to_vec();
        config.extend_from_slice(&u16::try_from(contents.len())?.to_be_bytes());
        config.extend_from_slice(&contents);
        let mut bytes = u16::try_from(config.len())?.to_be_bytes().to_vec();
        bytes.extend_from_slice(&config);

        let parsed: Result<Box<[EchConfig]>, EchConfigListError> =
            EchConfigList::new(bytes).parse();
        let configs = parsed?;
        let suites: &[EchCipherSuite] = configs[0].cipher_suites();
        assert_eq!((suites[0].kdf_id(), suites[0].aead_id()), (1, 1));
        let extensions: &[EchConfigExtension] = configs[0].extensions();
        assert_eq!(extensions[0].extension_type(), 1);
        assert_eq!(extensions[0].data(), &[7]);

        let error: EchConfigListError = match EchConfigList::new(vec![0, 0]).parse() {
            Ok(_) => return Err("an empty ECH list must fail".into()),
            Err(error) => error,
        };
        let kind: EchConfigListErrorKind = error.kind();
        assert_eq!(kind, EchConfigListErrorKind::Empty);
        Ok(())
    }
}
