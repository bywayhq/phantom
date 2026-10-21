use super::*;
use http_body_util::BodyExt;

fn part(data: Data) -> Part {
    Part {
        name: "x".into(),
        data,
        filename: None,
        content_type: None,
    }
}

#[tokio::test]
async fn seventy_stream_parts_share_one_root_and_advance_only_on_demand() -> Result<()> {
    let multipart = Multipart::new("b", (0..70).map(|_| part(Data::Stream)).collect(), 20000)?;
    let owner = Upload::new(None);
    owner.configure_multipart(Arc::clone(&multipart))?;
    let body = multipart.take_body(&owner)?;
    let encoding = async {
        body.collect()
            .await
            .map(|body| body.to_bytes())
            .map_err(|_| failure("Test", "multipart failed"))
    };
    let producing = async {
        for index in 0..70 {
            assert_eq!(owner.next_part().await?, Some(index));
            let demand = multipart
                .sources
                .demand
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .active;
            assert_eq!(demand, Some(index as usize));
            assert!(owner.ready().await);
            owner.write(vec![b'x'])?;
            assert!(owner.ready().await);
            owner.end()?;
        }
        Ok::<_, napi::Error>(())
    };
    let (bytes, ()) = tokio::try_join!(encoding, producing)?;
    let mut expected = Vec::new();
    for _ in 0..70 {
        expected.extend_from_slice(b"--b\r\nContent-Disposition: form-data; name=\"x\"\r\nContent-Type: application/octet-stream\r\n\r\nx\r\n");
    }
    expected.extend_from_slice(b"--b--\r\n");
    assert_eq!(bytes, expected);
    assert!(multipart.take_body(&owner).is_err());
    owner.stop();
    assert_eq!(owner.next_part().await?, None);
    Ok(())
}

#[tokio::test]
async fn core_cap_and_split_boundary_collision_remain_typed_framing_errors() -> Result<()> {
    for (maximum, chunks, expected) in [
        (
            105,
            vec![vec![b'x'; 100]],
            phantom::PreparedBodyErrorKind::TooLarge,
        ),
        (
            1024,
            vec![b"prefix--".to_vec(), b"b-suffix".to_vec()],
            phantom::PreparedBodyErrorKind::BoundaryCollision,
        ),
    ] {
        let multipart = Multipart::new("b", vec![part(Data::Stream)], maximum)?;
        let owner = Upload::new(None);
        owner.configure_multipart(Arc::clone(&multipart))?;
        let body = multipart.take_body(&owner)?;
        let encoding = async {
            let result = body.collect().await;
            assert!(
                matches!(result, Err(phantom::MultipartStreamError::Framing(error)) if error.kind() == expected)
            );
        };
        let producing = async {
            assert_eq!(owner.next_part().await?, Some(0));
            for chunk in chunks {
                if !owner.ready().await {
                    return Ok::<_, napi::Error>(());
                }
                owner.write(chunk)?;
            }
            if owner.ready().await {
                owner.end()?;
            }
            Ok(())
        };
        let ((), result) = tokio::join!(encoding, producing);
        result?;
    }
    Ok(())
}

#[tokio::test]
async fn dropped_encoder_stops_unstarted_sources_and_files_open_only_on_poll() -> Result<()> {
    let multipart = Multipart::new("b", vec![part(Data::Stream), part(Data::Stream)], 4096)?;
    let owner = Upload::new(None);
    owner.configure_multipart(Arc::clone(&multipart))?;
    drop(multipart.take_body(&owner)?);
    assert_eq!(owner.next_part().await?, None);
    for child in multipart.sources.children.iter().flatten() {
        assert!(!child.ready().await);
    }
    let file = Multipart::new(
        "b",
        vec![part(Data::File {
            path: "missing-private-path".into(),
            maximum: 10,
        })],
        4096,
    )?;
    // Construction does not touch the path; the actual encoder poll fails.
    assert!(file.take_body(&owner)?.collect().await.is_err());
    Ok(())
}

#[tokio::test]
async fn root_source_failure_is_an_error_in_the_actual_unknown_length_child() -> Result<()> {
    let multipart = Multipart::new("b", vec![part(Data::Stream)], 4096)?;
    let owner = Upload::new(None);
    owner.configure_multipart(Arc::clone(&multipart))?;
    let body = multipart.take_body(&owner)?;
    let encoding = async {
        assert!(matches!(
            body.collect().await,
            Err(phantom::MultipartStreamError::Source(_))
        ));
    };
    let failing = async {
        assert_eq!(owner.next_part().await?, Some(0));
        assert!(owner.ready().await);
        owner.fail();
        Ok::<_, napi::Error>(())
    };
    let ((), result) = tokio::join!(encoding, failing);
    result?;
    Ok(())
}
