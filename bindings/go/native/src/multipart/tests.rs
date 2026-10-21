use super::*;
use http_body_util::BodyExt;
use serde_json::json;
use std::time::Duration;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn owner(
    parts: serde_json::Value,
    input: &[u8],
    maximum: usize,
) -> Result<Arc<Upload>, Box<dyn std::error::Error>> {
    let parts = serde_json::from_value(parts)?;
    let multipart = Multipart::new(1, "test", parts, input, maximum)
        .map_err(|error| std::io::Error::other(error.kind))?;
    Ok(Upload::with_multipart(1, None, Some(multipart), None))
}

#[tokio::test]
async fn seventy_readers_use_one_group_and_actual_body_poll_demand() -> TestResult {
    let parts = (0..70)
        .map(|_| json!({"name":"tag", "source":{"kind":"reader"}}))
        .collect::<Vec<_>>();
    let owner = owner(json!(parts), &[], 32 * 1024)?;
    let multipart = owner.multipart.as_ref().ok_or("missing multipart")?;
    let mut body = multipart
        .take_body(&owner)
        .map_err(|error| std::io::Error::other(error.kind))?;
    // No part is activated by construction or by copying request metadata.
    assert!(
        multipart
            .readers
            .demand
            .lock()
            .map_err(|_| "lock")?
            .pending
            .is_none()
    );
    let writing = async {
        for index in 0..70 {
            assert_eq!(owner.next_part().await.map_err(|error| error.kind)?, index);
            owner
                .write(Bytes::from_static(b"value"), None)
                .await
                .map_err(|error| error.kind)?;
            owner
                .write(Bytes::new(), Some(false))
                .await
                .map_err(|error| error.kind)?;
        }
        Ok::<(), &'static str>(())
    };
    let reading = async {
        let mut result = Vec::new();
        while let Some(frame) = body.frame().await {
            result.extend_from_slice(&frame?.into_data().map_err(|_| "trailers")?);
        }
        Ok::<_, Box<dyn std::error::Error>>(result)
    };
    let (written, result) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(writing, reading)
    })
    .await?;
    written?;
    let result = result?;
    let part = b"--test\r\nContent-Disposition: form-data; name=\"tag\"\r\nContent-Type: application/octet-stream\r\n\r\nvalue\r\n";
    let expected = [part.repeat(70), b"--test--\r\n".to_vec()].concat();
    assert_eq!(result, expected);
    for source in multipart.readers.sources.iter().flatten() {
        tokio::time::timeout(Duration::from_secs(1), source.closed()).await?;
    }
    Ok(())
}

#[tokio::test]
async fn dropping_encoder_closes_active_unstarted_and_pending_demand() -> TestResult {
    let owner = owner(
        json!([
            {"name":"a","source":{"kind":"reader"}},
            {"name":"b","source":{"kind":"reader"}}
        ]),
        &[],
        4096,
    )?;
    let multipart = owner.multipart.as_ref().ok_or("missing multipart")?;
    let mut body = multipart.take_body(&owner).map_err(|error| error.kind)?;
    body.frame().await.ok_or("missing header")??;
    // The next poll activates a source but remains Pending until a writer.
    assert!(
        tokio::time::timeout(Duration::from_millis(1), body.frame())
            .await
            .is_err()
    );
    assert_eq!(owner.next_part().await.map_err(|error| error.kind)?, 0);
    drop(body);
    assert_eq!(
        owner.next_part().await.err().map(|error| error.kind),
        Some("upload_closed")
    );
    for source in multipart.readers.sources.iter().flatten() {
        tokio::time::timeout(Duration::from_secs(1), source.closed()).await?;
    }
    Ok(())
}

#[test]
fn strict_shapes_and_core_metadata_are_checked_before_contents() -> TestResult {
    assert!(
        serde_json::from_value::<Part>(
            json!({"name":"x","source":{"kind":"reader","data":{"offset":0,"length":0}}})
        )
        .is_err()
    );
    assert!(serde_json::from_value::<Part>(json!({"name":"x","source":{"kind":"bytes","data":{"offset":0,"length":0}},"unknown":true})).is_err());
    let parts = serde_json::from_value(
        json!([{"name":"x","source":{"kind":"bytes","data":{"offset":usize::MAX,"length":1}}}]),
    )?;
    assert_eq!(
        Multipart::new(1, "test", parts, &[], 4096)
            .err()
            .map(|error| error.kind),
        Some("invalid_multipart")
    );
    let parts = serde_json::from_value(json!([{"name":"x","source":{"kind":"reader"}}]))?;
    assert_eq!(
        Multipart::new(1, "test", parts, &[], 0)
            .err()
            .map(|error| error.kind),
        Some("multipart_too_large")
    );
    Ok(())
}
