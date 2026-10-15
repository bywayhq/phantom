//! Actual loopback openings compared with all three retained emulator runs.

use super::reacquire::checked;
use super::*;
use phantom::profile::browser::edge;

const ACCEPT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/websocket/edge-android/153.0.4234.49/android-17-pixel7-emulator/accept.txt"
));
const H1: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/websocket/edge-android/153.0.4234.49/android-17-pixel7-emulator/h1-accept.txt"
));

fn run(input: &str, index: usize) -> TestResult<Capture> {
    let prefix = format!("run_{index}_");
    let mut selected = String::new();
    for line in input.lines() {
        if let Some(value) = line.strip_prefix(&prefix) {
            selected.push_str("run_0_");
            selected.push_str(value);
        } else if !line.starts_with("run_") {
            selected.push_str(line);
        } else {
            continue;
        }
        selected.push('\n');
    }
    let capture = Capture::parse(&selected)?;
    assert_eq!(capture.value("repeat_count")?, "3");
    Ok(capture)
}

#[tokio::test]
async fn edge_android_http2_openings_match_each_retained_emulator_run() -> TestResult<()> {
    for index in 0..3 {
        let capture = run(ACCEPT, index)?;
        let identity = Arc::new(TestIdentity::generate()?);
        let mut server = TestServer::start(Arc::clone(&identity), Behavior::ACCEPT).await?;
        let caller = checked(bounded(async {
            let settings = edge::v153_android_websocket();
            let client = profile_client(&identity, edge::v153_android_http2(), settings.clone())?;
            ordinary_get(&client, &server).await?;
            let expected = capture.connect()?;
            exchange(connect_like(&client, server.address, &expected, &settings).await?).await?;
            let connections = server.connections()?;
            assert_eq!(connections.len(), 1);
            assert_eq!(methods(&connections[0]), ["GET", "CONNECT"]);
            assert_connect_matches(&connections[0].h2[1], &expected)?;
            Ok(())
        }))
        .await;
        server.finish(caller).await?;
    }
    Ok(())
}

#[tokio::test]
async fn edge_android_http1_openings_match_each_retained_emulator_run() -> TestResult<()> {
    for index in 0..3 {
        let capture = run(H1, index)?;
        assert_eq!(capture.value("socket_scheme")?, "ws");
        let identity = Arc::new(TestIdentity::generate()?);
        let mut server = TestServer::start_plaintext(Behavior::ACCEPT).await?;
        let caller = checked(bounded(async {
            let settings = edge::v153_android_websocket();
            let client = profile_client(&identity, edge::v153_android_http2(), settings.clone())?;
            let upgrade = capture.upgrade()?;
            let path = upgrade
                .request_line
                .split(' ')
                .nth(1)
                .ok_or("request line has no target")?;
            let builder =
                client.websocket_with_profile_policy(&format!("ws://{}{path}", server.address))?;
            let builder = fill_callers(builder, &settings.http1_fields, &upgrade.fields);
            let socket = with_profile_compression(builder, &settings)?
                .connect()
                .await?;
            assert_eq!(socket.handshake_response().version(), Version::HTTP_11);
            exchange(socket).await?;
            let connections = server.connections()?;
            assert_eq!(connections.len(), 1);
            assert_http1_upgrade(&connections[0], &capture)?;
            Ok(())
        }))
        .await;
        server.finish(caller).await?;
    }
    Ok(())
}
