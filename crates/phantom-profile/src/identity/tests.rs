use super::{ClientFamily, Platform, ProfileId, ProfileMetadata};

#[test]
fn accepts_builtin_and_custom_profile_identity() -> Result<(), Box<dyn std::error::Error>> {
    let id = ProfileId::new("safari/26.0/macos-26")?;
    let metadata = ProfileMetadata::new(id, ClientFamily::Safari, "26.0", Platform::MacOs)?;

    assert_eq!(metadata.id().as_str(), "safari/26.0/macos-26");

    let custom = ClientFamily::Other("ladybird".into());
    assert_eq!(custom, ClientFamily::Other("ladybird".into()));

    let native_stack = ProfileMetadata::new(
        ProfileId::new("native-http/5.3/android")?,
        ClientFamily::Other("native-http".into()),
        "5.3",
        Platform::Android,
    )?;
    assert_eq!(
        native_stack.family(),
        &ClientFamily::Other("native-http".into())
    );

    Ok(())
}

#[test]
fn rejects_noncanonical_profile_ids() {
    for value in [
        "",
        "/firefox/145/linux",
        "Firefox/145",
        "a//b",
        "a/./b",
        "a/../b",
        "a b",
    ] {
        assert!(ProfileId::new(value).is_err(), "accepted {value:?}");
    }
}

#[test]
fn rejects_empty_client_versions() -> Result<(), Box<dyn std::error::Error>> {
    let id = ProfileId::new("custom/development/linux")?;
    let result = ProfileMetadata::new(
        id,
        ClientFamily::Other("custom".into()),
        "  ",
        Platform::Linux,
    );

    assert!(result.is_err());
    Ok(())
}
