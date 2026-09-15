use super::{BrowserFamily, Platform, ProfileId, ProfileMetadata};

#[test]
fn accepts_builtin_and_custom_profile_identity() -> Result<(), Box<dyn std::error::Error>> {
    let id = ProfileId::new("safari/26.0/macos-26")?;
    let metadata = ProfileMetadata::new(id, BrowserFamily::Safari, "26.0", Platform::MacOs)?;

    assert_eq!(metadata.id().as_str(), "safari/26.0/macos-26");

    let custom = BrowserFamily::Other("ladybird".into());
    assert_eq!(custom, BrowserFamily::Other("ladybird".into()));

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
fn rejects_empty_browser_versions() -> Result<(), Box<dyn std::error::Error>> {
    let id = ProfileId::new("custom/development/linux")?;
    let result = ProfileMetadata::new(
        id,
        BrowserFamily::Other("custom".into()),
        "  ",
        Platform::Linux,
    );

    assert!(result.is_err());
    Ok(())
}
