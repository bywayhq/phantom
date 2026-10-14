//! Independent cookie values frozen at f2d6cb84bbd01d78d2b21062efac43c0f75fe9bd.

use phantom_profile::{CookiePlacement, browser};

#[test]
fn browser_cookie_factories_preserve_order_and_matching() {
    for (actual, original) in [
        (browser::chrome::v154_cookie_placement(), chrome_original()),
        (
            browser::firefox::v157_cookie_placement(),
            firefox_original(),
        ),
    ] {
        assert_eq!(actual, original);
        for names in [
            ["accept", "priority", "te"],
            ["sec-fetch-dest", "if-none-match", "priority"],
        ] {
            assert_eq!(
                actual.insertion_index(names),
                original.insertion_index(names)
            );
        }
    }
}
#[test]
fn composed_cookie_profiles_and_custom_values_keep_ownership() {
    for profile in [
        browser::chrome::v154_windows(),
        browser::edge::v154_windows(),
        browser::brave::v154_windows(),
        browser::opera::v136_windows(),
    ] {
        assert_eq!(*profile.cookie_placement(), chrome_original());
    }
    assert_eq!(
        *browser::firefox::v157_windows().cookie_placement(),
        firefox_original()
    );
    let custom = browser::chrome::v154_windows()
        .with_cookie_placement(CookiePlacement::before_fields(["x-custom"]));
    assert_ne!(*custom.cookie_placement(), chrome_original());
    assert_eq!(browser::chrome::v154_cookie_placement(), chrome_original());
    assert_eq!(
        browser::firefox::v157_cookie_placement(),
        firefox_original()
    );
    let default = phantom_profile::ClientProfile::new(browser::chrome::v154_tcp_tls());
    assert_eq!(*default.cookie_placement(), CookiePlacement::last());
}
fn chrome_original() -> CookiePlacement {
    CookiePlacement::before_fields(["if-none-match", "if-modified-since", "priority"])
}

fn firefox_original() -> CookiePlacement {
    CookiePlacement::before_fields([
        "upgrade-insecure-requests",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
        "sec-fetch-user",
        "if-modified-since",
        "if-none-match",
        "priority",
        "pragma",
        "cache-control",
        "te",
    ])
}
