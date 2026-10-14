//! Independent client-hint values frozen at 8a072dec28402f343e9cb70726a687889222e6d5.

use phantom_profile::{ClientHint, ClientHintDelivery, ClientHintSettings};

pub(super) fn chrome_windows_original() -> ClientHintSettings {
    use ClientHintDelivery::{AcceptCh, Default};

    ClientHintSettings::new(vec![
        ClientHint::new(
            "sec-ch-ua",
            r#""Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99""#,
            Default,
        ),
        ClientHint::new("sec-ch-ua-mobile", "?0", Default),
        ClientHint::new("sec-ch-ua-full-version", r#""154.0.8037.97""#, AcceptCh),
        ClientHint::new("sec-ch-ua-arch", r#""x86""#, AcceptCh),
        ClientHint::new("sec-ch-ua-platform", r#""Windows""#, Default),
        ClientHint::new("sec-ch-ua-platform-version", r#""19.0.0""#, AcceptCh),
        ClientHint::new("sec-ch-ua-model", r#""""#, AcceptCh),
        ClientHint::new("sec-ch-ua-bitness", r#""64""#, AcceptCh),
        ClientHint::new("sec-ch-ua-wow64", "?0", AcceptCh),
        ClientHint::new(
            "sec-ch-ua-full-version-list",
            r#""Chromium";v="154.0.8037.97", "Google Chrome";v="154.0.8037.97", "Not A(Brand";v="99.0.0.0""#,
            AcceptCh,
        ),
        ClientHint::new("sec-ch-ua-form-factors", r#""Desktop""#, AcceptCh),
    ])
}

pub(super) fn chrome_macos_original() -> ClientHintSettings {
    use ClientHintDelivery::{AcceptCh, Default};

    ClientHintSettings::new(vec![
        ClientHint::new(
            "sec-ch-ua",
            r#""Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99""#,
            Default,
        ),
        ClientHint::new("sec-ch-ua-mobile", "?0", Default),
        ClientHint::new("sec-ch-ua-full-version", r#""154.0.8037.95""#, AcceptCh),
        ClientHint::new("sec-ch-ua-arch", r#""arm""#, AcceptCh),
        ClientHint::new("sec-ch-ua-platform", r#""macOS""#, Default),
        ClientHint::new("sec-ch-ua-platform-version", r#""15.5.0""#, AcceptCh),
        ClientHint::new("sec-ch-ua-model", r#""""#, AcceptCh),
        ClientHint::new("sec-ch-ua-bitness", r#""64""#, AcceptCh),
        ClientHint::new("sec-ch-ua-wow64", "?0", AcceptCh),
        ClientHint::new(
            "sec-ch-ua-full-version-list",
            r#""Chromium";v="154.0.8037.95", "Google Chrome";v="154.0.8037.95", "Not A(Brand";v="99.0.0.0""#,
            AcceptCh,
        ),
        ClientHint::new("sec-ch-ua-form-factors", r#""Desktop""#, AcceptCh),
    ])
}

pub(super) fn edge_windows_original() -> ClientHintSettings {
    use ClientHintDelivery::{AcceptCh, Default};

    ClientHintSettings::new(vec![
        ClientHint::new(
            "sec-ch-ua",
            r#""Chromium";v="154", "Microsoft Edge";v="154", "Not A(Brand";v="99""#,
            Default,
        ),
        ClientHint::new("sec-ch-ua-mobile", "?0", Default),
        ClientHint::new("sec-ch-ua-full-version", r#""154.0.4258.48""#, AcceptCh),
        ClientHint::new("sec-ch-ua-arch", r#""x86""#, AcceptCh),
        ClientHint::new("sec-ch-ua-platform", r#""Windows""#, Default),
        ClientHint::new("sec-ch-ua-platform-version", r#""19.0.0""#, AcceptCh),
        ClientHint::new("sec-ch-ua-model", r#""""#, AcceptCh),
        ClientHint::new("sec-ch-ua-bitness", r#""64""#, AcceptCh),
        ClientHint::new("sec-ch-ua-wow64", "?0", AcceptCh),
        ClientHint::new(
            "sec-ch-ua-full-version-list",
            r#""Chromium";v="154.0.8037.58", "Microsoft Edge";v="154.0.4258.48", "Not A(Brand";v="99.0.0.0""#,
            AcceptCh,
        ),
        ClientHint::new("sec-ch-ua-form-factors", r#""Desktop""#, AcceptCh),
    ])
}

pub(super) fn edge_macos_original() -> ClientHintSettings {
    use ClientHintDelivery::{AcceptCh, Default};

    ClientHintSettings::new(vec![
        ClientHint::new(
            "sec-ch-ua",
            r#""Chromium";v="154", "Microsoft Edge";v="154", "Not A(Brand";v="99""#,
            Default,
        ),
        ClientHint::new("sec-ch-ua-mobile", "?0", Default),
        ClientHint::new("sec-ch-ua-full-version", r#""154.0.4258.48""#, AcceptCh),
        ClientHint::new("sec-ch-ua-arch", r#""arm""#, AcceptCh),
        ClientHint::new("sec-ch-ua-platform", r#""macOS""#, Default),
        ClientHint::new("sec-ch-ua-platform-version", r#""15.5.0""#, AcceptCh),
        ClientHint::new("sec-ch-ua-model", r#""""#, AcceptCh),
        ClientHint::new("sec-ch-ua-bitness", r#""64""#, AcceptCh),
        ClientHint::new("sec-ch-ua-wow64", "?0", AcceptCh),
        ClientHint::new(
            "sec-ch-ua-full-version-list",
            r#""Chromium";v="154.0.8037.58", "Microsoft Edge";v="154.0.4258.48", "Not A(Brand";v="99.0.0.0""#,
            AcceptCh,
        ),
        ClientHint::new("sec-ch-ua-form-factors", r#""Desktop""#, AcceptCh),
    ])
}

pub(super) fn opera_windows_original() -> ClientHintSettings {
    use ClientHintDelivery::{AcceptCh, Default};

    ClientHintSettings::new(vec![
        ClientHint::new(
            "sec-ch-ua",
            r#""Chromium";v="152", "Not?A_Brand";v="24", "Opera";v="136""#,
            Default,
        ),
        ClientHint::new("sec-ch-ua-mobile", "?0", Default),
        ClientHint::new("sec-ch-ua-full-version", r#""136.0.6008.52""#, AcceptCh),
        ClientHint::new("sec-ch-ua-arch", r#""x86""#, AcceptCh),
        ClientHint::new("sec-ch-ua-platform", r#""Windows""#, Default),
        ClientHint::new("sec-ch-ua-platform-version", r#""19.0.0""#, AcceptCh),
        ClientHint::new("sec-ch-ua-model", r#""""#, AcceptCh),
        ClientHint::new("sec-ch-ua-bitness", r#""64""#, AcceptCh),
        ClientHint::new("sec-ch-ua-wow64", "?0", AcceptCh),
        ClientHint::new(
            "sec-ch-ua-full-version-list",
            r#""Chromium";v="152.0.7977.130", "Not?A_Brand";v="24.0.0.0", "Opera";v="136.0.6008.52""#,
            AcceptCh,
        ),
        ClientHint::new("sec-ch-ua-form-factors", r#""Desktop""#, AcceptCh),
    ])
}

pub(super) fn opera_macos_original() -> ClientHintSettings {
    use ClientHintDelivery::{AcceptCh, Default};

    ClientHintSettings::new(vec![
        ClientHint::new(
            "sec-ch-ua",
            r#""Chromium";v="152", "Not?A_Brand";v="24", "Opera";v="136""#,
            Default,
        ),
        ClientHint::new("sec-ch-ua-mobile", "?0", Default),
        ClientHint::new("sec-ch-ua-full-version", r#""136.0.6008.52""#, AcceptCh),
        ClientHint::new("sec-ch-ua-arch", r#""arm""#, AcceptCh),
        ClientHint::new("sec-ch-ua-platform", r#""macOS""#, Default),
        ClientHint::new("sec-ch-ua-platform-version", r#""15.5.0""#, AcceptCh),
        ClientHint::new("sec-ch-ua-model", r#""""#, AcceptCh),
        ClientHint::new("sec-ch-ua-bitness", r#""64""#, AcceptCh),
        ClientHint::new("sec-ch-ua-wow64", "?0", AcceptCh),
        ClientHint::new(
            "sec-ch-ua-full-version-list",
            r#""Chromium";v="152.0.7977.130", "Not?A_Brand";v="24.0.0.0", "Opera";v="136.0.6008.52""#,
            AcceptCh,
        ),
        ClientHint::new("sec-ch-ua-form-factors", r#""Desktop""#, AcceptCh),
    ])
}

pub(super) fn brave_windows_original() -> ClientHintSettings {
    use ClientHintDelivery::{AcceptCh, Default};

    ClientHintSettings::new(vec![
        ClientHint::new(
            "sec-ch-ua",
            r#""Chromium";v="154", "Brave";v="154", "Not A(Brand";v="99""#,
            Default,
        ),
        ClientHint::new("sec-ch-ua-mobile", "?0", Default),
        ClientHint::new("sec-ch-ua-arch", r#""x86""#, AcceptCh),
        ClientHint::new("sec-ch-ua-platform", r#""Windows""#, Default),
        ClientHint::new("sec-ch-ua-platform-version", r#""19.0.0""#, AcceptCh),
        ClientHint::new("sec-ch-ua-model", r#""""#, AcceptCh),
        ClientHint::new("sec-ch-ua-bitness", r#""64""#, AcceptCh),
        ClientHint::new("sec-ch-ua-wow64", "?0", AcceptCh),
        ClientHint::new(
            "sec-ch-ua-full-version-list",
            r#""Chromium";v="154.0.0.0", "Brave";v="154.0.0.0", "Not A(Brand";v="99.0.0.0""#,
            AcceptCh,
        ),
    ])
}

pub(super) fn chrome_android_original() -> ClientHintSettings {
    chrome_android_for_model_original("Pixel 7")
}

pub(super) fn chrome_android_for_model_original(model: &str) -> ClientHintSettings {
    use ClientHintDelivery::{AcceptCh, Default};

    ClientHintSettings::new(vec![
        ClientHint::new(
            "sec-ch-ua",
            r#""Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99""#,
            Default,
        ),
        ClientHint::new("sec-ch-ua-mobile", "?1", Default),
        ClientHint::new("sec-ch-ua-full-version", r#""154.0.8037.57""#, AcceptCh),
        ClientHint::new("sec-ch-ua-arch", r#""""#, AcceptCh),
        ClientHint::new("sec-ch-ua-platform", r#""Android""#, Default),
        ClientHint::new("sec-ch-ua-platform-version", r#""17.0.0""#, AcceptCh),
        ClientHint::new("sec-ch-ua-model", frozen_model_value(model), AcceptCh),
        ClientHint::new("sec-ch-ua-bitness", r#""""#, AcceptCh),
        ClientHint::new("sec-ch-ua-wow64", "?0", AcceptCh),
        ClientHint::new(
            "sec-ch-ua-full-version-list",
            r#""Chromium";v="154.0.8037.57", "Google Chrome";v="154.0.8037.57", "Not A(Brand";v="99.0.0.0""#,
            AcceptCh,
        ),
        ClientHint::new("sec-ch-ua-form-factors", r#""Mobile""#, AcceptCh),
    ])
}

pub(super) fn edge_android_original() -> ClientHintSettings {
    edge_android_for_model_original("Pixel 7")
}

pub(super) fn edge_android_for_model_original(model: &str) -> ClientHintSettings {
    use ClientHintDelivery::{AcceptCh, Default};

    ClientHintSettings::new(vec![
        ClientHint::new(
            "sec-ch-ua",
            r#""Microsoft Edge";v="153", "Not_A Brand";v="8", "Chromium";v="153""#,
            Default,
        ),
        ClientHint::new("sec-ch-ua-mobile", "?1", Default),
        ClientHint::new("sec-ch-ua-full-version", r#""153.0.4234.49""#, AcceptCh),
        ClientHint::new("sec-ch-ua-arch", r#""""#, AcceptCh),
        ClientHint::new("sec-ch-ua-platform", r#""Android""#, Default),
        ClientHint::new("sec-ch-ua-platform-version", r#""17.0.0""#, AcceptCh),
        ClientHint::new("sec-ch-ua-model", frozen_model_value(model), AcceptCh),
        ClientHint::new("sec-ch-ua-bitness", r#""""#, AcceptCh),
        ClientHint::new("sec-ch-ua-wow64", "?0", AcceptCh),
        ClientHint::new(
            "sec-ch-ua-full-version-list",
            r#""Microsoft Edge";v="153.0.4234.49", "Not_A Brand";v="8.0.0.0", "Chromium";v="153.0.8010.53""#,
            AcceptCh,
        ),
        ClientHint::new("sec-ch-ua-form-factors", r#""Mobile""#, AcceptCh),
    ])
}

pub(super) fn opera_android_original() -> ClientHintSettings {
    opera_android_for_model_original("Pixel 7")
}

pub(super) fn opera_android_for_model_original(model: &str) -> ClientHintSettings {
    use ClientHintDelivery::{AcceptCh, Default};

    ClientHintSettings::new(vec![
        ClientHint::new(
            "sec-ch-ua",
            r#""OperaMobile";v="102", "Opera";v="137", "Chromium";v="152", " Not A;Brand";v="99""#,
            Default,
        ),
        ClientHint::new("sec-ch-ua-mobile", "?1", Default),
        ClientHint::new("sec-ch-ua-full-version", r#""102.1.5206.90382""#, AcceptCh),
        ClientHint::new("sec-ch-ua-arch", r#""""#, AcceptCh),
        ClientHint::new("sec-ch-ua-platform", r#""Android""#, Default),
        ClientHint::new("sec-ch-ua-platform-version", r#""17""#, AcceptCh),
        ClientHint::new("sec-ch-ua-model", frozen_model_value(model), AcceptCh),
        ClientHint::new("sec-ch-ua-bitness", r#""""#, AcceptCh),
        ClientHint::new("sec-ch-ua-wow64", "?0", AcceptCh),
        ClientHint::new(
            "sec-ch-ua-full-version-list",
            r#""OperaMobile";v="102.1.5206.90382", "Opera";v="137.0.6010.1", "Chromium";v="152.0.7977.82", " Not A;Brand";v="99.0.0.0""#,
            AcceptCh,
        ),
        ClientHint::new("sec-ch-ua-form-factors", "", AcceptCh),
    ])
}

pub(super) fn brave_android_original() -> ClientHintSettings {
    use ClientHintDelivery::{AcceptCh, Default};

    ClientHintSettings::new(vec![
        ClientHint::new(
            "sec-ch-ua",
            r#""Brave";v="153", "Not_A Brand";v="8", "Chromium";v="153""#,
            Default,
        ),
        ClientHint::new("sec-ch-ua-mobile", "?1", Default),
        ClientHint::new("sec-ch-ua-arch", r#""""#, AcceptCh),
        ClientHint::new("sec-ch-ua-platform", r#""Android""#, Default),
        ClientHint::new("sec-ch-ua-platform-version", r#""17.0.0""#, AcceptCh),
        ClientHint::new("sec-ch-ua-model", r#""""#, AcceptCh),
        ClientHint::new("sec-ch-ua-bitness", r#""""#, AcceptCh),
        ClientHint::new("sec-ch-ua-wow64", "?0", AcceptCh),
        ClientHint::new(
            "sec-ch-ua-full-version-list",
            r#""Brave";v="153.0.0.0", "Not_A Brand";v="8.0.0.0", "Chromium";v="153.0.0.0""#,
            AcceptCh,
        ),
    ])
}

fn frozen_model_value(model: &str) -> String {
    let mut value = String::with_capacity(model.len() + 2);
    value.push('"');
    for character in model.chars() {
        if matches!(character, '"' | '\\') {
            value.push('\\');
        }
        value.push(character);
    }
    value.push('"');
    value
}
