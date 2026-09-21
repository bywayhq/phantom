//! Test-only adapter for selected Web Platform Tests EventSource scenarios.

use std::{env, error::Error, io, path::PathBuf, time::Duration};

use phantom::{
    Client,
    profile::{ClientProfile, chromium},
};
use url::Url;

mod request_cases;
mod stream_cases;

const CASE_TIMEOUT: Duration = Duration::from_secs(8);

type BoxError = Box<dyn Error + Send + Sync>;

struct Context {
    client: Client,
    base_url: Url,
}

#[derive(Debug)]
struct Config {
    base_url: Url,
    ca_der: PathBuf,
    cases: Vec<String>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), BoxError> {
    let config = Config::parse(env::args().skip(1))?;
    let root = std::fs::read(&config.ca_der)?;
    let profile = ClientProfile::new(chromium::v152_tls());
    let context = Context {
        client: Client::builder(profile)
            .add_root_certificate_der(root)
            .build()?,
        base_url: config.base_url,
    };

    let mut failures = 0;
    for case in &config.cases {
        match tokio::time::timeout(CASE_TIMEOUT, dispatch(&context, case)).await {
            Ok(Ok(())) => println!("CASE\tPASS\t{case}"),
            Ok(Err(error)) => {
                failures += 1;
                println!("CASE\tFAIL\t{case}\t{}", one_line(&error.to_string()));
            }
            Err(_) => {
                failures += 1;
                println!("CASE\tFAIL\t{case}\ttimed out");
            }
        }
    }
    println!("SUMMARY\t{}\t{failures}", config.cases.len());

    if failures == 0 {
        Ok(())
    } else {
        Err(invalid_data(format!("{failures} EventSource cases failed")).into())
    }
}

async fn dispatch(context: &Context, case: &str) -> Result<(), BoxError> {
    match case {
        "eventsource/event-data.any.js" => stream_cases::event_data(context).await,
        "eventsource/format-bom-2.any.js" => stream_cases::double_bom(context).await,
        "eventsource/format-bom.any.js" => stream_cases::bom(context).await,
        "eventsource/format-data-before-final-empty-line.any.js" => {
            request_cases::unterminated_event(context).await
        }
        "eventsource/format-field-event.any.js" => stream_cases::event_name(context).await,
        "eventsource/format-field-id-3.window.js#persists" => {
            stream_cases::id_persists(context).await
        }
        "eventsource/format-field-id-3.window.js#resets-colon" => {
            stream_cases::id_resets(context, "2").await
        }
        "eventsource/format-field-id-3.window.js#resets-no-colon" => {
            stream_cases::id_resets(context, "3").await
        }
        "eventsource/format-field-id-null.window.js#nul-nul" => {
            request_cases::nul_id(context, "\0\0").await
        }
        "eventsource/format-field-id-null.window.js#nul-prefix" => {
            request_cases::nul_id(context, "\0x").await
        }
        "eventsource/format-field-id-null.window.js#nul-suffix" => {
            request_cases::nul_id(context, "x\0").await
        }
        "eventsource/format-field-id-null.window.js#nul-surrounded" => {
            request_cases::nul_id(context, "x\0x").await
        }
        "eventsource/format-field-id-null.window.js#space-nul" => {
            request_cases::nul_id(context, " \0").await
        }
        "eventsource/format-field-id.any.js" => request_cases::last_event_id(context).await,
        "eventsource/format-field-parsing.any.js" => stream_cases::field_parsing(context).await,
        "eventsource/format-field-retry-bogus.any.js" => request_cases::bogus_retry(context).await,
        "eventsource/format-mime-trailing-semicolon.any.js" => {
            stream_cases::mime_trailing_semicolon(context).await
        }
        "eventsource/format-mime-valid-bogus.any.js" => stream_cases::invalid_mime(context).await,
        "eventsource/format-newlines.any.js" => stream_cases::newlines(context).await,
        "eventsource/format-utf-8.any.js" => stream_cases::utf8(context).await,
        "eventsource/request-accept.any.js" => request_cases::accept_header(context).await,
        "eventsource/request-cache-control.any.js#same-origin" => {
            request_cases::cache_control(context).await
        }
        "eventsource/request-status-error.window.js#204" => {
            request_cases::status(context, 204).await
        }
        "eventsource/request-status-error.window.js#205" => {
            request_cases::status(context, 205).await
        }
        "eventsource/request-status-error.window.js#210" => {
            request_cases::status(context, 210).await
        }
        "eventsource/request-status-error.window.js#299" => {
            request_cases::status(context, 299).await
        }
        "eventsource/request-status-error.window.js#404" => {
            request_cases::status(context, 404).await
        }
        "eventsource/request-status-error.window.js#410" => {
            request_cases::status(context, 410).await
        }
        "eventsource/request-status-error.window.js#503" => {
            request_cases::status(context, 503).await
        }
        _ => Err(invalid_input(format!("unsupported case {case}")).into()),
    }
}

impl Config {
    fn parse(arguments: impl IntoIterator<Item = String>) -> Result<Self, BoxError> {
        let mut base_url = None;
        let mut ca_der = None;
        let mut cases = Vec::new();
        let mut arguments = arguments.into_iter();
        while let Some(argument) = arguments.next() {
            let value = arguments
                .next()
                .ok_or_else(|| invalid_input(format!("missing value after {argument}")))?;
            match argument.as_str() {
                "--url" => base_url = Some(Url::parse(&value)?),
                "--ca-der" => ca_der = Some(PathBuf::from(value)),
                "--case" => cases.push(value),
                _ => return Err(invalid_input(format!("unknown argument {argument}")).into()),
            }
        }

        let base_url = base_url.ok_or_else(|| invalid_input("--url is required"))?;
        validate_base_url(&base_url)?;
        if cases.is_empty() {
            return Err(invalid_input("at least one --case is required").into());
        }
        Ok(Self {
            base_url,
            ca_der: ca_der.ok_or_else(|| invalid_input("--ca-der is required"))?,
            cases,
        })
    }
}

fn validate_base_url(url: &Url) -> io::Result<()> {
    if url.scheme() != "https"
        || url.host_str() != Some("localhost")
        || url.cannot_be_a_base()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid_input(
            "--url must be an https://localhost:<port>/ root URL",
        ));
    }
    Ok(())
}

fn endpoint(base_url: &Url, path: &str, query: &[(&str, &str)]) -> Result<Url, url::ParseError> {
    let mut url = base_url.join(path)?;
    if !query.is_empty() {
        url.query_pairs_mut().extend_pairs(query.iter().copied());
    }
    Ok(url)
}

fn one_line(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            '\n' | '\r' | '\t' => ' ',
            other => other,
        })
        .take(500)
        .collect()
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::{BoxError, Config, validate_base_url};
    use url::Url;

    #[test]
    fn config_requires_local_https_and_one_case() -> Result<(), BoxError> {
        assert!(validate_base_url(&Url::parse("https://localhost:8443/")?).is_ok());
        assert!(validate_base_url(&Url::parse("http://localhost:8000/")?).is_err());
        assert!(validate_base_url(&Url::parse("https://127.0.0.1:8443/")?).is_err());
        assert!(Config::parse(["--url".into(), "https://localhost:8443/".into()]).is_err());
        Ok(())
    }
}
