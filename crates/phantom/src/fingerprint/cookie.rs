//! Complete cookie description parsing.

use super::{Result, json::Value};
use phantom_profile::CookiePlacement;

pub(super) fn parse(v: &Value) -> Result<CookiePlacement> {
    v.record(&["before"], "cookie_placement")?;
    Ok(CookiePlacement::before_fields(
        v.member("before", "cookie_placement.before")?
            .list("cookie_placement.before", |v| {
                Ok(v.text("cookie_placement.before")?.to_owned())
            })?,
    ))
}
