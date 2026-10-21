//! Validated origin and proxy leaf SPKI restrictions.

use napi::Result;
use phantom::ServerSpkiPins;

use crate::error::failure;

#[derive(Debug, Default)]
pub(crate) struct ServerPins {
    pub(crate) origin: Option<ServerSpkiPins>,
    pub(crate) proxy: Option<ServerSpkiPins>,
}

pub(crate) fn count(length: usize, field: &str) -> Result<()> {
    if !(1..=32).contains(&length) {
        return Err(failure(
            "InvalidArgument",
            &format!("{field} requires one to 32 supplied digests"),
        ));
    }
    Ok(())
}

pub(crate) fn digest_length(field: &str) -> napi::Error {
    failure(
        "InvalidArgument",
        &format!("{field} entries must contain exactly 32 bytes"),
    )
}

pub(crate) fn pins(input: Vec<Vec<u8>>, field: &str) -> Result<ServerSpkiPins> {
    count(input.len(), field)?;
    let digests = input
        .into_iter()
        .map(|digest| digest.try_into().map_err(|_| digest_length(field)))
        .collect::<Result<Vec<[u8; 32]>>>()?;
    ServerSpkiPins::new(digests).map_err(|_| {
        failure(
            "InvalidArgument",
            &format!("{field} requires one to 32 supplied digests"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supplied_count_precedes_canonicalization_and_errors_hide_digests() -> Result<()> {
        let pins = pins(
            vec![vec![2; 32], vec![1; 32], vec![2; 32]],
            "serverSpkiPins",
        )?;
        assert_eq!(pins.sha256_digests(), &[[1; 32], [2; 32]]);
        assert_eq!(format!("{pins:?}"), "ServerSpkiPins { count: 2, .. }");
        assert!(super::pins(vec![vec![1; 32]; 32], "serverSpkiPins").is_ok());
        for length in [0, 33] {
            assert!(super::pins(vec![vec![1; 32]; length], "serverSpkiPins").is_err());
        }
        for field in ["serverSpkiPins", "proxyServerSpkiPins"] {
            for length in [0, 31, 33] {
                let error = super::pins(vec![vec![85; length]], field).err();
                assert!(error.is_some_and(|error| error.reason
                    == format!(
                        "PHANTOM:InvalidArgument:{field} entries must contain exactly 32 bytes"
                    )));
            }
        }
        Ok(())
    }
}
