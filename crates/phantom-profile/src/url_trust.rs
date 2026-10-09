/// Selects field values for a potentially trustworthy URL or another URL.
///
/// A potentially trustworthy URL includes HTTPS, loopback HTTP addresses,
/// `localhost`, and `.localhost` names. This selector does not inspect a URL
/// or change certificate verification. The caller supplies the classification.
///
/// ```
/// use phantom_profile::{RequestField, UrlTrust};
///
/// let field = RequestField::by_trust("Accept-Encoding", "gzip, br", "gzip");
/// assert_eq!(field.default_value(UrlTrust::PotentiallyTrustworthy), Some("gzip, br"));
/// assert_eq!(field.default_value(UrlTrust::Untrustworthy), Some("gzip"));
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum UrlTrust {
    /// A potentially trustworthy URL.
    PotentiallyTrustworthy,
    /// A URL outside the potentially trustworthy set.
    Untrustworthy,
}
