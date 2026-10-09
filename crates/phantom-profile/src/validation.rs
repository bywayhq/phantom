/// The recovery category of a profile validation failure.
///
/// Each validator assigns a category at the failing check. Use the error's
/// `field()` and `reason()` for diagnostics, rather than matching their text.
/// The typed validator error identifies which settings type needs repair.
///
/// ```
/// use phantom_profile::{TlsVersion, TlsVersionRange, ValidationErrorKind};
///
/// let error = TlsVersionRange::try_from((TlsVersion::Tls13, TlsVersion::Tls12))
///     .unwrap_err();
/// assert_eq!(error.kind(), ValidationErrorKind::Inconsistent);
/// assert_eq!(error.field(), "version range");
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ValidationErrorKind {
    /// A required value, list, or advertised setting is absent.
    Missing,
    /// A value or placeholder occurs more than permitted.
    Duplicate,
    /// A value has invalid syntax, shape, or encoding.
    InvalidValue,
    /// A numeric value, length, or duration is outside its allowed range.
    OutOfRange,
    /// An encoded collection exceeds its size or representation limit.
    TooLarge,
    /// Settings disagree or require another setting to be enabled.
    Inconsistent,
    /// A setting requests a feature or field this context does not support.
    Unsupported,
}
