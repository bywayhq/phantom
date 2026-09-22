//! Position of the automatic `Cookie` request field.

/// Where a client inserts the `Cookie` field computed from its cookie jar.
///
/// The field goes immediately before the first request field whose name
/// equals one of the listed names, compared ASCII case-insensitively, or last
/// when no listed field is present. The default lists no names, so the field
/// always goes last. A caller-supplied `Cookie` field is never moved.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CookiePlacement {
    before: Vec<Box<str>>,
}

impl CookiePlacement {
    /// Places the field after every other request field.
    #[must_use]
    pub fn last() -> Self {
        Self::default()
    }

    /// Places the field before the first field with one of `names`.
    #[must_use]
    pub fn before_fields<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<Box<str>>,
    {
        Self {
            before: names.into_iter().map(Into::into).collect(),
        }
    }

    /// Returns the field names the `Cookie` field precedes, in list order.
    #[must_use]
    pub fn before(&self) -> &[Box<str>] {
        &self.before
    }

    /// Returns the index at which to insert the `Cookie` field among fields
    /// with `names`, in wire order.
    #[must_use]
    pub fn insertion_index<'a>(&self, names: impl IntoIterator<Item = &'a str>) -> Option<usize> {
        names.into_iter().position(|name| {
            self.before
                .iter()
                .any(|listed| listed.eq_ignore_ascii_case(name))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::CookiePlacement;

    #[test]
    fn last_never_precedes_a_field() {
        assert_eq!(
            CookiePlacement::last().insertion_index(["accept", "priority"]),
            None
        );
    }

    #[test]
    fn before_fields_matches_the_first_listed_name_case_insensitively() {
        let placement = CookiePlacement::before_fields(["priority", "sec-fetch-dest"]);

        assert_eq!(
            placement.insertion_index(["Accept", "Sec-Fetch-Dest", "Priority"]),
            Some(1)
        );
        assert_eq!(
            placement.insertion_index(["accept", "accept-language"]),
            None
        );
    }
}
