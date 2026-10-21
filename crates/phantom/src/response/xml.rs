//! Typed reads of bounded UTF-8 XML documents.

use std::{error::Error as StdError, fmt};

use http::Response;
use quick_xml::{
    Reader,
    de::Deserializer,
    events::{BytesDecl, BytesStart, Event},
};
use serde::de::DeserializeOwned;

use super::{ResponseReadCause, ResponseReadError, response_bytes};
use crate::ResponseBody;

const MAXIMUM_DEPTH: usize = 128;

/// Reads bounded UTF-8 XML into your chosen type, keeping response metadata.
///
/// Enable the `xml` feature. Uses [`response_bytes`] for collection, byte limits
/// and cleanup. The limit counts decoded bytes when content decoding is enabled.
/// This helper does not check the status, require a Content-Type, choose an HTTP
/// charset, or enable content decoding. Completed trailers remain in response
/// extensions; partial data is discarded.
///
/// Accepts one XML document with at most 128 element levels, an optional UTF-8
/// byte-order mark, and an absent or UTF-8 XML encoding declaration. DOCTYPE
/// declarations are rejected, including in ignored content. Custom entities and
/// external resources are not resolved. Attribute fields use `@name`; text
/// fields use `$text`, following quick-xml's Serde mapping. These checks are not
/// complete XML well-formedness or schema validation.
///
/// The byte cap bounds collected input, not allocations made by deserialization.
/// Dropping the future cancels a pending body read. Parsing runs synchronously
/// after collection; cancellation and I/O deadlines cannot preempt that work.
///
/// ```no_run
/// # async fn example(response: phantom::Response<phantom::ResponseBody>) -> Result<(), Box<dyn std::error::Error>> {
/// #[derive(serde::Deserialize)]
/// struct Message {
///     text: String,
/// }
/// let response = phantom::response_xml::<Message>(response, 1 << 20).await?;
/// println!("{}", response.body().text);
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns a body error, [`super::ResponseReadErrorKind::Utf8`] for invalid UTF-8,
/// or [`super::ResponseReadErrorKind::Xml`] for unsupported XML, malformed input,
/// or a value that cannot be deserialized into `T`. Errors retain the original
/// status, headers, version and extensions with a unit body.
pub async fn response_xml<T: DeserializeOwned>(
    response: Response<ResponseBody>,
    maximum_bytes: usize,
) -> Result<Response<T>, ResponseReadError> {
    let (parts, bytes) = response_bytes(response, maximum_bytes).await?.into_parts();
    let value = match std::str::from_utf8(&bytes) {
        Ok(text) => parse(text).map_err(ResponseReadCause::Xml),
        Err(error) => Err(ResponseReadCause::Utf8(error)),
    };
    match value {
        Ok(value) => Ok(Response::from_parts(parts, value)),
        Err(cause) => Err(ResponseReadError {
            response: Box::new(Response::from_parts(parts, ())),
            cause,
        }),
    }
}

fn parse<T: DeserializeOwned>(text: &str) -> Result<T, XmlError> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    validate_document(text)?;
    let mut deserializer = Deserializer::from_str(text);
    deserializer.recursion_limit(MAXIMUM_DEPTH);
    T::deserialize(&mut deserializer).map_err(XmlError::Deserialize)
}

fn validate_document(text: &str) -> Result<(), XmlError> {
    // Serde can skip fields or finish before EOF. Check the whole document so
    // those paths cannot bypass DOCTYPE, encoding, tail or nesting checks.
    let mut reader = Reader::from_str(text);
    reader.config_mut().enable_all_checks(true);
    reader.config_mut().expand_empty_elements = true;
    let mut depth = 0;
    let mut root_seen = false;
    let mut declaration_allowed = true;
    let mut version = quick_xml::XmlVersion::Implicit1_0;
    loop {
        match reader.read_event()? {
            Event::Decl(declaration) if declaration_allowed => {
                version = validate_declaration(&declaration)?;
            }
            Event::Decl(_) => return Err(XmlError::Document("misplaced XML declaration")),
            Event::DocType(_) => return Err(XmlError::Document("DOCTYPE is unsupported")),
            Event::Start(start) => {
                if depth == 0 {
                    if root_seen {
                        return Err(XmlError::Document("multiple root elements"));
                    }
                    root_seen = true;
                }
                if depth >= MAXIMUM_DEPTH {
                    return Err(XmlError::Document("XML nesting exceeds 128 levels"));
                }
                for attribute in start.attributes() {
                    attribute
                        .map_err(quick_xml::Error::from)?
                        .normalized_value_with(version, 1, quick_xml::escape::resolve_xml_entity)?;
                }
                depth += 1;
            }
            Event::End(_) => {
                depth = depth
                    .checked_sub(1)
                    .ok_or(XmlError::Document("unmatched XML end tag"))?;
            }
            Event::Text(text)
                if depth == 0
                    && !text
                        .chars()
                        .all(|ch| matches!(ch, ' ' | '\t' | '\r' | '\n')) =>
            {
                return Err(XmlError::Document("text outside the root element"));
            }
            Event::CData(_) | Event::GeneralRef(_) if depth == 0 => {
                return Err(XmlError::Document("content outside the root element"));
            }
            Event::GeneralRef(reference) => {
                if reference.resolve_char_ref()?.is_none()
                    && quick_xml::escape::resolve_xml_entity(&reference).is_none()
                {
                    return Err(XmlError::Document("custom XML entity is unsupported"));
                }
            }
            Event::Eof => {
                return if root_seen && depth == 0 {
                    Ok(())
                } else {
                    Err(XmlError::Document("missing or unfinished root element"))
                };
            }
            _ => {}
        }
        declaration_allowed = false;
    }
}

fn validate_declaration(declaration: &BytesDecl<'_>) -> Result<quick_xml::XmlVersion, XmlError> {
    let version = declaration.xml_version()?;
    // encoding() returns only the first occurrence. The attribute iterator
    // also detects duplicates, including contradictory encoding declarations.
    let start = BytesStart::from_content(declaration.as_ref(), 3);
    let mut standalone_seen = false;
    for attribute in start.attributes() {
        let attribute = attribute.map_err(quick_xml::Error::from)?;
        match attribute.key.as_ref() {
            "version" => {}
            "encoding" if !standalone_seen && attribute.value.eq_ignore_ascii_case("UTF-8") => {}
            "standalone" if matches!(attribute.value.as_ref(), "yes" | "no") => {
                standalone_seen = true;
            }
            _ => return Err(XmlError::Document("unsupported XML declaration")),
        }
    }
    Ok(version)
}

#[derive(Debug)]
pub(super) enum XmlError {
    Read(quick_xml::Error),
    Deserialize(quick_xml::DeError),
    Document(&'static str),
}

impl From<quick_xml::Error> for XmlError {
    fn from(error: quick_xml::Error) -> Self {
        Self::Read(error)
    }
}

impl fmt::Display for XmlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(_) => formatter.write_str("XML parsing failed"),
            Self::Deserialize(_) => formatter.write_str("XML deserialization failed"),
            Self::Document(message) => formatter.write_str(message),
        }
    }
}

impl StdError for XmlError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Read(error) => Some(error),
            Self::Deserialize(error) => Some(error),
            Self::Document(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    struct Message {
        #[serde(rename = "@id")]
        id: u32,
        text: String,
        #[serde(default)]
        item: Vec<String>,
    }

    #[test]
    fn utf8_documents_keep_attributes_lists_cdata_and_predefined_entities()
    -> Result<(), Box<dyn StdError>> {
        let message = parse::<Message>(
            "\u{feff}<?xml version='1.0' encoding='uTf-8' standalone='yes'?>\n\
             <!--before--><message id='7'><text>caf\u{e9} &amp; <![CDATA[tea]]></text>\
             <item>&lt;one&gt;</item><item>&#50;</item></message>\n<!--after-->",
        )?;
        assert_eq!(message.id, 7);
        assert_eq!(message.text, "caf\u{e9} & tea");
        assert_eq!(message.item, ["<one>", "2"]);
        Ok(())
    }

    #[test]
    fn declarations_and_all_document_content_are_checked_before_deserialization() {
        for text in [
            "",
            "<!--no root-->",
            "<a/><b/>",
            "<a/>tail",
            "<a/><![CDATA[tail]]>",
            "<a/>&amp;",
            "<a/><!--unterminated",
            "<a><!--bad--comment--></a>",
            "<a>",
            "<a></b>",
            "<?xml version='1.0' encoding='UTF-16'?><a/>",
            "<?xml version='1.0' encoding='UTF-8' encoding='latin1'?><a/>",
            "<?xml version='1.0' encoding='UTF-8' encoding='UTF-8'?><a/>",
            "<?xml version='1.0' standalone='yes' encoding='UTF-8'?><a/>",
            "<?xml version='1.0' other='secret'?><a/>",
            "<?xml version='1.0' standalone='maybe'?><a/>",
            " <?xml version='1.0'?><a/>",
            "<a/><?xml version='1.0'?>",
            "<!DOCTYPE a SYSTEM 'file:///private'><a/>",
            "<!DOCTYPE a [<!ENTITY x 'secret'>]><a>&x;</a>",
            "<a><ignored><!DOCTYPE x SYSTEM 'https://example.test/'></ignored></a>",
            "<a/><!DOCTYPE x>",
            "<a><ignored>&unknown;</ignored></a>",
            "<a><ignored>&#xZZ;</ignored></a>",
            "<a><ignored x='1' x='2'/></a>",
            "<a><ignored x='&unknown;'/></a>",
        ] {
            assert!(parse::<()>(text).is_err(), "accepted {text:?}");
        }
    }

    #[test]
    fn depth_limit_also_covers_ignored_fields_and_empty_elements() {
        for (levels, accepted) in [(127, true), (128, true), (129, false)] {
            let text = format!(
                "{}<leaf/>{}",
                "<a>".repeat(levels - 1),
                "</a>".repeat(levels - 1)
            );
            assert_eq!(parse::<()>(&text).is_ok(), accepted);
        }
    }

    #[test]
    fn type_mismatches_retain_the_deserializer_cause() {
        assert!(matches!(
            parse::<Message>("<message id='secret'><text>ok</text></message>"),
            Err(XmlError::Deserialize(_))
        ));
    }
}
