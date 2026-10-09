use std::error::Error;

use super::{LinkParseErrorKind, parse_link_headers, valid_uri_reference};

type TestResult = Result<(), Box<dyn Error>>;

fn parse(value: &[u8]) -> Result<Vec<super::Link>, super::LinkParseError> {
    parse_link_headers([value], value.len())
}

#[test]
fn rfc_examples_preserve_order_targets_and_attributes() -> TestResult {
    let links = parse(br##"<http://example.com/TheBook/chapter2>; rel="previous"; title="previous chapter", </>; rel="http://example.net/foo", </terms>; rel="copyright"; anchor="#foo""##)?;
    assert_eq!(links.len(), 3);
    assert_eq!(links[0].target(), "http://example.com/TheBook/chapter2");
    assert_eq!(links[0].relations(), ["previous"]);
    assert_eq!(
        links[0]
            .first_parameter("title")
            .and_then(|value| value.value()),
        Some(&b"previous chapter"[..])
    );
    assert_eq!(links[1].target(), "/");
    assert!(links[1].has_relation("http://example.net/foo"));
    assert_eq!(links[2].anchor(), Some("#foo"));
    Ok(())
}

#[test]
fn repeated_header_values_match_a_combined_value() -> TestResult {
    let first = b"<https://example.org/>; rel=start";
    let second = b"<https://example.org/index>; rel=index";
    let separate = parse_link_headers([&first[..], &second[..]], first.len() + 1 + second.len())?;
    let combined =
        parse(br#"<https://example.org/>; rel=start,<https://example.org/index>; rel=index"#)?;
    assert_eq!(separate, combined);
    let mut headers = http::HeaderMap::new();
    headers.append(http::header::LINK, http::HeaderValue::from_bytes(first)?);
    headers.append(http::header::LINK, http::HeaderValue::from_bytes(second)?);
    let supplied = parse_link_headers(
        headers
            .get_all(http::header::LINK)
            .iter()
            .map(http::HeaderValue::as_bytes),
        1024,
    )?;
    assert_eq!(supplied, separate);
    Ok(())
}

#[test]
fn quoted_delimiters_and_escapes_are_data() -> TestResult {
    let links = parse(br#"<https://example.test/a,b;c?q=a,b>; REL="Next previous"; title="comma, semicolon; quote\" slash\\"; empty=""; flag; token=abc!#$%&'*+-.^_`|~"#)?;
    let link = &links[0];
    assert_eq!(link.target(), "https://example.test/a,b;c?q=a,b");
    assert_eq!(link.relations(), ["Next", "previous"]);
    assert_eq!(link.parameters()[0].name(), "REL");
    assert_eq!(
        link.parameters()[1].value(),
        Some(&b"comma, semicolon; quote\" slash\\"[..])
    );
    assert_eq!(link.parameters()[2].value(), Some(&b""[..]));
    assert_eq!(link.parameters()[3].value(), None);
    assert_eq!(
        link.parameters()[4].value(),
        Some(&b"abc!#$%&'*+-.^_`|~"[..])
    );
    Ok(())
}

#[test]
fn whitespace_and_empty_list_elements_do_not_reorder_links() -> TestResult {
    let links = parse(b" ,\t<one> \t; \tReL \t= \t\"next  last\" , , <two>;rel=previous, ")?;
    assert_eq!(links.len(), 2);
    assert_eq!(links[0].target(), "one");
    assert_eq!(links[0].relations(), ["next", "last"]);
    assert_eq!(links[1].target(), "two");
    assert!(parse(b" , , \t ")?.is_empty());
    Ok(())
}

#[test]
fn first_relation_and_anchor_govern_semantics_without_dropping_duplicates() -> TestResult {
    let links = parse(br#"</first>; rel=next; REL="not/a/relation"; anchor="../context"; ANCHOR="not a URI"; hreflang=en; hreflang=de; title=one; title=two"#)?;
    let link = &links[0];
    assert_eq!(link.relations(), ["next"]);
    assert_eq!(link.anchor(), Some("../context"));
    assert_eq!(link.parameters().len(), 8);
    assert_eq!(link.parameters()[1].value(), Some(&b"not/a/relation"[..]));
    assert_eq!(link.parameters()[3].value(), Some(&b"not a URI"[..]));
    assert_eq!(
        link.first_parameter("TITLE")
            .and_then(|value| value.value()),
        Some(&b"one"[..])
    );
    assert_eq!(link.parameters()[5].value(), Some(&b"de"[..]));
    Ok(())
}

#[test]
fn missing_rel_is_data_but_an_invalid_first_rel_is_an_error() -> TestResult {
    let links = parse(br#"</first>; title="no relation", </second>"#)?;
    assert!(links.iter().all(|link| link.relations().is_empty()));
    for value in [
        &b"</>; rel"[..],
        &b"</>; rel=\"\""[..],
        &b"</>; rel=\" next\""[..],
        &b"</>; rel=\"next \""[..],
        &b"</>; rel=\"next\tlast\""[..],
        &b"</>; rel=\"not/a/relation\""[..],
        &b"</>; rel=123"[..],
        &b"</>; rel=\"https://example.test/%xy\""[..],
        &b"</>; rel=\"\xff\""[..],
    ] {
        assert_eq!(
            parse(value).err().map(|error| error.kind()),
            Some(LinkParseErrorKind::InvalidRelation)
        );
    }
    assert_eq!(
        parse(br#"</>; rel="bad/value"; rel=next"#)
            .err()
            .map(|error| error.kind()),
        Some(LinkParseErrorKind::InvalidRelation)
    );
    Ok(())
}

#[test]
fn registered_and_extension_relations_compare_as_case_insensitive_strings() -> TestResult {
    let links =
        parse(br#"</>; rel="Next HTTPS://EXAMPLE.test/Relation?Mode=A urn:example:relation""#)?;
    let link = &links[0];
    assert!(link.has_relation("NEXT"));
    assert!(link.has_relation("https://example.TEST/relation?mode=a"));
    assert!(link.has_relation("URN:EXAMPLE:RELATION"));
    assert!(!link.has_relation("https://example.test/Relation?Mode=B"));
    let percent = parse(br#"</>; rel="https://example.test/%6Eext""#)?;
    assert!(percent[0].has_relation("HTTPS://EXAMPLE.TEST/%6eEXT"));
    assert!(!percent[0].has_relation("https://example.test/next"));
    assert_eq!(link.relations()[1], "HTTPS://EXAMPLE.test/Relation?Mode=A");
    Ok(())
}

#[test]
fn relative_references_and_anchor_spelling_remain_unchanged() -> TestResult {
    for target in [
        "",
        "../page/2",
        "/page/2",
        "?page=2",
        "#part",
        "//other.test/page",
        "./a:b",
        "a%3Ab",
        "urn:example:book",
        "mailto:user@example.test",
        "https://EXAMPLE.test/%2f?q=A#B",
    ] {
        let value = format!("<{target}>; rel=next; anchor=\"../context#part\"");
        let links = parse(value.as_bytes())?;
        assert_eq!(links[0].target(), target);
        assert_eq!(links[0].anchor(), Some("../context#part"));
    }
    assert_eq!(parse(br#"<>; anchor="""#)?[0].anchor(), Some(""));
    Ok(())
}

#[test]
fn uri_reference_grammar_covers_components_and_ip_literals() {
    for value in [
        "http://user:pass@host.test:8080/a;b?x=y/z?#part?",
        "//host:",
        "//",
        "http:///path",
        "/",
        "a//b",
        "a:b",
        "a:",
        "http://[::1]/",
        "http://[2001:db8::192.0.2.1]:80/",
        "http://[v1.a:b!]/",
        "http://[VF.abc]/",
        "http://999.999/",
        "http://reg%2Dname/",
        "/%00%FF",
        "?",
        "#",
    ] {
        assert!(valid_uri_reference(value), "rejected {value}");
    }
    for value in [
        "1:a",
        ":a",
        "a b",
        "a\nb",
        "a\\b",
        "a[1]",
        "?a[1]",
        "#a[1]",
        "#a#b",
        "/%",
        "/%1",
        "/%xy",
        "http://user@@host/",
        "http://host:abc/",
        "http://::1/",
        "http://[not-ip]/",
        "http://[::1]extra/",
        "http://[::1]:abc/",
        "http://[v.a]/",
        "http://[v1.]/",
        "http://[v1.a%20]/",
        "http://[fe80::1%25eth0]/",
        "http://[12345::]/",
        "http://[1:2:3:4:5:6:7]/",
        "http://[::192.168.01.1]/",
        "café",
        "/<part>",
    ] {
        assert!(!valid_uri_reference(value), "accepted {value}");
    }
}

#[test]
fn rfc_3986_reference_examples_are_preserved() -> TestResult {
    // RFC 3986 section 5.4 examples, retained as references rather than joined.
    for target in [
        "g:h",
        "g",
        "./g",
        "g/",
        "/g",
        "//g",
        "?y",
        "g?y",
        "#s",
        "g#s",
        "g?y#s",
        ";x",
        "g;x",
        "g;x?y#s",
        "",
        ".",
        "./",
        "..",
        "../",
        "../g",
        "../..",
        "../../",
        "../../g",
        "../../../g",
        "../../../../g",
        "/./g",
        "/../g",
        "g.",
        ".g",
        "g..",
        "..g",
        "./../g",
        "./g/.",
        "g/./h",
        "g/../h",
        "g;x=1/./y",
        "g;x=1/../y",
        "g?y/./x",
        "g?y/../x",
        "g#s/./x",
        "g#s/../x",
        "http:g",
    ] {
        let value = format!("<{target}>;rel=next");
        assert_eq!(parse(value.as_bytes())?[0].target(), target);
    }
    Ok(())
}

#[test]
fn extended_parameters_remain_encoded_without_precedence_or_decoding() -> TestResult {
    let links = parse(br#"</TheBook/chapter4>; rel=next; title=plain; title*=UTF-8'de'n%c3%a4chstes%20Kapitel; custom*=unsupported'lang'%xy"#)?;
    let link = &links[0];
    assert_eq!(
        link.first_parameter("title")
            .and_then(|value| value.value()),
        Some(&b"plain"[..])
    );
    let extended = link.first_parameter("title*").ok_or("missing title*")?;
    assert!(extended.is_extended());
    assert_eq!(
        extended.value(),
        Some(&b"UTF-8'de'n%c3%a4chstes%20Kapitel"[..])
    );
    assert_eq!(
        link.parameters()[3].value(),
        Some(&b"unsupported'lang'%xy"[..])
    );
    Ok(())
}

#[test]
fn quoted_obs_text_and_escaped_octets_do_not_require_utf8() -> TestResult {
    let links = parse(b"</>; rel=next; title=\"\xff\\\x80\t\"; title*=\"\xfe\"")?;
    assert_eq!(links[0].parameters()[1].value(), Some(&b"\xff\x80\t"[..]));
    assert_eq!(links[0].parameters()[2].value(), Some(&b"\xfe"[..]));
    Ok(())
}

#[test]
fn quoted_pairs_accept_only_the_http_octet_ranges() -> TestResult {
    for byte in 0_u8..=u8::MAX {
        let mut value = b"<>;custom=\"\\".to_vec();
        value.push(byte);
        value.push(b'"');
        let allowed = byte == b'\t' || (b' '..=b'~').contains(&byte) || byte >= 0x80;
        if allowed {
            let links = parse(&value)?;
            assert_eq!(links[0].parameters()[0].value(), Some(&[byte][..]));
        } else {
            assert_eq!(
                parse(&value).err().map(|error| error.kind()),
                Some(LinkParseErrorKind::InvalidParameter)
            );
        }
    }
    Ok(())
}

#[test]
fn invalid_syntax_and_quoted_strings_return_typed_errors() {
    for (value, kind) in [
        (&b"/target; rel=next"[..], LinkParseErrorKind::InvalidSyntax),
        (&b"<target"[..], LinkParseErrorKind::InvalidSyntax),
        (&b"<> <>"[..], LinkParseErrorKind::InvalidSyntax),
        (&b"<>;"[..], LinkParseErrorKind::InvalidParameter),
        (&b"<>; bad(name)=x"[..], LinkParseErrorKind::InvalidSyntax),
        (&b"<>; =value"[..], LinkParseErrorKind::InvalidParameter),
        (&b"<>; x="[..], LinkParseErrorKind::InvalidParameter),
        (&b"<>; x=\"open"[..], LinkParseErrorKind::InvalidParameter),
        (
            &b"<>; x=\"escape\\"[..],
            LinkParseErrorKind::InvalidParameter,
        ),
        (&b"<>; x=\"a\nb\""[..], LinkParseErrorKind::InvalidParameter),
        (
            &b"<>; x=\"a\\\r\""[..],
            LinkParseErrorKind::InvalidParameter,
        ),
        (
            &b"<>; x=\"a\x7fb\""[..],
            LinkParseErrorKind::InvalidParameter,
        ),
        (
            &b"<>; x=\"a\x00b\""[..],
            LinkParseErrorKind::InvalidParameter,
        ),
        (&b"<>; x=a\xff"[..], LinkParseErrorKind::InvalidSyntax),
        (&b"<>\r\n"[..], LinkParseErrorKind::InvalidSyntax),
    ] {
        assert_eq!(parse(value).err().map(|error| error.kind()), Some(kind));
    }
}

#[test]
fn invalid_targets_and_first_anchors_fail_instead_of_producing_partial_links() {
    for target in ["a b", "/%xy", "http://[invalid]/", "/?bad[query]", "1:bad"] {
        let value = format!("</good>;rel=next,<{target}>;rel=last");
        assert_eq!(
            parse(value.as_bytes()).err().map(|error| error.kind()),
            Some(LinkParseErrorKind::InvalidTarget)
        );
    }
    for value in [
        &b"</>;anchor"[..],
        &b"</>;anchor=\"not a URI\""[..],
        &b"</>;anchor=\"/%xy\""[..],
        &b"</>;anchor=\"\xff\""[..],
    ] {
        assert_eq!(
            parse(value).err().map(|error| error.kind()),
            Some(LinkParseErrorKind::InvalidAnchor)
        );
    }
}

#[test]
fn byte_budget_counts_repeated_values_and_bounds_empty_value_iterators() -> TestResult {
    let value = b"</>;rel=next";
    assert_eq!(parse_link_headers([&value[..]], value.len())?.len(), 1);
    assert_eq!(
        parse_link_headers([&value[..]], value.len() - 1)
            .err()
            .map(|error| error.kind()),
        Some(LinkParseErrorKind::InputTooLarge)
    );
    let error = parse_link_headers([&value[..], &value[..]], value.len() * 2)
        .err()
        .ok_or("accepted a budget missing the separator")?;
    assert_eq!(error.kind(), LinkParseErrorKind::InputTooLarge);
    assert_eq!(error.value_index(), 1);
    assert_eq!(error.byte_offset(), 0);
    assert_eq!(
        parse_link_headers([&value[..], &value[..]], value.len() * 2 + 1)?.len(),
        2
    );
    assert!(parse_link_headers(std::iter::empty(), 0)?.is_empty());
    assert!(parse_link_headers([&b""[..]], 0)?.is_empty());
    let error = parse_link_headers(std::iter::repeat(&b""[..]), 3)
        .err()
        .ok_or("empty values exceeded budget without an error")?;
    assert_eq!(error.value_index(), 4);
    assert_eq!(error.kind(), LinkParseErrorKind::InputTooLarge);
    Ok(())
}

#[test]
fn errors_report_locations_and_formatting_reveals_no_header_data() -> TestResult {
    let secret = b"secret-user:secret-password@host.test";
    let value = b"</good>;rel=next,<https://secret-user:secret-password@host.test/%xy>;rel=last";
    let error = parse_link_headers([&b""[..], &value[..]], 1024)
        .err()
        .ok_or("accepted invalid target")?;
    assert_eq!(error.value_index(), 1);
    assert_eq!(error.byte_offset(), 18);
    assert_eq!(error.kind(), LinkParseErrorKind::InvalidTarget);
    for formatted in [
        error.to_string(),
        format!("{error:?}"),
        format!("{error:#?}"),
    ] {
        assert!(!formatted.contains(std::str::from_utf8(secret)?));
        assert!(!formatted.contains("secret"));
        assert!(!formatted.contains("%xy"));
    }
    assert!(error.source().is_none());
    let links = parse(br#"<https://secret-user:secret-password@host.test/?token=secret>;rel="https://relations.test/secret";secret-name="secret-value";anchor="/secret""#)?;
    assert!(!format!("{:?}", links[0]).contains("secret"));
    assert!(!format!("{:?}", links[0].parameters()).contains("secret"));
    Ok(())
}

#[test]
fn parsed_values_and_errors_are_cloneable_send_and_sync() {
    fn assert_traits<T: Clone + std::fmt::Debug + Eq + Send + Sync>() {}
    assert_traits::<super::Link>();
    assert_traits::<super::LinkParameter>();
    assert_traits::<super::LinkParseError>();
    assert_traits::<LinkParseErrorKind>();
}
