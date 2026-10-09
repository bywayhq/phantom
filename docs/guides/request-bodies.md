# Request bodies

Prepare form, JSON, or multipart bytes with a size limit, then send them in
the header positions you choose.

## Send an ordered form

Use `PreparedRequestBody::form` to keep the order and repeated names of your
UTF-8 pairs. Set one matching `Content-Type` header when using no template.

```rust
use phantom::{Client, HttpProtocol, Method, PreparedRequestBody, RequestHeader};

async fn form(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let body = PreparedRequestBody::form(
        [("tag", "rust"), ("tag", "http"), ("search", "a + b")],
        4096,
    )?;
    let response = client
        .request(HttpProtocol::Http2, Method::POST, "https://example.com/form")?
        .without_template()
        .header(RequestHeader::new("content-type", body.content_type()))
        .prepared_body(body)
        .send().await?;
    drop(response);
    Ok(())
}
```

Spaces become `+`, and literal plus signs become `%2B`. Empty names and
values remain in the body. The content type is exactly
`application/x-www-form-urlencoded;charset=UTF-8`. This encodes URL tuples
without the newline changes of an HTML form submission.

## Prepare JSON

Enable the `json` feature to serialize a value into bounded bytes.

```rust
use phantom::PreparedRequestBody;

#[cfg(feature = "json")]
fn json() -> Result<PreparedRequestBody, phantom::PreparedBodyError> {
    let value = std::collections::BTreeMap::from([("name", "Arya")]);
    PreparedRequestBody::json(&value, 4096)
}
```

The content type is exactly `application/json`. Send it with the same
explicit header placement as the form example. JSON uses Serde's encoding.
The output limit does not bound allocations inside a custom serializer.
Preparation errors format only their category. A JSON error's source keeps
the original serializer error, which may contain your serializer's message.

## Prepare multipart fields

Choose a boundary and supply ordered text or binary parts. Preparation reads
no files and makes no random draws.

```rust
use phantom::{MultipartPart, PreparedRequestBody};

fn multipart() -> Result<PreparedRequestBody, phantom::PreparedBodyError> {
    let parts = [
        MultipartPart::text("description", "first line\nsecond line")?,
        MultipartPart::bytes("file", b"binary contents")?
            .with_filename("report.bin")?,
    ];
    PreparedRequestBody::multipart("upload-boundary-01", parts, 1 << 20)
}
```

Text line endings become CRLF. Binary bytes stay unchanged. Text parts omit
a part content type. Binary parts use `application/octet-stream` unless you
set one with `with_content_type`. Adding a filename does not change encoding.

The size limit includes part headers and delimiters. Names and filenames
escape quotes and line breaks. Literal backslashes stay unchanged. A payload
containing `--` followed by your boundary is rejected, even mid-line.

## Use an upload template

Select a same-origin POST upload template to place the body headers. Supply
the page's `Origin` and `Referer` through its caller slots.

```rust
use phantom::profile::browser::chrome;
use phantom::{Client, HttpProtocol, Method, PreparedRequestBody,
    PreparedRequestTemplate, RequestHeader};

async fn upload(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let template = PreparedRequestTemplate::new(
        chrome::v154_windows_fetch_upload_template(),
    )?;
    let body = PreparedRequestBody::form([("message", "hello")], 4096)?;
    let response = client
        .request(HttpProtocol::Http2, Method::POST, "https://example.com/upload")?
        .template(&template)
        .fill_slots(|slots| {
            slots.fill(RequestHeader::new("origin", "https://example.com"))?;
            slots.fill(RequestHeader::new("referer", "https://example.com/page"))
        })?
        .prepared_body(body)
        .send().await?;
    drop(response);
    Ok(())
}
```

Use this with a matching Chrome profile and client hints. The prepared body
fills the declared `Content-Type` and `Content-Length` positions. Firefox's
Windows upload template also needs your `Priority` value for HTTP/1.1.
The [upload table](../reference/profiles.md#upload-templates) lists positions
and protocol support.

## Limits

- Missing content-type placement, duplicates, or a different value reject
  the request. Phantom does not append a content type for you.
- Upload templates cover same-origin Windows Chrome and Firefox POSTs over
  HTTP/1.1 and HTTP/2. They do not cover navigation or form submission.
- Multipart preparation accepts at most 1024 parts. Metadata limits and
  boundary rules are in `PreparedRequestBody::multipart` rustdoc.
- Body encoding does not establish browser parity for JSON or form bytes,
  multipart boundaries, or transport framing.

## Next

- [Request templates](request-templates.md): fill declared header slots.
- [Using the client](client.md#send-headers-a-body-and-trailers): send bytes
  or a streaming body.
- [Profile reference](../reference/profiles.md#upload-templates): upload
  headers and required caller values.
