use crate::{Config, Result};
use http::{HeaderMap, Method, header};
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Clone)]
pub(super) struct Upload {
    method: Method,
    length: usize,
}

impl Upload {
    pub(super) fn new(config: &Config) -> Self {
        Self {
            method: if config.method == "POST" {
                Method::POST
            } else {
                Method::GET
            },
            length: config.upload_bytes,
        }
    }

    pub(super) fn length(&self) -> usize {
        self.length
    }

    pub(super) fn head(&self, method: &Method, headers: &HeaderMap, http1: bool) -> Result<()> {
        if headers.contains_key(header::PROXY_AUTHORIZATION) {
            return Err("proxy credentials reached the origin".into());
        }
        if method != self.method || headers.contains_key(header::TRANSFER_ENCODING) {
            return Err("unexpected upload method or transfer encoding".into());
        }
        let mut lengths = headers.get_all(header::CONTENT_LENGTH).iter();
        let length = lengths
            .next()
            .map(|value| -> Result<usize> { Ok(value.to_str()?.parse()?) })
            .transpose()?;
        if lengths.next().is_some()
            || length.is_some_and(|length| length != self.length)
            || (http1 && self.length != 0 && length.is_none())
        {
            return Err("upload content length differs from the configured workload".into());
        }
        Ok(())
    }

    pub(super) fn chunk(&self, observed: &mut usize, bytes: &[u8]) -> Result<()> {
        *observed = observed
            .checked_add(bytes.len())
            .ok_or("upload length overflow")?;
        if *observed > self.length || bytes.iter().any(|byte| *byte != b'U') {
            return Err("incorrect upload content or length".into());
        }
        Ok(())
    }

    pub(super) fn finish(&self, observed: usize) -> Result<()> {
        if observed != self.length {
            return Err("truncated upload".into());
        }
        Ok(())
    }

    pub(super) async fn http1<S: AsyncRead + Unpin>(
        &self,
        head: &str,
        stream: &mut S,
    ) -> Result<String> {
        let mut fields = [httparse::EMPTY_HEADER; 128];
        let mut request = httparse::Request::new(&mut fields);
        if !request.parse(head.as_bytes())?.is_complete() {
            return Err("incomplete upload request head".into());
        }
        let method = Method::from_bytes(request.method.ok_or("missing method")?.as_bytes())?;
        let target = request.path.ok_or("missing request target")?.to_owned();
        let mut headers = HeaderMap::new();
        for field in request.headers {
            headers.append(
                header::HeaderName::from_bytes(field.name.as_bytes())?,
                header::HeaderValue::from_bytes(field.value)?,
            );
        }
        self.head(&method, &headers, true)?;
        let mut observed = 0;
        let mut buffer = [0; 16384];
        while observed < self.length {
            let limit = buffer.len().min(self.length - observed);
            let length = stream.read(&mut buffer[..limit]).await?;
            if length == 0 {
                break;
            }
            self.chunk(&mut observed, &buffer[..length])?;
        }
        self.finish(observed)?;
        Ok(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn http1_upload_requires_the_expected_method_framing_and_complete_payload() -> Result<()>
    {
        let upload = Upload::new(&Config {
            method: "POST".into(),
            upload_bytes: 3,
            ..Config::default()
        });
        for (head, data, valid) in [
            (
                "POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\n",
                &b"UUU"[..],
                true,
            ),
            (
                "GET / HTTP/1.1\r\nContent-Length: 3\r\n\r\n",
                &b"UUU"[..],
                false,
            ),
            ("POST / HTTP/1.1\r\n\r\n", &b"UUU"[..], false),
            (
                "POST / HTTP/1.1\r\ncontent-length: 4\r\n\r\n",
                &b"UUU"[..],
                false,
            ),
            (
                "POST / HTTP/1.1\r\ncontent-length: 3\r\ncontent-length: 3\r\n\r\n",
                &b"UUU"[..],
                false,
            ),
            (
                "POST / HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n",
                &b"UUU"[..],
                false,
            ),
            (
                "POST / HTTP/1.1\r\ncontent-length: 3\r\n\r\n",
                &b"UXU"[..],
                false,
            ),
            (
                "POST / HTTP/1.1\r\ncontent-length: 3\r\n\r\n",
                &b"UU"[..],
                false,
            ),
        ] {
            let result = upload.http1(head, &mut &data[..]).await;
            assert_eq!(result.is_ok(), valid, "{head:?} {data:?}: {result:?}");
        }
        let empty = Upload::new(&Config {
            method: "POST".into(),
            ..Config::default()
        });
        empty
            .http1(
                "POST / HTTP/1.1\r\ncontent-length: 0\r\n\r\n",
                &mut &b""[..],
            )
            .await?;
        Ok(())
    }

    #[test]
    fn multiplexed_uploads_reject_extra_wrong_and_truncated_data() -> Result<()> {
        let upload = Upload::new(&Config {
            method: "POST".into(),
            upload_bytes: 3,
            ..Config::default()
        });
        upload.head(&Method::POST, &HeaderMap::new(), false)?;
        let mut observed = 0;
        upload.chunk(&mut observed, b"U")?;
        assert!(upload.finish(observed).is_err());
        upload.chunk(&mut observed, b"UU")?;
        upload.finish(observed)?;
        assert!(upload.chunk(&mut observed, b"U").is_err());
        assert!(upload.chunk(&mut 0, b"X").is_err());
        assert!(upload.head(&Method::GET, &HeaderMap::new(), false).is_err());
        Ok(())
    }
}
