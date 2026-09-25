use super::table::{Index, Table};
use super::{huffman, Header};
use crate::ext::{CookieCrumbs, HpackEncoderProfile, HuffmanCoding};
use crate::tracing;

use bytes::{BufMut, BytesMut};
use http::header::{HeaderName, HeaderValue};

#[derive(Debug)]
pub struct Encoder {
    table: Table,
    size_update: Option<SizeUpdate>,
    huffman: HuffmanCoding,
    crumbs: CookieCrumbs,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum SizeUpdate {
    One(usize),
    Two(usize, usize), // min, max
}

impl Encoder {
    pub fn new(max_size: usize, capacity: usize) -> Encoder {
        Encoder {
            table: Table::new(max_size, capacity),
            size_update: None,
            huffman: HuffmanCoding::default(),
            crumbs: CookieCrumbs::default(),
        }
    }

    /// Adopts the caller's HPACK encoder choices.
    ///
    /// This must happen before the first field block is encoded, because the
    /// choices decide which entries reach the dynamic table.
    pub fn set_profile(&mut self, profile: HpackEncoderProfile) {
        self.huffman = profile.huffman();
        self.crumbs = profile.crumbs();
        self.table.set_profile(profile);
    }

    /// Queues a max size update.
    ///
    /// The next call to `encode` will include a dynamic size update frame.
    pub fn update_max_size(&mut self, val: usize) {
        match self.size_update {
            Some(SizeUpdate::One(old)) => {
                if val > old {
                    if old > self.table.max_size() {
                        self.size_update = Some(SizeUpdate::One(val));
                    } else {
                        self.size_update = Some(SizeUpdate::Two(old, val));
                    }
                } else {
                    self.size_update = Some(SizeUpdate::One(val));
                }
            }
            Some(SizeUpdate::Two(min, _)) => {
                if val < min {
                    self.size_update = Some(SizeUpdate::One(val));
                } else {
                    self.size_update = Some(SizeUpdate::Two(min, val));
                }
            }
            None => {
                if val != self.table.max_size() {
                    // Don't bother writing a frame if the value already matches
                    // the table's max size.
                    self.size_update = Some(SizeUpdate::One(val));
                }
            }
        }
    }

    /// Encode a set of headers into the provide buffer
    pub fn encode<I>(&mut self, headers: I, dst: &mut BytesMut)
    where
        I: IntoIterator<Item = Header<Option<HeaderName>>>,
    {
        let _span = tracing::trace_span!("hpack::encode");

        self.encode_size_updates(dst);

        let mut last_index = None;
        // Whether the previous named field was a `cookie` field sent as
        // crumbs, so that its nameless further values are split too.
        let mut crumbling = false;

        for header in headers {
            match header.reify() {
                Ok(Header::Field { name, value })
                    if name == http::header::COOKIE && self.crumbs != CookieCrumbs::Whole =>
                {
                    crumbling = true;
                    last_index = self.encode_crumbs(&value, dst).or(last_index);
                }
                Err(value) if crumbling => {
                    last_index = self.encode_crumbs(&value, dst).or(last_index);
                }
                // The header has an associated name. In which case, try to
                // index it in the table.
                Ok(header) => {
                    crumbling = false;
                    let index = self.table.index(header);
                    self.encode_header(&index, dst);

                    last_index = Some(index);
                }
                // The header does not have an associated name. This means that
                // the name is the same as the previously yielded header. In
                // which case, we skip table lookup and just use the same index
                // as the previous entry.
                Err(value) => {
                    self.encode_header_without_name(
                        last_index.as_ref().unwrap_or_else(|| {
                            panic!("encoding header without name, but no previous index to use for name");
                        }),
                        &value,
                        dst,
                    );
                }
            }
        }
    }

    /// Encodes one `cookie` value as one field per crumb, in order, and
    /// returns the index of the last crumb.
    fn encode_crumbs(&mut self, value: &HeaderValue, dst: &mut BytesMut) -> Option<Index> {
        // A slice of a valid field value is itself a valid value, so every
        // crumb converts. Should one not, the field is sent once, whole.
        let crumbs = self
            .crumbs
            .split(value.as_bytes())
            .into_iter()
            .map(|(crumb, never_indexed)| {
                HeaderValue::from_bytes(crumb).ok().map(|mut crumb| {
                    crumb.set_sensitive(never_indexed);
                    crumb
                })
            })
            .collect::<Option<Vec<_>>>();
        debug_assert!(crumbs.is_some(), "a cookie crumb was not a valid value");
        let crumbs = crumbs.unwrap_or_else(|| vec![value.clone()]);
        let mut last = None;
        for crumb in crumbs {
            let index = self.table.index(Header::Field {
                name: http::header::COOKIE,
                value: crumb,
            });
            self.encode_header(&index, dst);
            last = Some(index);
        }
        last
    }

    fn encode_size_updates(&mut self, dst: &mut BytesMut) {
        match self.size_update.take() {
            Some(SizeUpdate::One(val)) => {
                self.table.resize(val);
                encode_size_update(val, dst);
            }
            Some(SizeUpdate::Two(min, max)) => {
                self.table.resize(min);
                self.table.resize(max);
                encode_size_update(min, dst);
                encode_size_update(max, dst);
            }
            None => {}
        }
    }

    fn encode_header(&mut self, index: &Index, dst: &mut BytesMut) {
        match *index {
            Index::Indexed(idx, _) => {
                encode_int(idx, 7, 0x80, dst);
            }
            Index::Name(idx, _) => {
                let header = self.table.resolve(index);

                encode_not_indexed(
                    idx,
                    header.value_slice(),
                    header.is_sensitive(),
                    self.huffman,
                    dst,
                );
            }
            Index::Inserted(_) => {
                let header = self.table.resolve(index);

                assert!(!header.is_sensitive());

                dst.put_u8(0b0100_0000);

                encode_str(header.name().as_slice(), self.huffman, dst);
                encode_str(header.value_slice(), self.huffman, dst);
            }
            Index::InsertedValue(idx, _) => {
                let header = self.table.resolve(index);

                assert!(!header.is_sensitive());

                encode_int(idx, 6, 0b0100_0000, dst);
                encode_str(header.value_slice(), self.huffman, dst);
            }
            Index::NotIndexed(_) => {
                let header = self.table.resolve(index);

                encode_not_indexed2(
                    header.name().as_slice(),
                    header.value_slice(),
                    header.is_sensitive(),
                    self.huffman,
                    dst,
                );
            }
        }
    }

    fn encode_header_without_name(
        &mut self,
        last: &Index,
        value: &HeaderValue,
        dst: &mut BytesMut,
    ) {
        match *last {
            Index::Indexed(..)
            | Index::Name(..)
            | Index::Inserted(..)
            | Index::InsertedValue(..) => {
                let idx = self.table.resolve_idx(last);

                encode_not_indexed(idx, value.as_ref(), value.is_sensitive(), self.huffman, dst);
            }
            Index::NotIndexed(_) => {
                let last = self.table.resolve(last);

                encode_not_indexed2(
                    last.name().as_slice(),
                    value.as_ref(),
                    value.is_sensitive(),
                    self.huffman,
                    dst,
                );
            }
        }
    }
}

impl Default for Encoder {
    fn default() -> Encoder {
        Encoder::new(4096, 0)
    }
}

fn encode_size_update(val: usize, dst: &mut BytesMut) {
    encode_int(val, 5, 0b0010_0000, dst)
}

fn encode_not_indexed(
    name: usize,
    value: &[u8],
    sensitive: bool,
    huffman: HuffmanCoding,
    dst: &mut BytesMut,
) {
    if sensitive {
        encode_int(name, 4, 0b10000, dst);
    } else {
        encode_int(name, 4, 0, dst);
    }

    encode_str(value, huffman, dst);
}

fn encode_not_indexed2(
    name: &[u8],
    value: &[u8],
    sensitive: bool,
    huffman: HuffmanCoding,
    dst: &mut BytesMut,
) {
    if sensitive {
        dst.put_u8(0b10000);
    } else {
        dst.put_u8(0);
    }

    encode_str(name, huffman, dst);
    encode_str(value, huffman, dst);
}

/// Returns whether `val` is sent Huffman-coded under `huffman`.
fn use_huffman(val: &[u8], huffman: HuffmanCoding) -> bool {
    match huffman {
        HuffmanCoding::Always => true,
        HuffmanCoding::WhenShorter => huffman::encoded_len(val) < val.len(),
        HuffmanCoding::WhenNotLonger => huffman::encoded_len(val) <= val.len(),
    }
}

fn encode_str(val: &[u8], huffman: HuffmanCoding, dst: &mut BytesMut) {
    if !use_huffman(val, huffman) {
        // A raw literal knows its own length, so the head is written first.
        encode_int(val.len(), 7, 0, dst);
        dst.put_slice(val);
        return;
    }

    if !val.is_empty() {
        let idx = position(dst);

        // Push a placeholder byte for the length header
        dst.put_u8(0);

        // Encode with huffman
        huffman::encode(val, dst);

        let huff_len = position(dst) - (idx + 1);

        if encode_int_one_byte(huff_len, 7) {
            // Write the string head
            dst[idx] = 0x80 | huff_len as u8;
        } else {
            // Write the head to a placeholder
            const PLACEHOLDER_LEN: usize = 8;
            let mut buf = [0u8; PLACEHOLDER_LEN];

            let head_len = {
                let mut head_dst = &mut buf[..];
                encode_int(huff_len, 7, 0x80, &mut head_dst);
                PLACEHOLDER_LEN - head_dst.remaining_mut()
            };

            // This is just done to reserve space in the destination
            dst.put_slice(&buf[1..head_len]);

            // Shift the header forward
            for i in 0..huff_len {
                let src_i = idx + 1 + (huff_len - (i + 1));
                let dst_i = idx + head_len + (huff_len - (i + 1));
                dst[dst_i] = dst[src_i];
            }

            // Copy in the head
            for i in 0..head_len {
                dst[idx + i] = buf[i];
            }
        }
    } else {
        // Write an empty string
        dst.put_u8(0);
    }
}

/// Encode an integer into the given destination buffer
fn encode_int<B: BufMut>(
    mut value: usize,   // The integer to encode
    prefix_bits: usize, // The number of bits in the prefix
    first_byte: u8,     // The base upon which to start encoding the int
    dst: &mut B,
) {
    if encode_int_one_byte(value, prefix_bits) {
        dst.put_u8(first_byte | value as u8);
        return;
    }

    let low = (1 << prefix_bits) - 1;

    value -= low;

    dst.put_u8(first_byte | low as u8);

    while value >= 128 {
        dst.put_u8(0b1000_0000 | value as u8);

        value >>= 7;
    }

    dst.put_u8(value as u8);
}

/// Returns true if the in the int can be fully encoded in the first byte.
fn encode_int_one_byte(value: usize, prefix_bits: usize) -> bool {
    value < (1 << prefix_bits) - 1
}

fn position(buf: &BytesMut) -> usize {
    buf.len()
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ext::{Protocol, StaticNameIndex};
    use crate::frame::PseudoId;
    use crate::hpack::{BytesStr, Decoder};
    use http::*;
    use std::io::Cursor;

    #[test]
    fn test_encode_method_get() {
        let mut encoder = Encoder::default();
        let res = encode(&mut encoder, vec![method("GET")]);
        assert_eq!(*res, [0x80 | 2]);
        assert_eq!(encoder.table.len(), 0);
    }

    #[test]
    fn test_encode_method_post() {
        let mut encoder = Encoder::default();
        let res = encode(&mut encoder, vec![method("POST")]);
        assert_eq!(*res, [0x80 | 3]);
        assert_eq!(encoder.table.len(), 0);
    }

    #[test]
    fn test_encode_method_patch() {
        let mut encoder = Encoder::default();
        let res = encode(&mut encoder, vec![method("PATCH")]);

        assert_eq!(res[0], 0b01000000 | 2); // Incremental indexing w/ name pulled from table
        assert_eq!(res[1], 0x80 | 5); // header value w/ huffman coding

        assert_eq!("PATCH", huff_decode(&res[2..7]));
        assert_eq!(encoder.table.len(), 1);

        let res = encode(&mut encoder, vec![method("PATCH")]);

        assert_eq!(1 << 7 | 62, res[0]);
        assert_eq!(1, res.len());
    }

    #[test]
    fn test_encode_indexed_name_literal_value() {
        let mut encoder = Encoder::default();
        let res = encode(&mut encoder, vec![header("content-language", "foo")]);

        assert_eq!(res[0], 0b01000000 | 27); // Indexed name
        assert_eq!(res[1], 0x80 | 2); // header value w/ huffman coding

        assert_eq!("foo", huff_decode(&res[2..4]));

        // Same name, new value should still use incremental
        let res = encode(&mut encoder, vec![header("content-language", "bar")]);
        assert_eq!(res[0], 0b01000000 | 27); // Indexed name
        assert_eq!(res[1], 0x80 | 3); // header value w/ huffman coding
        assert_eq!("bar", huff_decode(&res[2..5]));
    }

    #[test]
    fn test_repeated_headers_are_indexed() {
        let mut encoder = Encoder::default();
        let res = encode(&mut encoder, vec![header("foo", "hello")]);

        assert_eq!(&[0b01000000, 0x80 | 2], &res[0..2]);
        assert_eq!("foo", huff_decode(&res[2..4]));
        assert_eq!(0x80 | 4, res[4]);
        assert_eq!("hello", huff_decode(&res[5..]));
        assert_eq!(9, res.len());

        assert_eq!(1, encoder.table.len());

        let res = encode(&mut encoder, vec![header("foo", "hello")]);
        assert_eq!([0x80 | 62], *res);

        assert_eq!(encoder.table.len(), 1);
    }

    #[test]
    fn test_evicting_headers() {
        let mut encoder = Encoder::default();

        // Fill the table
        for i in 0..64 {
            let key = format!("x-hello-world-{:02}", i);
            let res = encode(&mut encoder, vec![header(&key, &key)]);

            assert_eq!(&[0b01000000, 0x80 | 12], &res[0..2]);
            assert_eq!(key, huff_decode(&res[2..14]));
            assert_eq!(0x80 | 12, res[14]);
            assert_eq!(key, huff_decode(&res[15..]));
            assert_eq!(27, res.len());

            // Make sure the header can be found...
            let res = encode(&mut encoder, vec![header(&key, &key)]);

            // Only check that it is found
            assert_eq!(0x80, res[0] & 0x80);
        }

        assert_eq!(4096, encoder.table.size());
        assert_eq!(64, encoder.table.len());

        // Find existing headers
        for i in 0..64 {
            let key = format!("x-hello-world-{:02}", i);
            let res = encode(&mut encoder, vec![header(&key, &key)]);
            assert_eq!(0x80, res[0] & 0x80);
        }

        // Insert a new header
        let key = "x-hello-world-64";
        let res = encode(&mut encoder, vec![header(key, key)]);

        assert_eq!(&[0b01000000, 0x80 | 12], &res[0..2]);
        assert_eq!(key, huff_decode(&res[2..14]));
        assert_eq!(0x80 | 12, res[14]);
        assert_eq!(key, huff_decode(&res[15..]));
        assert_eq!(27, res.len());

        assert_eq!(64, encoder.table.len());

        // Now try encoding entries that should exist in the table
        for i in 1..65 {
            let key = format!("x-hello-world-{:02}", i);
            let res = encode(&mut encoder, vec![header(&key, &key)]);
            assert_eq!(0x80 | (61 + (65 - i)), res[0]);
        }
    }

    #[test]
    fn test_large_headers_are_not_indexed() {
        let mut encoder = Encoder::new(128, 0);
        let key = "hello-world-hello-world-HELLO-zzz";

        let res = encode(&mut encoder, vec![header(key, key)]);

        assert_eq!(&[0, 0x80 | 25], &res[..2]);

        assert_eq!(0, encoder.table.len());
        assert_eq!(0, encoder.table.size());
    }

    #[test]
    fn test_sensitive_headers_are_never_indexed() {
        use http::header::HeaderValue;

        let name = "my-password".parse().unwrap();
        let mut value = HeaderValue::from_bytes(b"12345").unwrap();
        value.set_sensitive(true);

        let header = Header::Field {
            name: Some(name),
            value,
        };

        // Now, try to encode the sensitive header

        let mut encoder = Encoder::default();
        let res = encode(&mut encoder, vec![header]);

        assert_eq!(&[0b10000, 0x80 | 8], &res[..2]);
        assert_eq!("my-password", huff_decode(&res[2..10]));
        assert_eq!(0x80 | 4, res[10]);
        assert_eq!("12345", huff_decode(&res[11..]));

        // Now, try to encode a sensitive header w/ a name in the static table
        let name = "authorization".parse().unwrap();
        let mut value = HeaderValue::from_bytes(b"12345").unwrap();
        value.set_sensitive(true);

        let header = Header::Field {
            name: Some(name),
            value,
        };

        let mut encoder = Encoder::default();
        let res = encode(&mut encoder, vec![header]);

        assert_eq!(&[0b11111, 8], &res[..2]);
        assert_eq!(0x80 | 4, res[2]);
        assert_eq!("12345", huff_decode(&res[3..]));

        // Using the name component of a previously indexed header (without
        // sensitive flag set)

        let _ = encode(
            &mut encoder,
            vec![self::header("my-password", "not-so-secret")],
        );

        let name = "my-password".parse().unwrap();
        let mut value = HeaderValue::from_bytes(b"12345").unwrap();
        value.set_sensitive(true);

        let header = Header::Field {
            name: Some(name),
            value,
        };
        let res = encode(&mut encoder, vec![header]);

        assert_eq!(&[0b11111, 47], &res[..2]);
        assert_eq!(0x80 | 4, res[2]);
        assert_eq!("12345", huff_decode(&res[3..]));
    }

    #[test]
    fn test_content_length_value_not_indexed() {
        let mut encoder = Encoder::default();
        let res = encode(&mut encoder, vec![header("content-length", "1234")]);

        assert_eq!(&[15, 13, 0x80 | 3], &res[0..3]);
        assert_eq!("1234", huff_decode(&res[3..]));
        assert_eq!(6, res.len());
    }

    #[test]
    fn test_encoding_headers_with_same_name() {
        let mut encoder = Encoder::default();
        let name = "hello";

        // Encode first one
        let _ = encode(&mut encoder, vec![header(name, "one")]);

        // Encode second one
        let res = encode(&mut encoder, vec![header(name, "two")]);
        assert_eq!(&[0x40 | 62, 0x80 | 3], &res[0..2]);
        assert_eq!("two", huff_decode(&res[2..]));
        assert_eq!(5, res.len());

        // Encode the first one again
        let res = encode(&mut encoder, vec![header(name, "one")]);
        assert_eq!(&[0x80 | 63], &res[..]);

        // Now the second one
        let res = encode(&mut encoder, vec![header(name, "two")]);
        assert_eq!(&[0x80 | 62], &res[..]);
    }

    #[test]
    fn test_evicting_headers_when_multiple_of_same_name_are_in_table() {
        // The encoder only has space for 2 headers
        let mut encoder = Encoder::new(76, 0);

        let _ = encode(&mut encoder, vec![header("foo", "bar")]);
        assert_eq!(1, encoder.table.len());

        let _ = encode(&mut encoder, vec![header("bar", "foo")]);
        assert_eq!(2, encoder.table.len());

        // This will evict the first header, while still referencing the header
        // name
        let res = encode(&mut encoder, vec![header("foo", "baz")]);
        assert_eq!(&[0x40 | 63, 0, 0x80 | 3], &res[..3]);
        assert_eq!(2, encoder.table.len());

        // Try adding the same header again
        let res = encode(&mut encoder, vec![header("foo", "baz")]);
        assert_eq!(&[0x80 | 62], &res[..]);
        assert_eq!(2, encoder.table.len());
    }

    #[test]
    fn test_max_size_zero() {
        // Static table only
        let mut encoder = Encoder::new(0, 0);
        let res = encode(&mut encoder, vec![method("GET")]);
        assert_eq!(*res, [0x80 | 2]);
        assert_eq!(encoder.table.len(), 0);

        let res = encode(&mut encoder, vec![header("foo", "bar")]);
        assert_eq!(&[0, 0x80 | 2], &res[..2]);
        assert_eq!("foo", huff_decode(&res[2..4]));
        assert_eq!(0x80 | 3, res[4]);
        assert_eq!("bar", huff_decode(&res[5..8]));
        assert_eq!(0, encoder.table.len());

        // Encode a custom value
        let res = encode(&mut encoder, vec![header("transfer-encoding", "chunked")]);
        assert_eq!(&[15, 42, 0x80 | 6], &res[..3]);
        assert_eq!("chunked", huff_decode(&res[3..]));
    }

    #[test]
    fn test_update_max_size_combos() {
        let mut encoder = Encoder::default();
        assert!(encoder.size_update.is_none());
        assert_eq!(4096, encoder.table.max_size());

        encoder.update_max_size(4096); // Default size
        assert!(encoder.size_update.is_none());

        encoder.update_max_size(0);
        assert_eq!(Some(SizeUpdate::One(0)), encoder.size_update);

        encoder.update_max_size(100);
        assert_eq!(Some(SizeUpdate::Two(0, 100)), encoder.size_update);

        let mut encoder = Encoder::default();
        encoder.update_max_size(8000);
        assert_eq!(Some(SizeUpdate::One(8000)), encoder.size_update);

        encoder.update_max_size(100);
        assert_eq!(Some(SizeUpdate::One(100)), encoder.size_update);

        encoder.update_max_size(8000);
        assert_eq!(Some(SizeUpdate::Two(100, 8000)), encoder.size_update);

        encoder.update_max_size(4000);
        assert_eq!(Some(SizeUpdate::Two(100, 4000)), encoder.size_update);

        encoder.update_max_size(50);
        assert_eq!(Some(SizeUpdate::One(50)), encoder.size_update);
    }

    #[test]
    fn test_resizing_table() {
        let mut encoder = Encoder::default();

        // Add a header
        let _ = encode(&mut encoder, vec![header("foo", "bar")]);

        encoder.update_max_size(1);
        assert_eq!(1, encoder.table.len());

        let res = encode(&mut encoder, vec![method("GET")]);
        assert_eq!(&[32 | 1, 0x80 | 2], &res[..]);
        assert_eq!(0, encoder.table.len());

        let res = encode(&mut encoder, vec![header("foo", "bar")]);
        assert_eq!(0, res[0]);

        encoder.update_max_size(100);
        let res = encode(&mut encoder, vec![header("foo", "bar")]);
        assert_eq!(&[32 | 31, 69, 64], &res[..3]);

        encoder.update_max_size(0);
        let res = encode(&mut encoder, vec![header("foo", "bar")]);
        assert_eq!(&[32, 0], &res[..2]);
    }

    #[test]
    fn test_decreasing_table_size_without_eviction() {
        let mut encoder = Encoder::default();

        // Add a header
        let _ = encode(&mut encoder, vec![header("foo", "bar")]);

        encoder.update_max_size(100);
        assert_eq!(1, encoder.table.len());

        let res = encode(&mut encoder, vec![header("foo", "bar")]);
        assert_eq!(&[32 | 31, 69, 0x80 | 62], &res[..]);
    }

    #[test]
    fn test_nameless_header() {
        let mut encoder = Encoder::default();

        let res = encode(
            &mut encoder,
            vec![
                Header::Field {
                    name: Some("hello".parse().unwrap()),
                    value: HeaderValue::from_bytes(b"world").unwrap(),
                },
                Header::Field {
                    name: None,
                    value: HeaderValue::from_bytes(b"zomg").unwrap(),
                },
            ],
        );

        assert_eq!(&[0x40, 0x80 | 4], &res[0..2]);
        assert_eq!("hello", huff_decode(&res[2..6]));
        assert_eq!(0x80 | 4, res[6]);
        assert_eq!("world", huff_decode(&res[7..11]));

        // Next is not indexed
        assert_eq!(&[15, 47, 0x80 | 3], &res[11..14]);
        assert_eq!("zomg", huff_decode(&res[14..]));
    }

    #[test]
    fn test_large_size_update() {
        let mut encoder = Encoder::default();

        encoder.update_max_size(1912930560);
        assert_eq!(Some(SizeUpdate::One(1912930560)), encoder.size_update);

        let mut dst = BytesMut::with_capacity(6);
        encoder.encode_size_updates(&mut dst);
        assert_eq!([63, 225, 129, 148, 144, 7], &dst[..]);
    }

    #[test]
    #[ignore]
    fn test_evicted_overflow() {
        // Not sure what the best way to do this is.
    }

    /// Setting the default profile changes no byte of any block.
    ///
    /// The seam's identity element is what keeps every existing caller, which
    /// never sets a profile, encoding exactly as it did before.
    #[test]
    fn the_default_profile_encodes_like_the_upstream_encoder() {
        let fields = || {
            vec![
                method("GET"),
                method("CONNECT"),
                path("/echo"),
                path("/"),
                scheme("https"),
                protocol("websocket"),
                header("accept-language", "13"),
                header("accept-language", "en-US,en;q=0.9"),
                header("x-new", "value"),
                header("content-length", "1234"),
            ]
        };
        let mut upstream = Encoder::default();
        let mut profiled = Encoder::default();
        profiled.set_profile(HpackEncoderProfile::new());

        // Three blocks, so the evolving dynamic table is compared too.
        for block in 0..3 {
            assert_eq!(
                encode(&mut upstream, fields()),
                encode(&mut profiled, fields()),
                "block {block} differed under the default profile"
            );
        }
        assert_eq!(upstream.table.len(), profiled.table.len());
    }

    /// Chromium keeps `:method` and `:protocol` out of its dynamic table.
    #[test]
    fn literal_pseudo_headers_are_never_value_indexed() {
        let mut encoder = Encoder::default();
        encoder.set_profile(
            HpackEncoderProfile::new()
                .literal_pseudo_headers([PseudoId::Method, PseudoId::Protocol]),
        );

        // Literal without indexing, naming static entry 2 (`:method GET`).
        let res = encode(&mut encoder, vec![method("CONNECT")]);
        assert_eq!(res[0], 2);
        assert_eq!(res[1], 0x80 | 7);
        assert_eq!("CONNECT", huff_decode(&res[2..]));
        assert_eq!(0, encoder.table.len());

        // Literal without indexing with a literal name.
        let res = encode(&mut encoder, vec![protocol("websocket")]);
        assert_eq!(res[0], 0);
        assert_eq!(0, encoder.table.len());

        // A repeat is encoded identically, because nothing was inserted.
        let repeat = encode(&mut encoder, vec![method("CONNECT")]);
        assert_eq!(repeat[0], 2);
        assert_eq!("CONNECT", huff_decode(&repeat[2..]));
    }

    /// A listed pseudo-header whose value also matches stays fully indexed.
    #[test]
    fn literal_pseudo_headers_keep_full_static_matches_indexed() {
        let mut encoder = Encoder::default();
        encoder.set_profile(
            HpackEncoderProfile::new().literal_pseudo_headers([PseudoId::Method, PseudoId::Scheme]),
        );

        assert_eq!(*encode(&mut encoder, vec![method("GET")]), [0x80 | 2]);
        assert_eq!(*encode(&mut encoder, vec![method("POST")]), [0x80 | 3]);
        assert_eq!(*encode(&mut encoder, vec![scheme("https")]), [0x80 | 7]);
        assert_eq!(0, encoder.table.len());
    }

    /// Firefox names a repeated static entry with its highest index.
    #[test]
    fn highest_static_name_index_names_repeated_entries() {
        let mut encoder = Encoder::default();
        encoder.set_profile(HpackEncoderProfile::new().static_name_index(StaticNameIndex::Highest));

        // Incremental indexing against `:method POST`, not `:method GET`.
        let res = encode(&mut encoder, vec![method("CONNECT")]);
        assert_eq!(res[0], 0b0100_0000 | 3);

        // `:path` is never value-indexed, so it names entry 5, not 4.
        let res = encode(&mut encoder, vec![path("/echo")]);
        assert_eq!(res[0], 5);

        // A value that matches a static entry is still sent as that index.
        assert_eq!(*encode(&mut encoder, vec![method("GET")]), [0x80 | 2]);
        assert_eq!(*encode(&mut encoder, vec![path("/")]), [0x80 | 4]);
    }

    /// The default keeps the lowest index, so existing blocks are unchanged.
    #[test]
    fn lowest_static_name_index_is_the_default() {
        let mut encoder = Encoder::default();
        assert_eq!(
            encode(&mut encoder, vec![method("CONNECT")])[0],
            0b0100_0000 | 2
        );
        let mut encoder = Encoder::default();
        assert_eq!(encode(&mut encoder, vec![path("/echo")])[0], 4);
    }

    /// Chromium sends a literal whose Huffman form is no shorter uncoded.
    ///
    /// A zero-size table keeps every field literal, so the two bytes before
    /// the value are the representation and the `accept-language` name index.
    #[test]
    fn huffman_when_shorter_sends_a_tie_uncoded() {
        let mut encoder = Encoder::new(0, 0);
        encoder.set_profile(HpackEncoderProfile::new().huffman_coding(HuffmanCoding::WhenShorter));

        // Huffman codes "13" in exactly two bytes, so it is sent raw.
        let res = encode(&mut encoder, vec![header("accept-language", "13")]);
        assert_eq!(&res[..3], &[0x0f, 0x02, 2]);
        assert_eq!(&res[3..], b"13".as_slice());

        // A value the coding does shorten is still coded.
        let res = encode(
            &mut encoder,
            vec![header("accept-language", "en-US,en;q=0.9")],
        );
        assert_eq!(&res[..2], &[0x0f, 0x02]);
        assert_ne!(res[2] & 0x80, 0, "a shortened value was not coded");
        assert_eq!("en-US,en;q=0.9", huff_decode(&res[3..]));
    }

    /// Firefox codes a literal whose Huffman form ties with the raw one.
    #[test]
    fn huffman_when_not_longer_codes_a_tie() {
        let mut encoder = Encoder::new(0, 0);
        encoder
            .set_profile(HpackEncoderProfile::new().huffman_coding(HuffmanCoding::WhenNotLonger));

        let res = encode(&mut encoder, vec![header("accept-language", "13")]);
        assert_eq!(&res[..3], &[0x0f, 0x02, 0x80 | 2]);
        assert_eq!("13", huff_decode(&res[3..]));
    }

    /// Both length rules agree with the default when coding does shorten.
    #[test]
    fn huffman_rules_agree_when_coding_shortens() {
        let mut always = Encoder::default();
        let mut shorter = Encoder::default();
        shorter.set_profile(HpackEncoderProfile::new().huffman_coding(HuffmanCoding::WhenShorter));
        let mut not_longer = Encoder::default();
        not_longer
            .set_profile(HpackEncoderProfile::new().huffman_coding(HuffmanCoding::WhenNotLonger));

        let field = || vec![header("accept-language", "en-US,en;q=0.9")];
        let expected = encode(&mut always, field());
        assert_eq!(expected, encode(&mut shorter, field()));
        assert_eq!(expected, encode(&mut not_longer, field()));
    }

    /// An empty value is one byte whatever the length rule says.
    #[test]
    fn huffman_rules_agree_on_an_empty_value() {
        for coding in [
            HuffmanCoding::Always,
            HuffmanCoding::WhenShorter,
            HuffmanCoding::WhenNotLonger,
        ] {
            let mut encoder = Encoder::new(0, 0);
            encoder.set_profile(HpackEncoderProfile::new().huffman_coding(coding));
            let res = encode(&mut encoder, vec![header("x-empty", "")]);
            assert_eq!(res[res.len() - 1], 0, "{coding:?} changed the empty value");
        }
    }

    /// Chromium sends one incrementally indexed field per cookie, then
    /// indexes each crumb on the next block.
    #[test]
    fn index_all_crumbs_insert_each_cookie_then_index_it() {
        let mut encoder = Encoder::default();
        encoder.set_profile(HpackEncoderProfile::new().cookie_crumbs(CookieCrumbs::IndexAll));
        let mut decoder = Decoder::new(4096);

        let first = encode(&mut encoder, vec![header("cookie", "a=1; b=22")]);
        assert_eq!(representations(&first), [0x40 | 32, 0x40 | 32]);
        assert_eq!(
            decode(&mut decoder, first),
            pairs(&[("cookie", "a=1"), ("cookie", "b=22")])
        );
        assert_eq!(encoder.table.len(), 2);

        let repeat = encode(&mut encoder, vec![header("cookie", "a=1; b=22")]);
        assert_eq!(*repeat, [0x80 | 63, 0x80 | 62]);
    }

    /// Chromium trims the value and splits at a `;` with no space after it.
    #[test]
    fn index_all_crumbs_follow_chromium_splitting() {
        let mut encoder = Encoder::default();
        encoder.set_profile(HpackEncoderProfile::new().cookie_crumbs(CookieCrumbs::IndexAll));
        let block = encode(&mut encoder, vec![header("cookie", " a=1;b=2;  c=3	")]);
        assert_eq!(
            decode(&mut Decoder::new(4096), block),
            pairs(&[("cookie", "a=1"), ("cookie", "b=2"), ("cookie", " c=3")])
        );
    }

    /// The profile, not the field's sensitivity, decides a crumb's form.
    #[test]
    fn index_all_crumbs_index_a_sensitive_cookie() {
        let mut encoder = Encoder::default();
        encoder.set_profile(HpackEncoderProfile::new().cookie_crumbs(CookieCrumbs::IndexAll));
        let mut value = HeaderValue::from_static("a=1");
        value.set_sensitive(true);
        let field = Header::Field {
            name: Some(http::header::COOKIE),
            value,
        };
        let block = encode(&mut encoder, vec![field]);
        assert_eq!(representations(&block), [0x40 | 32]);
    }

    /// A further nameless value of the same `cookie` field is split too.
    #[test]
    fn crumbs_split_every_value_of_a_cookie_field() {
        let mut encoder = Encoder::default();
        encoder.set_profile(HpackEncoderProfile::new().cookie_crumbs(CookieCrumbs::IndexAll));
        let second = Header::Field {
            name: None,
            value: HeaderValue::from_static("c=3; d=4"),
        };
        let block = encode(&mut encoder, vec![header("cookie", "a=1; b=2"), second]);
        assert_eq!(representations(&block), [0x40 | 32; 4]);
        assert_eq!(decode(&mut Decoder::new(4096), block).len(), 4);
    }

    /// Firefox never indexes a crumb shorter than 20 bytes and indexes a
    /// longer one.
    #[test]
    fn never_index_short_crumbs_split_on_length() {
        let mut encoder = Encoder::default();
        encoder
            .set_profile(HpackEncoderProfile::new().cookie_crumbs(CookieCrumbs::NeverIndexShort));
        let short = "pc=0123456789abcdef";
        let long = "pd=0123456789abcdefg";
        assert_eq!((short.len(), long.len()), (19, 20));

        let first = encode(
            &mut encoder,
            vec![header("cookie", &format!("{short}; {long}"))],
        );
        // Never-indexed naming static 32 (0x1f then 17), then incremental.
        assert_eq!(&first[..2], &[0x1f, 17]);
        assert_eq!(representations(&first), [0x10, 0x40 | 32]);
        assert_eq!(
            decode(&mut Decoder::new(4096), first),
            pairs(&[("cookie", short), ("cookie", long)])
        );
        assert_eq!(encoder.table.len(), 1);

        let repeat = encode(&mut encoder, vec![header("cookie", long)]);
        assert_eq!(*repeat, [0x80 | 62]);
    }

    /// Firefox splits only at `"; "`.
    #[test]
    fn never_index_short_crumbs_split_only_at_semicolon_space() {
        let mut encoder = Encoder::default();
        encoder
            .set_profile(HpackEncoderProfile::new().cookie_crumbs(CookieCrumbs::NeverIndexShort));
        let block = encode(&mut encoder, vec![header("cookie", "a=1;b=2; c=3")]);
        assert_eq!(
            decode(&mut Decoder::new(4096), block),
            pairs(&[("cookie", "a=1;b=2"), ("cookie", "c=3")])
        );
    }

    /// Without crumbs, `cookie` stays one literal outside the table.
    #[test]
    fn whole_cookies_are_one_literal_without_indexing() {
        let mut encoder = Encoder::default();
        let block = encode(&mut encoder, vec![header("cookie", "a=1; b=2")]);
        assert_eq!(representations(&block), [0x00]);
        assert_eq!(encoder.table.len(), 0);
    }

    /// Returns each representation's leading pattern: the indexed bit, the
    /// incremental pattern with its 6-bit name index, or the 4-bit literal
    /// pattern without its name index.
    fn representations(block: &[u8]) -> Vec<u8> {
        fn int(block: &[u8], offset: &mut usize, prefix: u8) -> usize {
            let limit = (1usize << prefix) - 1;
            let mut value = usize::from(block[*offset]) & limit;
            *offset += 1;
            if value == limit {
                let mut shift = 0;
                loop {
                    let byte = block[*offset];
                    *offset += 1;
                    value += usize::from(byte & 0x7f) << shift;
                    shift += 7;
                    if byte & 0x80 == 0 {
                        break;
                    }
                }
            }
            value
        }
        fn string(block: &[u8], offset: &mut usize) {
            let length = int(block, offset, 7);
            *offset += length;
        }
        let mut kinds = Vec::new();
        let mut offset = 0;
        while offset < block.len() {
            let byte = block[offset];
            let (kind, prefix) = if byte & 0x80 != 0 {
                (byte, 7)
            } else if byte & 0x40 != 0 {
                (byte, 6)
            } else {
                (byte & 0xf0, 4)
            };
            kinds.push(kind);
            let name = int(block, &mut offset, prefix);
            if prefix != 7 {
                if name == 0 {
                    string(block, &mut offset);
                }
                string(block, &mut offset);
            }
        }
        kinds
    }

    fn pairs(items: &[(&str, &str)]) -> Vec<(String, String)> {
        items
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn decode(decoder: &mut Decoder, mut block: BytesMut) -> Vec<(String, String)> {
        let mut fields = Vec::new();
        decoder
            .decode(&mut Cursor::new(&mut block), |header| {
                if let Header::Field { name, value } = header {
                    fields.push((name.as_str().to_owned(), value.to_str().unwrap().to_owned()));
                }
                std::ops::ControlFlow::Continue(())
            })
            .unwrap();
        fields
    }

    fn protocol(s: &str) -> Header<Option<HeaderName>> {
        Header::Protocol(Protocol::from(s))
    }

    fn scheme(s: &str) -> Header<Option<HeaderName>> {
        Header::Scheme(BytesStr::from(s))
    }

    fn path(s: &str) -> Header<Option<HeaderName>> {
        Header::Path(BytesStr::from(s))
    }

    fn encode(e: &mut Encoder, hdrs: Vec<Header<Option<HeaderName>>>) -> BytesMut {
        let mut dst = BytesMut::with_capacity(1024);
        e.encode(hdrs, &mut dst);
        dst
    }

    fn method(s: &str) -> Header<Option<HeaderName>> {
        Header::Method(Method::from_bytes(s.as_bytes()).unwrap())
    }

    fn header(name: &str, val: &str) -> Header<Option<HeaderName>> {
        let name = HeaderName::from_bytes(name.as_bytes()).unwrap();
        let value = HeaderValue::from_bytes(val.as_bytes()).unwrap();

        Header::Field {
            name: Some(name),
            value,
        }
    }

    fn huff_decode(src: &[u8]) -> BytesMut {
        let mut buf = BytesMut::new();
        huffman::decode(src, &mut buf).unwrap()
    }
}
