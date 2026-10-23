//! Concrete TLS certificate-compression codecs.

use std::io::{self, Write};

use btls::ssl::{CertificateCompressionAlgorithm, CertificateCompressor};
use flate2::{Compression, read::ZlibDecoder, write::ZlibEncoder};
use zstd::stream::{Decoder as ZstdDecoder, Encoder as ZstdEncoder};

#[derive(Clone, Copy, Debug)]
pub(super) struct ZlibCertificateCompression;

impl CertificateCompressor for ZlibCertificateCompression {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::ZLIB;
    const CAN_COMPRESS: bool = true;
    const CAN_DECOMPRESS: bool = true;

    fn compress<W>(&self, input: &[u8], output: &mut W) -> io::Result<()>
    where
        W: Write,
    {
        let mut encoder = ZlibEncoder::new(output, Compression::default());
        encoder.write_all(input)?;
        encoder.finish()?;
        Ok(())
    }

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> io::Result<()>
    where
        W: Write,
    {
        io::copy(&mut ZlibDecoder::new(input), output)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct BrotliCertificateCompression;

impl CertificateCompressor for BrotliCertificateCompression {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = true;
    const CAN_DECOMPRESS: bool = true;

    fn compress<W>(&self, input: &[u8], output: &mut W) -> io::Result<()>
    where
        W: Write,
    {
        let parameters = brotli::enc::BrotliEncoderParams {
            quality: 11,
            lgwin: 22,
            ..Default::default()
        };
        brotli::BrotliCompress(&mut io::Cursor::new(input), output, &parameters)?;
        Ok(())
    }

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> io::Result<()>
    where
        W: Write,
    {
        brotli::BrotliDecompress(&mut io::Cursor::new(input), output)
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ZstdCertificateCompression;

impl CertificateCompressor for ZstdCertificateCompression {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::ZSTD;
    const CAN_COMPRESS: bool = true;
    const CAN_DECOMPRESS: bool = true;

    fn compress<W>(&self, input: &[u8], output: &mut W) -> io::Result<()>
    where
        W: Write,
    {
        let mut encoder = ZstdEncoder::new(output, 0)?;
        encoder.write_all(input)?;
        encoder.finish()?;
        Ok(())
    }

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> io::Result<()>
    where
        W: Write,
    {
        let mut decoder = ZstdDecoder::new(input)?;
        io::copy(&mut decoder, output)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CERTIFICATE_MESSAGE: &[u8] =
        b"certificate chain bytes with repeated repeated repeated fields";
    const ZSTD_FRAME: &[u8] = include_bytes!("compression/fixtures/example.txt.v8.zst");
    const ZSTD_TEXT: &[u8] = include_bytes!("compression/fixtures/example.txt");

    #[test]
    fn all_certificate_compressors_round_trip() -> io::Result<()> {
        assert_round_trip(ZlibCertificateCompression)?;
        assert_round_trip(BrotliCertificateCompression)?;
        assert_round_trip(ZstdCertificateCompression)
    }

    #[test]
    fn brotli_finalization_propagates_output_errors() {
        let error = BrotliCertificateCompression.compress(&[], &mut RejectWrites);
        assert_eq!(
            error.err().map(|error| error.kind()),
            Some(io::ErrorKind::Other)
        );
    }

    #[test]
    fn zstd_decodes_an_independent_standard_frame() -> io::Result<()> {
        let mut output = Vec::new();
        ZstdCertificateCompression.decompress(ZSTD_FRAME, &mut output)?;
        assert_eq!(output, ZSTD_TEXT);
        Ok(())
    }

    #[test]
    fn zstd_rejects_truncated_standard_frames() {
        for length in [0, 3, ZSTD_FRAME.len() - 1] {
            let result =
                ZstdCertificateCompression.decompress(&ZSTD_FRAME[..length], &mut Vec::new());
            assert!(result.is_err(), "accepted a {length}-byte truncated frame");
        }
    }

    #[test]
    fn zstd_preserves_bounded_output_failures() {
        let mut output = [0; 16];
        let result = ZstdCertificateCompression.decompress(ZSTD_FRAME, &mut output.as_mut_slice());
        assert_eq!(
            result.err().map(|error| error.kind()),
            Some(io::ErrorKind::WriteZero)
        );
        assert_eq!(output.as_slice(), &ZSTD_TEXT[..output.len()]);
    }

    struct RejectWrites;

    impl Write for RejectWrites {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("rejected compressed output"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn assert_round_trip<C>(compressor: C) -> io::Result<()>
    where
        C: CertificateCompressor,
    {
        let mut compressed = Vec::new();
        compressor.compress(CERTIFICATE_MESSAGE, &mut compressed)?;
        let mut decompressed = Vec::new();
        compressor.decompress(&compressed, &mut decompressed)?;
        assert_eq!(decompressed, CERTIFICATE_MESSAGE);
        Ok(())
    }
}
