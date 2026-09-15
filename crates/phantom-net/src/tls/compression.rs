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
        let mut parameters = brotli::enc::BrotliEncoderParams::default();
        parameters.quality = 11;
        parameters.lgwin = 22;
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
