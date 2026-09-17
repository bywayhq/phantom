use std::io::{self, Cursor};

pub(super) struct Incoming(pub(super) Cursor<Vec<u8>>);

impl io::Read for Incoming {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        io::Read::read(&mut self.0, buf)
    }
}

impl io::Write for Incoming {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
