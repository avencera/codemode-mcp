//! A log writer that scrubs known secrets from each event

use std::{io, sync::Arc};

use tracing_subscriber::fmt::MakeWriter;

use super::Redactor;

/// Wraps `inner` so everything written to it passes the process's shared
/// [`Redactor`]
///
/// HTTP client libraries print the URL they were connecting to in their own
/// log events, which a URL that is a secret must not appear in. Each writer
/// buffers what it is given and scrubs it on `flush` and drop
pub fn redacting_logs<M>(inner: M) -> RedactingMakeWriter<M> {
    RedactingMakeWriter {
        inner,
        redactor: Arc::clone(Redactor::log()),
    }
}

/// See [`redacting_logs`]
pub struct RedactingMakeWriter<M> {
    inner: M,
    redactor: Arc<Redactor>,
}

impl<'a, M: MakeWriter<'a>> MakeWriter<'a> for RedactingMakeWriter<M> {
    type Writer = RedactingWriter<M::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        RedactingWriter {
            inner: self.inner.make_writer(),
            redactor: Arc::clone(&self.redactor),
            buffer: Vec::new(),
        }
    }
}

/// One event's writer
///
/// Bytes are held until `flush` or drop and scrubbed together, so a secret
/// written in fragments is still replaced
pub struct RedactingWriter<W: io::Write> {
    inner: W,
    redactor: Arc<Redactor>,
    buffer: Vec<u8>,
}

impl<W: io::Write> io::Write for RedactingWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.buffer.extend_from_slice(buffer);

        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.buffer.is_empty() {
            let scrubbed = self.redactor.scrub(&String::from_utf8_lossy(&self.buffer));
            self.buffer.clear();
            self.inner.write_all(scrubbed.as_bytes())?;
        }

        self.inner.flush()
    }
}

impl<W: io::Write> Drop for RedactingWriter<W> {
    fn drop(&mut self) {
        // nowhere to report a failed log write
        let _ = io::Write::flush(self);
    }
}
