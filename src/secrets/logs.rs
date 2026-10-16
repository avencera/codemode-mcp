//! A log writer that scrubs known secrets from each event

use std::{io, sync::Arc};

use tracing_subscriber::fmt::MakeWriter;

use super::Redactor;

/// Wraps `inner` so everything written to it passes the process's shared
/// [`Redactor`]
///
/// HTTP client libraries print the URL they were connecting to in their own
/// log events, which a URL that is a secret must not appear in. The fmt
/// layer writes one event per call, so a secret is never split across calls
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
        }
    }
}

/// One event's writer
pub struct RedactingWriter<W> {
    inner: W,
    redactor: Arc<Redactor>,
}

impl<W: io::Write> io::Write for RedactingWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let scrubbed = self.redactor.scrub(&String::from_utf8_lossy(buffer));
        self.inner.write_all(scrubbed.as_bytes())?;

        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
