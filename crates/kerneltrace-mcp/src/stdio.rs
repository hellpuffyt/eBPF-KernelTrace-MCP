//! Newline-delimited JSON-RPC over stdin/stdout, with bounded line length and
//! graceful shutdown on EOF or SIGINT/SIGTERM.

use std::io::{self, BufRead, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::Value;

use crate::protocol::{self, INVALID_REQUEST};
use crate::server::Server;

/// Longest accepted message in bytes. Longer lines are discarded with an error.
pub const MAX_LINE: usize = 1 << 20;

enum Input {
    Line(String),
    TooLong,
    Eof,
    Error(io::Error),
}

/// Reads one line of at most `max` bytes. Over-long lines are consumed to the
/// next newline and reported as `TooLong` without buffering them.
fn read_bounded(r: &mut impl BufRead, max: usize) -> Input {
    let mut buf = Vec::new();
    match io::Read::take(&mut *r, max as u64 + 1).read_until(b'\n', &mut buf) {
        Err(e) => return Input::Error(e),
        Ok(0) => return Input::Eof,
        Ok(_) => {}
    }
    if buf.last() != Some(&b'\n') && buf.len() > max {
        // Discard the rest of the line.
        loop {
            let (done, used) = match r.fill_buf() {
                Ok([]) => (true, 0),
                Ok(chunk) => match chunk.iter().position(|b| *b == b'\n') {
                    Some(i) => (true, i + 1),
                    None => (false, chunk.len()),
                },
                Err(e) => return Input::Error(e),
            };
            r.consume(used);
            if done {
                return Input::TooLong;
            }
        }
    }
    match String::from_utf8(buf) {
        Ok(s) => Input::Line(s),
        Err(_) => Input::Line(String::from("\u{FFFD}")), // becomes a parse error
    }
}

fn write_message(out: &mut impl Write, v: &Value) -> io::Result<()> {
    serde_json::to_writer(&mut *out, v)?;
    out.write_all(b"\n")?;
    out.flush()
}

/// Serves until EOF or a termination signal. Returns the shutdown reason.
pub fn serve(server: &mut Server<'_>) -> Result<&'static str> {
    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = Arc::clone(&stop);
        ctrlc::set_handler(move || stop.store(true, Ordering::Release))
            .context("installing signal handler")?;
    }
    // Reading stdin blocks, so it runs on its own thread; the main loop can
    // then notice a signal within 100 ms. The reader thread is detached: if we
    // exit on a signal it is blocked in read() and dies with the process.
    let (tx, rx) = mpsc::sync_channel::<Input>(16);
    thread::Builder::new().name("stdin".into()).spawn(move || {
        let stdin = io::stdin();
        let mut lock = stdin.lock();
        loop {
            let input = read_bounded(&mut lock, MAX_LINE);
            let end = matches!(input, Input::Eof | Input::Error(_));
            if tx.send(input).is_err() || end {
                return;
            }
        }
    })?;
    let stdout = io::stdout();
    let mut out = stdout.lock();
    loop {
        if stop.load(Ordering::Acquire) {
            return Ok("signal");
        }
        let input = match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(i) => i,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => return Ok("stdin closed"),
        };
        let response = match input {
            Input::Eof => return Ok("stdin closed"),
            Input::Error(e) => return Err(e).context("reading stdin"),
            Input::TooLong => Some(protocol::error(
                &Value::Null,
                INVALID_REQUEST,
                format!("message exceeds {MAX_LINE} bytes"),
            )),
            Input::Line(l) if l.trim().is_empty() => None,
            Input::Line(l) => server.handle_line(l.trim_end()),
        };
        if let Some(r) = response
            && let Err(e) = write_message(&mut out, &r)
        {
            // The client went away (EPIPE): that is a normal shutdown.
            if e.kind() == io::ErrorKind::BrokenPipe {
                return Ok("stdout closed");
            }
            return Err(e).context("writing stdout");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn bounded_reader() {
        let mut r = Cursor::new(b"short\nxxxxxxxxxxxxxxxxxxxx\nnext\n".to_vec());
        assert!(matches!(read_bounded(&mut r, 8), Input::Line(l) if l == "short\n"));
        assert!(matches!(read_bounded(&mut r, 8), Input::TooLong));
        assert!(matches!(read_bounded(&mut r, 8), Input::Line(l) if l == "next\n"));
        assert!(matches!(read_bounded(&mut r, 8), Input::Eof));
    }

    #[test]
    fn exact_length_line_is_accepted() {
        let mut r = Cursor::new(b"12345678".to_vec());
        assert!(matches!(read_bounded(&mut r, 8), Input::Line(l) if l == "12345678"));
    }
}
