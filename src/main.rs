use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, IsTerminal, Read, Write},
    os::fd::AsRawFd,
    sync::atomic::AtomicBool,
};

use anyhow::{anyhow, bail, ensure, Result};
use base64::Engine;
use clap::{Parser, ValueEnum};

static BASE64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::general_purpose::GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    );

const OSC52: &str = "\x1b]52;";
const ST: &str = "\x1b\\";

#[derive(Parser)]
struct Args {
    /// Specifies a clipboard to use, passed as the Pc parameter to the terminal.
    #[arg(short, long, default_value_t, hide_default_value = true)]
    clipboard: String,

    /// The terminal to query
    #[arg(short, long, env = "TTY", default_value = "/dev/tty")]
    tty: String,

    /// Force operation even if <TTY> is not a terminal
    #[arg(short, long)]
    force: bool,

    /// How long (in milliseconds) to wait for a reply from the terminal before giving up, or 0
    /// for no timeout
    #[arg(long, default_value_t = 100)]
    timeout: u64,

    #[arg(id = "copy|paste")]
    command: Command,

    /// Copy from/paste into the specified file, instead of stdin/stdout
    file: Option<String>,
}

#[derive(ValueEnum, Clone)]
enum Command {
    /// Copy text to the system clipboard
    Copy,

    /// Paste text from the system clipboard
    Paste,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open(args.tty.clone())?;
    if !args.force && !tty.is_terminal() {
        bail!("{} is not a terminal", args.tty);
    }

    match args.command {
        Command::Copy => copy(args, tty),
        Command::Paste => paste(args, tty),
    }
}

fn copy(args: Args, tty: File) -> Result<()> {
    let input: Box<dyn Read> = if let Some(path) = args.file {
        Box::new(File::open(path)?)
    } else {
        Box::new(std::io::stdin())
    };
    let mut input = BufReader::new(input);
    let mut output = BufWriter::new(tty);

    // Start the escape sequence
    write!(output, "{OSC52}{};", args.clipboard)?;

    // Read some data, convert to base64, write to terminal, repeat
    let mut output_buf = String::new();
    while let input_buf @ [_, ..] = input.fill_buf()? {
        BASE64.encode_string(input_buf, &mut output_buf);
        output.write_all(output_buf.as_bytes())?;

        let len = input_buf.len();
        input.consume(len);
        output_buf.clear();
    }

    // End the escape sequence
    write!(output, "{ST}")?;
    output.flush()?;
    Ok(())
}

fn paste(args: Args, mut tty: File) -> Result<()> {
    let output: Box<dyn Write> = if let Some(path) = args.file {
        Box::new(std::fs::File::open(path)?)
    } else {
        Box::new(std::io::stdout())
    };
    let mut output = std::io::BufWriter::new(output);

    // Put the terminal in raw mode
    let raw = RawMode::enable_raw_mode(&tty);
    // If the force flag is set, ignore any error
    let raw = if args.force { raw.ok() } else { Some(raw?) };

    // Request a paste from the terminal
    write!(tty, "{OSC52}{};?{ST}", args.clipboard)?;
    tty.flush()?;

    let mut tty = BufReader::new(tty);
    let completed: &AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));

    // Spawn a thread to terminate the process if the timeout expires before we get input
    let _raw = raw.clone();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(args.timeout));
        if completed.load(std::sync::atomic::Ordering::SeqCst) {
            std::mem::forget(_raw);
        } else {
            std::mem::drop(_raw);
            eprintln!("error: Timeout exceeded");
            std::process::exit(1);
        }
    });

    // Wait for a reply from the terminal
    let target = OSC52.as_bytes();
    let mut i = 0;
    loop {
        let c = tty
            .by_ref()
            .bytes()
            .next()
            .ok_or_else(|| anyhow!("Unexpected EOF from terminal"))??;
        if c != target[i] {
            i = 0;
        }
        if c == target[i] {
            i += 1;
        }
        if i == target.len() {
            break;
        }
    }
    // Signal to the timeout thread that we've received a response, so it doesn't kill us
    completed.store(true, std::sync::atomic::Ordering::SeqCst);

    // Ignore the clipboard specifier
    while tty
        .by_ref()
        .bytes()
        .next()
        .ok_or_else(|| anyhow!("Unexpected EOF from terminal"))??
        != b';'
    {}

    // Decode and output the pasted data
    let mut output_buf = Vec::new();
    let mut partial = Vec::new();
    let mut has_more = true;
    while has_more {
        // Get a chunk of base64-encoded data from the terminal.
        let buf = tty.fill_buf()?;
        ensure!(!buf.is_empty(), "Unexpected EOF from terminal");

        // Is there an escape sequence in these bytes?
        let bytes_to_consume = match buf.iter().position(|&x| x == ST.as_bytes()[0]) {
            Some(esc_pos) => {
                // Yes, decode up to the escape sequence and stop.
                has_more = false;
                esc_pos
            }
            // No, decode the entire chunk.
            None => buf.len(),
        };
        let buf = &buf[0..bytes_to_consume];

        let mut decode_buf = buf;
        // Are there leftover un-decoded bytes from the last chunk?
        if !partial.is_empty() {
            // Yes. Decode them if we have enough data to finish a 4-byte base64 sequence and/or
            // if this is the last chunk
            assert!(partial.len() < 4);
            let bytes_to_fill = (4 - partial.len()).min(bytes_to_consume);
            partial.extend_from_slice(&buf[0..bytes_to_fill]);
            decode_buf = &decode_buf[bytes_to_fill..];

            if partial.len() == 4 || !has_more {
                BASE64.decode_vec(&partial, &mut output_buf)?;
                partial.clear();
            }
        }

        // If this is not the last chunk, and this chunk ends in the middle of a 4-byte base64
        // sequence, then save the partial sequence for when we have more data.
        if has_more {
            let bytes_to_decode = decode_buf.len() & !0x3; // round down to a multiple of 4
            partial.extend_from_slice(&decode_buf[bytes_to_decode..decode_buf.len()]);
            decode_buf = &decode_buf[..bytes_to_decode];
        }

        BASE64.decode_vec(decode_buf, &mut output_buf)?;
        tty.consume(bytes_to_consume);
        output.write_all(&output_buf)?;
        output_buf.clear();
    }

    // make sure the terminal sent a valid ST sequence to finish it off
    for &c in ST.as_bytes().iter() {
        ensure!(
            tty.by_ref().bytes().next().transpose()? == Some(c),
            "expected an ST sequence to terminate paste"
        );
    }

    // Restore the original terminal settings
    raw.map(RawMode::disable_raw_mode).transpose()?;

    Ok(())
}

/// A RAII helper to put the terminal into raw mode, ensuring the terminal is always restored to
/// its original state later.
#[derive(Clone)]
struct RawMode {
    fd: std::os::fd::RawFd,
    orig_termios: termios::Termios,
}

impl RawMode {
    fn enable_raw_mode(tty: &impl AsRawFd) -> std::io::Result<RawMode> {
        let fd = tty.as_raw_fd();
        let orig_termios = termios::Termios::from_fd(fd)?;
        let mut raw_termios = orig_termios;
        termios::cfmakeraw(&mut raw_termios);
        termios::tcsetattr(fd, termios::TCSAFLUSH, &raw_termios)?;
        Ok(RawMode { fd, orig_termios })
    }

    fn disable_raw_mode(mut self) -> std::io::Result<()> {
        self._disable_raw_mode()?;
        std::mem::forget(self);
        Ok(())
    }

    fn _disable_raw_mode(&mut self) -> std::io::Result<()> {
        termios::tcsetattr(self.fd, termios::TCSADRAIN, &self.orig_termios)
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        _ = self._disable_raw_mode()
    }
}
