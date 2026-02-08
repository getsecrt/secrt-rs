#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{self, Cursor, Write};
use std::sync::{Arc, Mutex};

use secrt::cli::Deps;
use secrt::envelope::EnvelopeError;

/// A shared buffer that implements Write for capturing output.
#[derive(Clone)]
pub struct SharedBuf(pub Arc<Mutex<Vec<u8>>>);

impl SharedBuf {
    pub fn new() -> Self {
        SharedBuf(Arc::new(Mutex::new(Vec::new())))
    }

    pub fn to_string(&self) -> String {
        let buf = self.0.lock().unwrap();
        String::from_utf8_lossy(&buf).to_string()
    }
}

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Build test Deps with configurable options.
pub struct TestDepsBuilder {
    stdin_data: Vec<u8>,
    is_tty: bool,
    is_stdout_tty: bool,
    env: HashMap<String, String>,
    read_pass_responses: Vec<String>,
    read_pass_error: Option<String>,
}

impl TestDepsBuilder {
    pub fn new() -> Self {
        TestDepsBuilder {
            stdin_data: Vec::new(),
            is_tty: false,
            is_stdout_tty: false,
            env: HashMap::new(),
            read_pass_responses: Vec::new(),
            read_pass_error: None,
        }
    }

    pub fn stdin(mut self, data: &[u8]) -> Self {
        self.stdin_data = data.to_vec();
        self
    }

    pub fn is_tty(mut self, v: bool) -> Self {
        self.is_tty = v;
        self
    }

    #[allow(dead_code)]
    pub fn is_stdout_tty(mut self, v: bool) -> Self {
        self.is_stdout_tty = v;
        self
    }

    pub fn env(mut self, key: &str, val: &str) -> Self {
        self.env.insert(key.to_string(), val.to_string());
        self
    }

    pub fn read_pass(mut self, responses: &[&str]) -> Self {
        self.read_pass_responses = responses.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn read_pass_error(mut self, msg: &str) -> Self {
        self.read_pass_error = Some(msg.to_string());
        self
    }

    pub fn build(self) -> (Deps, SharedBuf, SharedBuf) {
        let stdout = SharedBuf::new();
        let stderr = SharedBuf::new();
        let stdout_clone = stdout.clone();
        let stderr_clone = stderr.clone();

        let is_tty = self.is_tty;
        let is_stdout_tty = self.is_stdout_tty;
        let env = self.env;

        let read_pass_responses = Arc::new(Mutex::new(self.read_pass_responses));
        let read_pass_error = self.read_pass_error;

        let deps = Deps {
            stdin: Box::new(Cursor::new(self.stdin_data)),
            stdout: Box::new(stdout_clone),
            stderr: Box::new(stderr_clone),
            is_tty: Box::new(move || is_tty),
            is_stdout_tty: Box::new(move || is_stdout_tty),
            getenv: Box::new(move |key: &str| env.get(key).cloned()),
            rand_bytes: Box::new(|buf: &mut [u8]| {
                use ring::rand::{SecureRandom, SystemRandom};
                let rng = SystemRandom::new();
                rng.fill(buf)
                    .map_err(|_| EnvelopeError::RngError("SystemRandom failed".into()))
            }),
            read_pass: Box::new(move |_prompt: &str, _w: &mut dyn Write| {
                if let Some(ref msg) = read_pass_error {
                    return Err(io::Error::new(io::ErrorKind::Other, msg.clone()));
                }
                let mut responses = read_pass_responses.lock().unwrap();
                if responses.is_empty() {
                    Err(io::Error::new(io::ErrorKind::Other, "no password input"))
                } else {
                    Ok(responses.remove(0))
                }
            }),
        };

        (deps, stdout, stderr)
    }
}

/// Helper to build args vec from a slice of &str.
pub fn args(strs: &[&str]) -> Vec<String> {
    strs.iter().map(|s| s.to_string()).collect()
}
