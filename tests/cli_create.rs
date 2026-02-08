mod helpers;

use helpers::{args, TestDepsBuilder};
use secrt::cli;

/// Use a non-routable address to ensure API calls fail
const DEAD_URL: &str = "http://127.0.0.1:19191";

#[test]
fn create_help() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "create", "--help"]), &mut deps);
    assert_eq!(code, 0);
    assert!(!stderr.to_string().is_empty());
}

#[test]
fn create_stdin() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"my secret data")
        .env("SECRET_BASE_URL", DEAD_URL)
        .build();
    let code = cli::run(&args(&["secrt", "create"]), &mut deps);
    assert_eq!(code, 1, "stderr: {}", stderr.to_string());
}

#[test]
fn create_text_flag() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("SECRET_BASE_URL", DEAD_URL)
        .build();
    let code = cli::run(&args(&["secrt", "create", "--text", "hello"]), &mut deps);
    assert_eq!(code, 1, "stderr: {}", stderr.to_string());
}

#[test]
fn create_file_flag() {
    let dir = std::env::temp_dir();
    let path = dir.join("secrt_test_create_file.txt");
    std::fs::write(&path, "file content").unwrap();

    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("SECRET_BASE_URL", DEAD_URL)
        .build();
    let code = cli::run(
        &args(&["secrt", "create", "--file", path.to_str().unwrap()]),
        &mut deps,
    );
    assert_eq!(code, 1, "stderr: {}", stderr.to_string());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn create_multiple_sources() {
    let dir = std::env::temp_dir();
    let path = dir.join("secrt_test_create_multi.txt");
    std::fs::write(&path, "data").unwrap();

    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(
        &args(&[
            "secrt",
            "create",
            "--text",
            "hello",
            "--file",
            path.to_str().unwrap(),
        ]),
        &mut deps,
    );
    assert_eq!(code, 2, "stderr: {}", stderr.to_string());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn create_empty_stdin() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().stdin(b"").build();
    let code = cli::run(&args(&["secrt", "create"]), &mut deps);
    assert_eq!(code, 2, "stderr: {}", stderr.to_string());
    assert!(stderr.to_string().contains("empty"));
}

#[test]
fn create_invalid_ttl() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().stdin(b"data").build();
    let code = cli::run(&args(&["secrt", "create", "--ttl", "abc"]), &mut deps);
    assert_eq!(code, 2, "stderr: {}", stderr.to_string());
}

#[test]
fn create_tty_prompt() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"tty data")
        .is_tty(true)
        .env("SECRET_BASE_URL", DEAD_URL)
        .build();
    let code = cli::run(&args(&["secrt", "create"]), &mut deps);
    assert_eq!(code, 1, "stderr: {}", stderr.to_string());
    assert!(
        stderr.to_string().contains("Enter secret"),
        "stderr should contain prompt: {}",
        stderr.to_string()
    );
}

#[test]
fn create_with_passphrase_env() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"data")
        .env("MY_PASS", "secret123")
        .env("SECRET_BASE_URL", DEAD_URL)
        .build();
    let code = cli::run(
        &args(&["secrt", "create", "--passphrase-env", "MY_PASS"]),
        &mut deps,
    );
    assert_eq!(code, 1, "stderr: {}", stderr.to_string());
}

#[test]
fn create_json_output() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .stdin(b"data")
        .env("SECRET_BASE_URL", DEAD_URL)
        .build();
    let code = cli::run(&args(&["secrt", "create", "--json"]), &mut deps);
    assert_eq!(code, 1);
    let err = stderr.to_string();
    assert!(err.contains("\"error\""), "stderr should be JSON: {}", err);
}
