mod helpers;

use helpers::{args, TestDepsBuilder};
use secrt::cli;
use secrt::envelope::crypto::b64_encode;

/// Non-routable address to ensure API calls fail
const DEAD_URL: &str = "http://127.0.0.1:19191";

fn make_share_url(base: &str, id: &str) -> String {
    let key = vec![42u8; 32];
    let key_b64 = b64_encode(&key);
    format!("{}/s/{}#v1.{}", base, id, key_b64)
}

#[test]
fn burn_help() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "burn", "--help"]), &mut deps);
    assert_eq!(code, 0);
    assert!(!stderr.to_string().is_empty());
}

#[test]
fn burn_no_id() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "burn"]), &mut deps);
    assert_eq!(code, 2);
    assert!(stderr.to_string().contains("required"));
}

#[test]
fn burn_no_api_key() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "burn", "testid"]), &mut deps);
    assert_eq!(code, 2);
    assert!(stderr.to_string().contains("api-key"));
}

#[test]
fn burn_bare_id() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("SECRET_BASE_URL", DEAD_URL)
        .build();
    let code = cli::run(
        &args(&["secrt", "burn", "testid", "--api-key", "sk_test"]),
        &mut deps,
    );
    assert_eq!(code, 1, "stderr: {}", stderr.to_string());
}

#[test]
fn burn_share_url() {
    let url = make_share_url(DEAD_URL, "abc123");
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(
        &args(&["secrt", "burn", &url, "--api-key", "sk_test"]),
        &mut deps,
    );
    assert_eq!(code, 1, "stderr: {}", stderr.to_string());
}

#[test]
fn burn_json_output() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("SECRET_BASE_URL", DEAD_URL)
        .build();
    let code = cli::run(
        &args(&["secrt", "burn", "testid", "--api-key", "sk_test", "--json"]),
        &mut deps,
    );
    assert_eq!(code, 1);
    let err = stderr.to_string();
    assert!(err.contains("\"error\""), "should be JSON error: {}", err);
}

#[test]
fn burn_env_api_key() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("SECRET_API_KEY", "sk_from_env")
        .env("SECRET_BASE_URL", DEAD_URL)
        .build();
    let code = cli::run(&args(&["secrt", "burn", "testid"]), &mut deps);
    assert_eq!(code, 1, "stderr: {}", stderr.to_string());
}
