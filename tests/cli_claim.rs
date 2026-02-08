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
fn claim_help() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "claim", "--help"]), &mut deps);
    assert_eq!(code, 0);
    assert!(!stderr.to_string().is_empty());
}

#[test]
fn claim_no_url() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "claim"]), &mut deps);
    assert_eq!(code, 2);
    assert!(stderr.to_string().contains("required"));
}

#[test]
fn claim_invalid_url() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "claim", "not-a-valid-url"]), &mut deps);
    assert_eq!(code, 2);
    assert!(stderr.to_string().contains("invalid"));
}

#[test]
fn claim_api_call_fails() {
    let url = make_share_url(DEAD_URL, "test123");
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "claim", &url]), &mut deps);
    assert_eq!(code, 1, "stderr: {}", stderr.to_string());
}

#[test]
fn claim_base_url_flag_override() {
    let url = make_share_url("https://secrt.ca", "test123");
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(
        &args(&["secrt", "claim", &url, "--base-url", DEAD_URL]),
        &mut deps,
    );
    assert_eq!(code, 1, "stderr: {}", stderr.to_string());
}

#[test]
fn claim_json_error() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "claim", "--json", "not-valid"]), &mut deps);
    assert_eq!(code, 2);
    let err = stderr.to_string();
    assert!(err.contains("\"error\""), "should be JSON error: {}", err);
}
