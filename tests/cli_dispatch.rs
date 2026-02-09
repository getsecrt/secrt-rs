mod helpers;

use helpers::{args, TestDepsBuilder};
use secrt::cli;

#[test]
fn no_args_exit_2() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt"]), &mut deps);
    assert_eq!(code, 2);
    let err = stderr.to_string();
    assert!(err.contains("secrt"), "stderr should contain usage");
}

#[test]
fn version_flag() {
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "--version"]), &mut deps);
    assert_eq!(code, 0);
    let out = stdout.to_string();
    assert!(out.contains("secrt"), "stdout should contain version");
}

#[test]
fn version_flag_short() {
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "-v"]), &mut deps);
    assert_eq!(code, 0);
    assert!(stdout.to_string().contains("secrt"));
}

#[test]
fn version_command() {
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "version"]), &mut deps);
    assert_eq!(code, 0);
    assert!(stdout.to_string().contains("secrt"));
}

#[test]
fn help_flag() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "--help"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(err.contains("USAGE") || err.contains("secrt"));
}

#[test]
fn help_flag_short() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "-h"]), &mut deps);
    assert_eq!(code, 0);
    assert!(!stderr.to_string().is_empty());
}

#[test]
fn help_command() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "help"]), &mut deps);
    assert_eq!(code, 0);
    assert!(!stderr.to_string().is_empty());
}

#[test]
fn help_create() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "help", "create"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(err.contains("create") || err.contains("Encrypt"));
}

#[test]
fn help_claim() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "help", "claim"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(err.contains("claim") || err.contains("Retrieve"));
}

#[test]
fn help_burn() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "help", "burn"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(err.contains("burn") || err.contains("Destroy"));
}

#[test]
fn help_unknown() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "help", "bogus"]), &mut deps);
    assert_eq!(code, 2);
    assert!(stderr.to_string().contains("unknown"));
}

#[test]
fn unknown_command() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "bogus"]), &mut deps);
    assert_eq!(code, 2);
    assert!(stderr.to_string().contains("unknown"));
}

#[test]
fn config_shows_defaults() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "config"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(
        err.contains("base_url"),
        "config should show base_url: {}",
        err
    );
    assert!(
        err.contains("https://secrt.ca"),
        "config should show default base_url: {}",
        err
    );
    assert!(
        err.contains("api_key"),
        "config should show api_key: {}",
        err
    );
    assert!(
        err.contains("show_input"),
        "config should show show_input: {}",
        err
    );
}

#[test]
fn config_shows_env_api_key_masked() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("SECRET_API_KEY", "sk_live_abc123xyz789")
        .build();
    let code = cli::run(&args(&["secrt", "config"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(
        err.contains("sk_live_"),
        "config should show masked api_key prefix: {}",
        err
    );
    assert!(
        !err.contains("xyz789"),
        "config should NOT show full api_key: {}",
        err
    );
    assert!(
        err.contains("env SECRET_API_KEY"),
        "config should show source: {}",
        err
    );
}

#[test]
fn config_shows_env_base_url() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new()
        .env("SECRET_BASE_URL", "https://custom.example.com")
        .build();
    let code = cli::run(&args(&["secrt", "config"]), &mut deps);
    assert_eq!(code, 0);
    let err = stderr.to_string();
    assert!(
        err.contains("https://custom.example.com"),
        "config should show env base_url: {}",
        err
    );
    assert!(
        err.contains("env SECRET_BASE_URL"),
        "config should show source: {}",
        err
    );
}

#[test]
fn completion_bash() {
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "completion", "bash"]), &mut deps);
    assert_eq!(code, 0);
    assert!(stdout.to_string().contains("_secrt"));
}

#[test]
fn completion_zsh() {
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "completion", "zsh"]), &mut deps);
    assert_eq!(code, 0);
    assert!(stdout.to_string().contains("compdef") || stdout.to_string().contains("_secrt"));
}

#[test]
fn completion_fish() {
    let (mut deps, stdout, _stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "completion", "fish"]), &mut deps);
    assert_eq!(code, 0);
    assert!(stdout.to_string().contains("complete"));
}

#[test]
fn completion_no_arg() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "completion"]), &mut deps);
    assert_eq!(code, 2);
    assert!(stderr.to_string().contains("specify a shell"));
}

#[test]
fn completion_unknown() {
    let (mut deps, _stdout, stderr) = TestDepsBuilder::new().build();
    let code = cli::run(&args(&["secrt", "completion", "powershell"]), &mut deps);
    assert_eq!(code, 2);
    assert!(stderr.to_string().contains("unsupported shell"));
}
