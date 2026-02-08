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
