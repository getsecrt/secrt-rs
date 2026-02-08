# Test Coverage Report

## Current State

**165 tests passing, 6 E2E tests ignored (gated by env var)**

| File | Lines | Missed | Coverage |
|------|------:|-------:|---------:|
| `burn.rs` | 57 | 2 | 96.5% |
| `claim.rs` | 73 | 12 | 83.6% |
| `cli.rs` | 492 | 15 | 97.0% |
| `client.rs` | 98 | 45 | 54.1% |
| `color.rs` | 15 | 0 | 100% |
| `config.rs` | 120 | 13 | 89.2% |
| `create.rs` | 100 | 11 | 89.0% |
| `envelope/crypto.rs` | 660 | 18 | 97.3% |
| `envelope/ttl.rs` | 53 | 3 | 94.3% |
| `envelope/types.rs` | 10 | 0 | 100% |
| `envelope/url.rs` | 127 | 1 | 99.2% |
| `keychain.rs` | 3 | 0 | 100% |
| `main.rs` | 41 | 41 | 0% |
| `passphrase.rs` | 281 | 14 | 95.0% |
| **TOTAL** | **2130** | **175** | **91.8%** |

Excluding `main.rs` and `client.rs` (untestable I/O wiring and HTTP): **95.5%**.

## Architecture: Mock API Testing

The codebase uses a `SecretApi` trait to abstract the HTTP layer:

```rust
pub trait SecretApi {
    fn create(&self, req: CreateRequest) -> Result<CreateResponse, String>;
    fn claim(&self, secret_id: &str, claim_token: &[u8]) -> Result<ClaimResponse, String>;
    fn burn(&self, secret_id: &str) -> Result<(), String>;
}
```

`Deps` includes a `make_api: Box<dyn Fn(&str, &str) -> Box<dyn SecretApi>>` factory. In production (`main.rs`), this creates a real `ApiClient`. In tests, `TestDepsBuilder` supports `.mock_create()`, `.mock_claim()`, and `.mock_burn()` to inject canned responses via `MockApi`, enabling full success-path testing without network calls.

## What's Covered

- **Crypto**: All `seal()`/`open()` paths, RNG failure injection at each call site, every `validate_envelope()` check, every `parse_kdf()` branch, claim token derivation, base64 error handling, Display impl for all error variants.
- **URL parsing**: Full URL, bare ID, port, missing fragment, wrong version, bad base64, wrong key length, empty ID, no-path URL, format/parse roundtrip.
- **TTL parsing**: All valid/invalid vectors from the spec (34 vectors), single-char invalid input.
- **CLI parsing**: Every flag (value + missing-value), positional args, `--help`/`-h`, unknown flags, mixed args. `resolve_globals()` with env vars, config file, flag overrides, and defaults.
- **Config**: TOML loading, partial configs, invalid TOML warnings, permission-based secret filtering, missing file fallback.
- **Passphrase**: All three sources (env/file/prompt), config default fallback, mutual exclusivity (in both `resolve_passphrase` and `resolve_passphrase_for_create`), empty values, file trimming, create confirmation match/mismatch, `write_error()` in JSON and plain modes.
- **CLI dispatch**: All commands, version/help flags, completion scripts (bash/zsh/fish), unknown command/shell errors.
- **Command handlers (create)**: Unknown flags, input validation (empty stdin/file, multiple sources, invalid TTL), passphrase via env, success path (plain + JSON + TTL), API error handling.
- **Command handlers (claim)**: Unknown flags, missing URL, invalid URL, base-URL override, success path (plain + JSON + passphrase), decryption error, API error handling.
- **Command handlers (burn)**: Unknown flags, missing ID, missing API key, bare ID, share URL, malformed URL, success path (plain + JSON + via share URL), API error handling.

## What's Not Covered (175 lines)

### 1. `main.rs` -- 41 lines, 0%

Pure I/O wiring: `io::stdin()`, `io::stdout()`, `SystemRandom`, `rpassword`, config loading. Tests use `cli::run()` with injected deps instead. Not coverable with unit/integration tests.

### 2. `client.rs` -- 45 lines, 54%

All HTTP methods (`create`, `claim`, `burn`), response parsing, and error handling. The mock API trait bypasses this code entirely. Only coverable via E2E tests against a real server.

### 3. `config.rs` -- 13 lines, 89%

The top-level `load_config()` function (config path resolution, permission checking, file loading orchestration). The internal functions (`load_config_from_path`, `load_config_filtered`) are fully tested. `load_config()` itself is only called from `main.rs`.

### 4. `claim.rs` -- 12 lines, 84%

| Lines | What | Why |
|-------|------|-----|
| L50, L53, L56 | Base URL derivation edge cases | L53 unreachable (redundant `if let` after `contains`). L50/L56 require URLs without paths, which fail at `parse_share_url` first. |
| L65-72 | `derive_claim_token` error | Only triggers with invalid url_key length, but `parse_share_url` already validates this. Dead code. |
| L89-92 | Passphrase resolution error during claim | Requires a passphrase flag that errors, but the mock API must succeed first. |

### 5. `create.rs` -- 11 lines, 89%

| Lines | What | Why |
|-------|------|-----|
| L48-51 | Passphrase resolution error during create | Requires passphrase to fail after plaintext/TTL succeed. |
| L65-72 | Seal envelope error | Ring won't fail with valid inputs. |
| L126, L141 | `fs::read` and `stdin.read_to_end` error map closures | Require I/O errors that can't be injected through `Deps`. |

### 6. `envelope/crypto.rs` -- 18 lines, 97%

All inside ring library error branches (`UnboundKey::new`, `Nonce::try_assume_unique_for_key`, HKDF expand/fill). Ring won't fail on valid-length inputs. Defensive code.

### 7. `passphrase.rs` -- 14 lines, 95%

Uncovered lines are inside test helper closures (`make_deps`), not production code. One line (L77) is the `passphrase_default` counting in `resolve_passphrase_for_create` which delegates to `resolve_passphrase` before reaching that check.

### 8. `cli.rs` -- 15 lines, 97%

Test helper closures and config-related globals wiring in test helpers. Not production code.

### 9. `envelope/ttl.rs` -- 3 lines, 94%

L35 and L61 are genuinely unreachable (empty check at L11 prevents L35; L61 is `unreachable!()` after exhaustive match).

## Theoretical Coverage Ceiling

| Category | Lines | Notes |
|----------|------:|-------|
| `main.rs` I/O wiring | 41 | Not testable |
| `client.rs` HTTP | 45 | Only via E2E |
| `crypto.rs` ring errors | 18 | Can't trigger with valid inputs |
| `config.rs` `load_config()` | 13 | Only called from `main.rs` |
| `ttl.rs` unreachable | 2 | Dead code |
| Test helper closures | ~10 | Not production code |
| **Total uncoverable** | **~129** | |

Maximum achievable without E2E: **~93.9%** (2130 - 129 = 2001 coverable, 2130 - 175 = 1955 covered, 1955/2001 = 97.7% of coverable code).

## E2E Tests

6 E2E tests cover the full create/claim/burn roundtrip against a real server:

```sh
# Basic (public endpoints only):
SECRET_E2E_BASE_URL=https://secrt.ca cargo test e2e -- --ignored

# Full (including burn and API key create, requires API key):
SECRET_E2E_BASE_URL=https://secrt.ca SECRET_E2E_API_KEY=sk_... cargo test e2e -- --ignored
```

When run, these cover `client.rs` HTTP paths (~45 lines), pushing total coverage towards ~94%.
