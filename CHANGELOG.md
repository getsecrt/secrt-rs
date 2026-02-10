# Changelog

## 0.1.1 — 2026-02-09

### Added

- **File handling:** `create --file` now stores file metadata (filename, MIME type) in the envelope `hint` field. On claim, file secrets are automatically saved to disk on TTY, with raw bytes piped when stdout is not a terminal.
- **`--output` / `-o` flag for `claim`:** Write claimed secret directly to a file path, or use `-o -` to force raw bytes to stdout.
- **JSON base64 encoding:** `claim --json` outputs `plaintext_base64` (standard base64) instead of lossy UTF-8 for binary files with a file hint.
- **Implicit claim:** Share URLs are auto-detected as the first argument (`secrt <url>` works without `claim` subcommand).

### Fixed

- `<url>` placeholder in usage text now uses ARG color (dim) instead of OPT color (yellow).

## 0.1.0 — 2026-02-09

Initial release.

- **Commands:** `create`, `claim`, `burn`, `config`, `completion`
- **Crypto:** AES-256-GCM + HKDF-SHA256, optional PBKDF2 passphrases, zero-knowledge client-side encryption via `ring`
- **Config:** TOML config file (`~/.config/secrt/config.toml`) with `config init`, env vars, CLI flag precedence
- **Keychain:** Optional OS keychain integration (macOS Keychain, Linux keyutils, Windows Credential Manager) for passphrase storage
- **Claim:** Auto-tries configured `decryption_passphrases`, falls back to interactive prompt on TTY
- **Input:** Stdin pipe, `--text`, `--file`, `--multi-line`, `--trim`, hidden/shown interactive input
- **Output:** Human-friendly TTY output with color, `--json` for scripting, `--silent` mode
- **Shell completions:** Bash, Zsh, Fish via `completion` command
- **No async runtime** — blocking HTTP via `ureq`, ~1.5 MB static binary
