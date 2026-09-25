# QuickProbe — agent instructions

Every coding agent loads this file itself. `ARCHITECTURE.md` is the Project Atlas: read the
parts a task needs, and update it in the same change whenever structure, APIs, boundaries,
build or config change.

## Mandatory Rules

1. **Always run `scripts/verify.ps1` before claiming work is done.** This is the single source of truth for repo health.
2. **Do not weaken checks to make things pass.** Fix the underlying issue instead.
3. **Prefer small, focused commits.** One concern per commit. Keep diffs auditable.
4. **Do not commit secrets, credentials, or API keys.** Use environment variables or Windows Credential Manager.
5. **Do not silence warnings without justification.** If a warning is suppressed, document why in a code comment.

## Development Workflow

1. Work directly on `main`: this repository has one branch and takes no PRs.
2. Make changes — keep them small and reversible.
3. Run `pwsh -File scripts/verify.ps1` and confirm all 4 steps pass.
4. Commit and push to `main`; CI runs on the push.

## Tech Stack

- **Backend**: Rust (Tauri v2)
- **Frontend**: JavaScript, HTML, Tailwind CSS (DaisyUI)
- **Build**: `cargo build --lib` (library), `npm run build` (full Tauri app)
- **Tests**: `cargo test --lib` (Rust unit tests), WebdriverIO (E2E)
- **Platform**: Windows only (WinRM, SSH, Windows Credential Manager)

## Code Quality Standards

- All Rust code must pass `cargo fmt --check` and `cargo clippy -- -D warnings`.
- Handle errors explicitly — no `unwrap()` in production paths.
- Validate inputs defensively.
- Follow existing module patterns and naming conventions.

## WinRM Session Rules

- Always use explicit `New-PSSession` / `Remove-PSSession` in `execute_remote()`.
- Do not add connectivity pre-checks to the heartbeat path.
- Session caching is handled in `main.rs` via a global `RwLock<HashMap>` pool with a 5-minute TTL.
- Heartbeat interval is 120 seconds — do not reduce below 60s.
