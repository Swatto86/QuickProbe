# QuickProbe Development Guidelines

## Hard Requirements

### Code Quality
- **Neat and tidy**: Keep the codebase clean, organized, and consistent
- **Maintainable**: Write clear, understandable code that others can easily work with
- **Extensible**: Design for future growth and feature additions

### Production Standards
- All code must be **production-ready**
- Must compile without errors or warnings
- No placeholder code, demo code, or incomplete implementations

### Documentation
- Include in-code commentary where necessary
- Comments should explain **why**, not just **what**
- Keep comments concise and relevant

## Tech Stack
- **Backend**: Rust (Tauri)
- **Frontend**: JavaScript, HTML, Tailwind CSS
- **Testing**: WebdriverIO (E2E)

## Best Practices
- Follow Rust and JavaScript idioms
- Handle errors explicitly
- Validate inputs defensively
- Keep functions focused and testable

## WinRM Session Rules
- **Always use explicit `New-PSSession` / `Remove-PSSession`** in `execute_remote()`. Never use bare `Invoke-Command -ComputerName` which creates implicit sessions that rely on WinRM idle timeout (default 2 hours) for cleanup.
- **Do not add connectivity pre-checks to the heartbeat path.** `Test-WSMan` or similar validation creates an extra session per probe. Reserve it for user-initiated actions only.
- **Session caching** is handled in `main.rs` via a global `RwLock<HashMap>` pool with a 5-minute TTL. Invalidate on credential/host changes.
- **Heartbeat interval is 120 seconds.** Don't reduce below 60s without considering the session load on target servers (especially domain controllers).
