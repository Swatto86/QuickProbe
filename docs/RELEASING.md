# Releasing QuickProbe

## Prerequisites

- Push access to `main`
- Repository secrets configured:
  - `TAURI_SIGNING_PRIVATE_KEY` — Tauri update signing key
  - `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` — Signing key password

## Release Process

### 1. Update version numbers

Update the version in both:
- `src-tauri/Cargo.toml` → `version = "X.Y.Z"`
- `src-tauri/tauri.conf.json` → `"version": "X.Y.Z"`

### 2. Update CHANGELOG.md

Move items from `[Unreleased]` to a new version section:

```markdown
## [X.Y.Z] - YYYY-MM-DD

### Added
- ...

### Fixed
- ...
```

Update comparison links at the bottom of the file.

### 3. Run verification

```powershell
pwsh -File scripts/verify.ps1
```

All 4 steps must pass.

### 4. Commit and push

```powershell
git add -A
git commit -m "release: vX.Y.Z"
git push origin main
```

### 5. Create an annotated tag

```powershell
git tag -a vX.Y.Z -m "QuickProbe vX.Y.Z

## What's New
- Feature 1
- Feature 2

## Fixes
- Fix 1
"
git push origin vX.Y.Z
```

The tag message becomes the GitHub Release body.

### 6. Wait for CI

The `release.yml` workflow will:
1. Run `scripts/verify.ps1` (quality gate)
2. Build the Tauri app (NSIS installer)
3. Generate SHA256 checksums for all artifacts
4. Create a draft GitHub Release with artifacts attached
5. Publish the release automatically

Monitor progress at: https://github.com/Swatto86/QuickProbe/actions

### 7. Verify the release

- Check the [Releases page](https://github.com/Swatto86/QuickProbe/releases)
- Download and verify the installer
- Confirm SHA256 checksums match

## Rollback

If a release has critical issues:

1. **Remove the tag** (stops further downloads from that version):
   ```powershell
   git tag -d vX.Y.Z
   git push origin :refs/tags/vX.Y.Z
   ```

2. **Delete the GitHub Release** from the Releases page.

3. **Fix the issue** on `main`, then re-release with a patch version bump.

## Versioning

QuickProbe follows [Semantic Versioning](https://semver.org/):

- **MAJOR** (X): Breaking changes to user-facing behavior
- **MINOR** (Y): New features, backward compatible
- **PATCH** (Z): Bug fixes, backward compatible

## Artifacts Produced

| Artifact | Description |
|----------|-------------|
| `QuickProbe_X.Y.Z_x64-setup.exe` | NSIS installer for Windows |
| `QuickProbe_X.Y.Z_x64-setup.nsis.zip` | Compressed installer |
| `SHA256SUMS.txt` | SHA256 checksums for all artifacts |
| `latest.json` | Tauri auto-update manifest |
