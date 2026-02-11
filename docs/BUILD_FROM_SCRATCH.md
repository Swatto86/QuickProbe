# Build From Scratch (Windows)

Step-by-step guide to build and run QuickProbe from source on a fresh Windows machine.

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Windows 10/11 or Server 2019+ | — | Operating system |
| [Rust](https://rustup.rs) | stable (1.75+) | Backend compiler |
| [Node.js](https://nodejs.org) | 20 LTS | Frontend tooling + Tauri CLI |
| [Strawberry Perl](https://strawberryperl.com) | 5.x | Required by OpenSSL (ssh2 crate) |
| [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) | 2019+ | C/C++ compiler for native dependencies |
| Git | 2.x | Source control |

### Install Rust

```powershell
# Download and run rustup-init.exe from https://rustup.rs
# Accept defaults (stable toolchain, add to PATH)
rustup default stable
rustup component add rustfmt clippy
```

### Install Node.js

```powershell
winget install --id OpenJS.NodeJS.LTS --accept-package-agreements
```

### Install Strawberry Perl

Required for building the `ssh2` crate's vendored OpenSSL.

```powershell
winget install --id StrawberryPerl.StrawberryPerl --accept-package-agreements
```

After installation, **restart your terminal** so `perl` is on PATH.

### Install Visual Studio Build Tools

If you don't already have Visual Studio installed:

```powershell
winget install --id Microsoft.VisualStudio.2022.BuildTools --accept-package-agreements
```

During installation, select the **"Desktop development with C++"** workload.

## Clone the Repository

```powershell
git clone https://github.com/Swatto86/QuickProbe.git
cd QuickProbe
```

## Install Dependencies

```powershell
npm ci
```

## Verify the Build

Run the single verification command:

```powershell
pwsh -File scripts/verify.ps1
```

This runs format check, linting, tests, and a release build. All 4 steps must pass.

## Build the Application

### Development mode (with hot reload)

```powershell
npm run dev
```

### Production build (creates installer)

```powershell
npm run build
```

The installer (`.exe`) will be in `src-tauri/target/release/bundle/nsis/`.

## Run the Application

After `npm run dev`, the app launches automatically. For a production build:

```
src-tauri\target\release\bundle\nsis\QuickProbe_<version>_x64-setup.exe
```

## Project Structure

| Path | Purpose |
|------|---------|
| `src-tauri/` | Rust backend (Tauri v2) |
| `ui/` | Frontend (HTML + Tailwind CSS + JS) |
| `scripts/` | Dev tooling (verify.ps1) |
| `e2e/` | WebdriverIO end-to-end tests |

## Common Failure Modes

### `perl` not found during build

**Symptom**: `Error configuring OpenSSL build: Command 'perl' not found`

**Fix**: Install Strawberry Perl and restart your terminal:
```powershell
winget install --id StrawberryPerl.StrawberryPerl
# Close and reopen terminal
```

### OpenSSL build fails with NASM errors

**Symptom**: `NASM not found` during OpenSSL compilation

**Fix**: This is typically a false alarm — the build falls back to a C-only configuration. If it truly fails, install NASM:
```powershell
winget install --id NASM.NASM
```

### `cargo clippy` / `cargo build` reports missing MSVC linker

**Symptom**: `linker 'link.exe' not found`

**Fix**: Install Visual Studio Build Tools with the C++ workload:
```powershell
winget install --id Microsoft.VisualStudio.2022.BuildTools
# Select "Desktop development with C++" during setup
```

### `npm ci` fails with node-gyp errors

**Symptom**: `node-gyp` compilation errors for native modules

**Fix**: Ensure Python 3 is installed (usually bundled with Build Tools). If not:
```powershell
winget install --id Python.Python.3.12
```

### Tests fail with `registry` or `credman` errors

**Symptom**: Registry or Credential Manager tests fail

**Fix**: These tests interact with the Windows registry and Credential Manager. They require the current user to have write access (standard user permissions are sufficient — no admin required).

### First build is very slow

**Expected**: The initial build compiles ~600 crate dependencies including OpenSSL from source. This takes 10–20 minutes depending on your machine. Subsequent builds use cached artifacts and complete in seconds.
