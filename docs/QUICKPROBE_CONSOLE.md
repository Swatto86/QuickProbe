# QuickProbe Console

QuickProbe Console is a fast, business-focused desktop view over the existing QuickProbe host inventory.

It intentionally avoids dashboard summary cards and presents hosts in a single filterable, sortable table.

## Current scope

This first pass is a standalone Rust/egui binary that reuses the existing QuickProbe SQLite database at:

```text
%APPDATA%\QuickProbe\quickprobe.db
```

It currently supports:

- loading hosts from the existing `hosts` table
- joining latest probe data from `host_health`
- filtering by host, group, OS, status, or notes
- sorting table columns
- selecting a host
- double-click connect behaviour:
  - Windows hosts launch `mstsc /v:<host>`
  - Linux hosts launch `ssh <host>`

## Run locally

From the repository root:

```powershell
cd src-tauri
cargo run --bin quickprobe-console
```

## Design rules

- Table-first interface.
- No summary cards.
- Keep the existing Tauri UI untouched until Console reaches feature parity.
- Keep probing, credentials, database, and host actions outside the UI layer.
- The UI should display state and dispatch commands; it should not own business logic.

## Next work

Planned follow-up work:

1. Add a proper action column/context menu.
2. Reuse existing QuickProbe refresh/probe commands rather than only reading cached health data.
3. Add host editor integration.
4. Add credentials flow.
5. Add AD scan entry point.
6. Add packaging/release workflow once the binary is stable.
