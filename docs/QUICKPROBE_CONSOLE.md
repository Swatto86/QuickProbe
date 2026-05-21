# QuickProbe Console

QuickProbe Console is a standalone Rust/egui desktop app for a fast, business-focused host operations table.

It deliberately avoids dashboard cards and presents the estate as a single filterable, sortable table.

## Separation from Tauri

QuickProbe Console now lives in its own crate:

```text
quickprobe-console/
```

It does not depend on the Tauri app crate. It only shares the existing local QuickProbe SQLite database:

```text
%APPDATA%\QuickProbe\quickprobe.db
```

The existing Tauri app remains under:

```text
src-tauri/
ui/
```

## Current capabilities

- Loads hosts from the existing `hosts` table.
- Joins latest cached probe data from `host_health`.
- Global filtering across all visible columns.
- Optional per-column filters for every table column.
- Sortable columns.
- Resizable table columns.
- Light/dark mode toggle.
- Add, edit, and delete hosts.
- Double-click/connect behaviour:
  - Windows hosts launch `mstsc /v:<host>`
  - Linux hosts launch `ssh <host>`
- Optional embedded Meslo Nerd Font support.

## Run locally

From the repository root:

```powershell
npm run console
```

Or directly:

```powershell
cd quickprobe-console
cargo run
```

Check the standalone crate:

```powershell
npm run console:check
```

## Optional Meslo Nerd Font

QuickProbe Console can embed Meslo Nerd Font for the whole egui UI.

Place the regular TTF here:

```text
quickprobe-console/assets/fonts/MesloLGS NF Regular.ttf
```

Then rerun:

```powershell
npm run console
```

If the file is not present, the console falls back to egui defaults.

## Design rules

- Table-first interface.
- No dashboard summary cards.
- Keep UI, database access, and remote operations separated as the app grows.
- Do not make the Tauri app a dependency of Console.
- Use the existing database schema for compatibility until a deliberate migration is needed.

## Next work

Planned follow-up work:

1. Add a right-click/context action menu per row.
2. Reuse or port live refresh/probe commands.
3. Add credential management.
4. Add AD scan/import entry point.
5. Add packaging/release workflow for the standalone executable.
6. Split the standalone source into modules once the UI surface stabilises.
