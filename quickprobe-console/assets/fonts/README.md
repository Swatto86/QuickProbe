# Console font assets

QuickProbe Console can embed Meslo Nerd Font for the whole egui UI.

To enable it locally, place this file here:

```text
quickprobe-console/assets/fonts/MesloLGS NF Regular.ttf
```

Then rebuild or rerun:

```powershell
npm run console
```

If the font file is not present, the console falls back to egui's default fonts.

The font file itself is intentionally not committed here. Use the MesloLGS Nerd Font regular TTF from the Nerd Fonts project and verify its licence/source before redistributing binaries that include it.
