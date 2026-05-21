use eframe::egui;
use egui_extras::{Column, TableBuilder};
use quickprobe::db;
use rusqlite::{params, Connection};
use serde_json::Value;
use std::cmp::Ordering;
use std::process::Command;

const APP_TITLE: &str = "QuickProbe Console";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SortColumn {
    Status,
    Host,
    Os,
    Group,
    Cpu,
    Memory,
    Disk,
    Uptime,
    LastChecked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SortDirection {
    Asc,
    Desc,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ThemeMode {
    Dark,
    Light,
}

#[derive(Clone, Debug, Default)]
struct HostRow {
    server_name: String,
    group_name: String,
    os_type: String,
    notes: String,
    services: String,
    status: String,
    cpu: Option<f64>,
    memory: Option<f64>,
    disk: Option<f64>,
    uptime: Option<String>,
    last_checked: Option<String>,
}

#[derive(Clone, Debug, Default)]
struct HostEditor {
    original_name: Option<String>,
    server_name: String,
    group_name: String,
    os_type: String,
    notes: String,
    services: String,
}

impl HostEditor {
    fn new() -> Self {
        Self {
            os_type: "Windows".to_string(),
            ..Default::default()
        }
    }

    fn from_host(host: &HostRow) -> Self {
        Self {
            original_name: Some(host.server_name.clone()),
            server_name: host.server_name.clone(),
            group_name: host.group_name.clone(),
            os_type: host.os_type.clone(),
            notes: host.notes.clone(),
            services: host.services.clone(),
        }
    }

    fn title(&self) -> &'static str {
        if self.original_name.is_some() {
            "Edit host"
        } else {
            "Add host"
        }
    }
}

struct ConsoleApp {
    hosts: Vec<HostRow>,
    filter: String,
    sort_column: SortColumn,
    sort_direction: SortDirection,
    selected_host: Option<String>,
    last_error: Option<String>,
    theme_mode: ThemeMode,
    host_editor: Option<HostEditor>,
    confirm_delete_host: Option<String>,
}

impl Default for ConsoleApp {
    fn default() -> Self {
        let mut app = Self {
            hosts: Vec::new(),
            filter: String::new(),
            sort_column: SortColumn::Host,
            sort_direction: SortDirection::Asc,
            selected_host: None,
            last_error: None,
            theme_mode: ThemeMode::Dark,
            host_editor: None,
            confirm_delete_host: None,
        };
        app.reload_hosts();
        app
    }
}

impl ConsoleApp {
    fn reload_hosts(&mut self) {
        match load_hosts() {
            Ok(hosts) => {
                self.hosts = hosts;
                self.last_error = None;
            }
            Err(err) => self.last_error = Some(err),
        }
    }

    fn visible_hosts(&self) -> Vec<HostRow> {
        let filter = self.filter.trim().to_lowercase();
        let mut rows: Vec<_> = self
            .hosts
            .iter()
            .filter(|host| {
                filter.is_empty()
                    || host.server_name.to_lowercase().contains(&filter)
                    || host.group_name.to_lowercase().contains(&filter)
                    || host.os_type.to_lowercase().contains(&filter)
                    || host.status.to_lowercase().contains(&filter)
                    || host.notes.to_lowercase().contains(&filter)
                    || host.services.to_lowercase().contains(&filter)
            })
            .cloned()
            .collect();

        rows.sort_by(|left, right| compare_hosts(left, right, self.sort_column));
        if self.sort_direction == SortDirection::Desc {
            rows.reverse();
        }
        rows
    }

    fn set_sort(&mut self, column: SortColumn) {
        if self.sort_column == column {
            self.sort_direction = match self.sort_direction {
                SortDirection::Asc => SortDirection::Desc,
                SortDirection::Desc => SortDirection::Asc,
            };
        } else {
            self.sort_column = column;
            self.sort_direction = SortDirection::Asc;
        }
    }

    fn toggle_theme(&mut self) {
        self.theme_mode = match self.theme_mode {
            ThemeMode::Dark => ThemeMode::Light,
            ThemeMode::Light => ThemeMode::Dark,
        };
    }

    fn apply_theme(&self, ctx: &egui::Context) {
        match self.theme_mode {
            ThemeMode::Dark => ctx.set_visuals(egui::Visuals::dark()),
            ThemeMode::Light => ctx.set_visuals(egui::Visuals::light()),
        }
    }

    fn open_add_host(&mut self) {
        self.host_editor = Some(HostEditor::new());
    }

    fn open_edit_selected(&mut self) {
        let Some(selected) = self.selected_host.as_deref() else {
            return;
        };

        if let Some(host) = self.hosts.iter().find(|host| host.server_name == selected) {
            self.host_editor = Some(HostEditor::from_host(host));
        }
    }

    fn request_delete_selected(&mut self) {
        if let Some(selected) = &self.selected_host {
            self.confirm_delete_host = Some(selected.clone());
        }
    }

    fn save_editor(&mut self, editor: HostEditor) {
        match save_host(&editor) {
            Ok(saved_name) => {
                self.selected_host = Some(saved_name);
                self.host_editor = None;
                self.reload_hosts();
            }
            Err(err) => self.last_error = Some(err),
        }
    }

    fn delete_host(&mut self, server_name: &str) {
        match delete_host(server_name) {
            Ok(()) => {
                if self.selected_host.as_deref() == Some(server_name) {
                    self.selected_host = None;
                }
                self.confirm_delete_host = None;
                self.reload_hosts();
            }
            Err(err) => self.last_error = Some(err),
        }
    }

    fn launch_selected(&mut self) {
        let Some(host) = self.selected_host.clone() else {
            return;
        };

        let Some((server_name, os_type)) = self
            .hosts
            .iter()
            .find(|candidate| candidate.server_name == host)
            .map(|row| (row.server_name.clone(), row.os_type.clone()))
        else {
            return;
        };

        if os_type.eq_ignore_ascii_case("linux") {
            self.launch_process("ssh", &[server_name.as_str()]);
        } else {
            let target = format!("/v:{server_name}");
            self.launch_process("mstsc", &[target.as_str()]);
        }
    }

    fn launch_process(&mut self, program: &str, args: &[&str]) {
        match Command::new(program).args(args).spawn() {
            Ok(_) => self.last_error = None,
            Err(err) => {
                self.last_error = Some(format!("Failed to launch {program}: {err}"));
            }
        }
    }

    fn show_host_editor(&mut self, ctx: &egui::Context) {
        let Some(editor) = &mut self.host_editor else {
            return;
        };

        let mut should_save = false;
        let mut should_cancel = false;

        egui::Window::new(editor.title())
            .collapsible(false)
            .resizable(true)
            .default_width(420.0)
            .show(ctx, |ui| {
                ui.label("Host name");
                ui.text_edit_singleline(&mut editor.server_name);
                ui.add_space(8.0);

                ui.label("OS");
                egui::ComboBox::from_id_salt("host_os_type")
                    .selected_text(&editor.os_type)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut editor.os_type, "Windows".to_string(), "Windows");
                        ui.selectable_value(&mut editor.os_type, "Linux".to_string(), "Linux");
                    });
                ui.add_space(8.0);

                ui.label("Group");
                ui.text_edit_singleline(&mut editor.group_name);
                ui.add_space(8.0);

                ui.label("Services, comma-separated");
                ui.text_edit_singleline(&mut editor.services);
                ui.add_space(8.0);

                ui.label("Notes");
                ui.add(
                    egui::TextEdit::multiline(&mut editor.notes)
                        .desired_rows(4)
                        .desired_width(f32::INFINITY),
                );

                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("Save").clicked() {
                        should_save = true;
                    }
                    if ui.button("Cancel").clicked() {
                        should_cancel = true;
                    }
                });
            });

        if should_cancel {
            self.host_editor = None;
        }

        if should_save {
            if let Some(editor) = self.host_editor.clone() {
                self.save_editor(editor);
            }
        }
    }

    fn show_delete_confirmation(&mut self, ctx: &egui::Context) {
        let Some(server_name) = self.confirm_delete_host.clone() else {
            return;
        };

        egui::Window::new("Delete host")
            .collapsible(false)
            .resizable(false)
            .default_width(360.0)
            .show(ctx, |ui| {
                ui.label(format!("Delete {server_name} from the host inventory?"));
                ui.label("Cached health data for this host will also be removed.");
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("Delete").clicked() {
                        self.delete_host(&server_name);
                    }
                    if ui.button("Cancel").clicked() {
                        self.confirm_delete_host = None;
                    }
                });
            });
    }
}

impl eframe::App for ConsoleApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.apply_theme(ctx);

        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading(APP_TITLE);
                ui.separator();

                let search = egui::TextEdit::singleline(&mut self.filter)
                    .hint_text("Filter hosts, groups, status, OS, services...")
                    .desired_width(320.0);
                ui.add(search);

                if ui.button("Refresh list").clicked() {
                    self.reload_hosts();
                }

                if ui
                    .add_enabled(self.selected_host.is_some(), egui::Button::new("Connect"))
                    .clicked()
                {
                    self.launch_selected();
                }

                ui.separator();

                if ui.button("Add host").clicked() {
                    self.open_add_host();
                }

                if ui
                    .add_enabled(self.selected_host.is_some(), egui::Button::new("Edit host"))
                    .clicked()
                {
                    self.open_edit_selected();
                }

                if ui
                    .add_enabled(self.selected_host.is_some(), egui::Button::new("Delete host"))
                    .clicked()
                {
                    self.request_delete_selected();
                }

                ui.separator();

                let theme_label = match self.theme_mode {
                    ThemeMode::Dark => "Light mode",
                    ThemeMode::Light => "Dark mode",
                };
                if ui.button(theme_label).clicked() {
                    self.toggle_theme();
                }
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            if let Some(error) = &self.last_error {
                ui.colored_label(egui::Color32::from_rgb(180, 50, 50), error);
                ui.separator();
            }

            let rows = self.visible_hosts();
            ui.horizontal(|ui| {
                ui.label(format!("{} hosts", rows.len()));
                if let Some(selected) = &self.selected_host {
                    ui.separator();
                    ui.label(format!("Selected: {selected}"));
                }
            });
            ui.separator();

            TableBuilder::new(ui)
                .striped(true)
                .resizable(true)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::auto().at_least(82.0))
                .column(Column::remainder().at_least(170.0))
                .column(Column::auto().at_least(80.0))
                .column(Column::auto().at_least(110.0))
                .column(Column::auto().at_least(72.0))
                .column(Column::auto().at_least(82.0))
                .column(Column::auto().at_least(72.0))
                .column(Column::auto().at_least(90.0))
                .column(Column::auto().at_least(145.0))
                .header(24.0, |mut header| {
                    header.col(|ui| sort_header(ui, "Status", self, SortColumn::Status));
                    header.col(|ui| sort_header(ui, "Host", self, SortColumn::Host));
                    header.col(|ui| sort_header(ui, "OS", self, SortColumn::Os));
                    header.col(|ui| sort_header(ui, "Group", self, SortColumn::Group));
                    header.col(|ui| sort_header(ui, "CPU", self, SortColumn::Cpu));
                    header.col(|ui| sort_header(ui, "Memory", self, SortColumn::Memory));
                    header.col(|ui| sort_header(ui, "Disk", self, SortColumn::Disk));
                    header.col(|ui| sort_header(ui, "Uptime", self, SortColumn::Uptime));
                    header.col(|ui| sort_header(ui, "Last checked", self, SortColumn::LastChecked));
                })
                .body(|body| {
                    body.rows(24.0, rows.len(), |mut row| {
                        let host = &rows[row.index()];
                        let selected =
                            self.selected_host.as_deref() == Some(host.server_name.as_str());

                        row.col(|ui| row_label(ui, selected, &host.status, || {}));
                        row.col(|ui| {
                            let response = ui.selectable_label(selected, &host.server_name);
                            if response.clicked() {
                                self.selected_host = Some(host.server_name.clone());
                            }
                            if response.double_clicked() {
                                self.selected_host = Some(host.server_name.clone());
                                self.launch_selected();
                            }
                        });
                        row.col(|ui| row_label(ui, selected, &host.os_type, || {}));
                        row.col(|ui| row_label(ui, selected, empty_dash(&host.group_name), || {}));
                        row.col(|ui| {
                            row_label(ui, selected, format_percent(host.cpu).as_str(), || {})
                        });
                        row.col(|ui| {
                            row_label(ui, selected, format_percent(host.memory).as_str(), || {})
                        });
                        row.col(|ui| {
                            row_label(ui, selected, format_percent(host.disk).as_str(), || {})
                        });
                        row.col(|ui| {
                            row_label(ui, selected, host.uptime.as_deref().unwrap_or("—"), || {})
                        });
                        row.col(|ui| {
                            row_label(
                                ui,
                                selected,
                                host.last_checked.as_deref().unwrap_or("—"),
                                || {},
                            )
                        });
                    });
                });
        });

        self.show_host_editor(ctx);
        self.show_delete_confirmation(ctx);
    }
}

fn sort_header(ui: &mut egui::Ui, label: &str, app: &mut ConsoleApp, column: SortColumn) {
    let arrow = if app.sort_column == column {
        match app.sort_direction {
            SortDirection::Asc => " ↑",
            SortDirection::Desc => " ↓",
        }
    } else {
        ""
    };

    if ui.button(format!("{label}{arrow}")).clicked() {
        app.set_sort(column);
    }
}

fn row_label(ui: &mut egui::Ui, selected: bool, text: &str, on_click: impl FnOnce()) {
    let response = ui.selectable_label(selected, text);
    if response.clicked() {
        on_click();
    }
}

fn empty_dash(value: &str) -> &str {
    if value.trim().is_empty() {
        "—"
    } else {
        value
    }
}

fn format_percent(value: Option<f64>) -> String {
    value
        .map(|number| format!("{number:.0}%"))
        .unwrap_or_else(|| "—".to_string())
}

fn compare_hosts(left: &HostRow, right: &HostRow, column: SortColumn) -> Ordering {
    match column {
        SortColumn::Status => left.status.cmp(&right.status),
        SortColumn::Host => cmp_text(&left.server_name, &right.server_name),
        SortColumn::Os => cmp_text(&left.os_type, &right.os_type),
        SortColumn::Group => cmp_text(&left.group_name, &right.group_name),
        SortColumn::Cpu => cmp_opt_f64(left.cpu, right.cpu),
        SortColumn::Memory => cmp_opt_f64(left.memory, right.memory),
        SortColumn::Disk => cmp_opt_f64(left.disk, right.disk),
        SortColumn::Uptime => left.uptime.cmp(&right.uptime),
        SortColumn::LastChecked => left.last_checked.cmp(&right.last_checked),
    }
}

fn cmp_text(left: &str, right: &str) -> Ordering {
    left.to_lowercase().cmp(&right.to_lowercase())
}

fn cmp_opt_f64(left: Option<f64>, right: Option<f64>) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => left.partial_cmp(&right).unwrap_or(Ordering::Equal),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

fn load_hosts() -> Result<Vec<HostRow>, String> {
    let conn = db::open_db().map_err(|err| err.to_string())?;
    db::init_schema(&conn).map_err(|err| err.to_string())?;
    query_hosts(&conn).map_err(|err| err.to_string())
}

fn save_host(editor: &HostEditor) -> Result<String, String> {
    let server_name = editor.server_name.trim();
    if server_name.is_empty() {
        return Err("Host name is required".to_string());
    }

    let os_type = normalize_os_type(&editor.os_type);
    let services_json = services_text_to_json(&editor.services)?;
    let mut conn = db::open_db().map_err(|err| err.to_string())?;
    db::init_schema(&conn).map_err(|err| err.to_string())?;

    let tx = conn.transaction().map_err(|err| err.to_string())?;
    if let Some(original_name) = editor.original_name.as_deref() {
        tx.execute(
            "UPDATE hosts
             SET server_name = ?1,
                 notes = ?2,
                 group_name = ?3,
                 os_type = ?4,
                 services = ?5
             WHERE server_name = ?6",
            params![
                server_name,
                empty_to_null(&editor.notes),
                empty_to_null(&editor.group_name),
                os_type,
                services_json,
                original_name
            ],
        )
        .map_err(|err| err.to_string())?;

        if !server_name.eq_ignore_ascii_case(original_name) {
            tx.execute(
                "UPDATE host_health SET server_name = ?1 WHERE UPPER(server_name) = UPPER(?2)",
                params![server_name, original_name],
            )
            .map_err(|err| err.to_string())?;
        }
    } else {
        tx.execute(
            "INSERT INTO hosts(server_name, notes, group_name, os_type, services)
             VALUES(?1, ?2, ?3, ?4, ?5)",
            params![
                server_name,
                empty_to_null(&editor.notes),
                empty_to_null(&editor.group_name),
                os_type,
                services_json
            ],
        )
        .map_err(|err| err.to_string())?;
    }

    tx.commit().map_err(|err| err.to_string())?;
    Ok(server_name.to_string())
}

fn delete_host(server_name: &str) -> Result<(), String> {
    let mut conn = db::open_db().map_err(|err| err.to_string())?;
    db::init_schema(&conn).map_err(|err| err.to_string())?;

    let tx = conn.transaction().map_err(|err| err.to_string())?;
    tx.execute(
        "DELETE FROM host_health WHERE UPPER(server_name) = UPPER(?1)",
        params![server_name],
    )
    .map_err(|err| err.to_string())?;
    tx.execute("DELETE FROM hosts WHERE server_name = ?1", params![server_name])
        .map_err(|err| err.to_string())?;
    tx.commit().map_err(|err| err.to_string())
}

fn query_hosts(conn: &Connection) -> rusqlite::Result<Vec<HostRow>> {
    let mut stmt = conn.prepare(
        "SELECT
            h.server_name,
            COALESCE(h.group_name, ''),
            COALESCE(h.os_type, 'Windows'),
            COALESCE(h.notes, ''),
            COALESCE(h.services, '[]'),
            hh.snapshot_json,
            hh.last_probed_at
         FROM hosts h
         LEFT JOIN host_health hh ON UPPER(h.server_name) = UPPER(hh.server_name)
         ORDER BY h.server_name COLLATE NOCASE",
    )?;

    let rows = stmt.query_map([], |row| {
        let snapshot_json: Option<String> = row.get(5)?;
        let snapshot = snapshot_json
            .as_deref()
            .and_then(|json| serde_json::from_str::<Value>(json).ok());
        let services_json: String = row.get(4)?;

        Ok(HostRow {
            server_name: row.get(0)?,
            group_name: row.get(1)?,
            os_type: row.get(2)?,
            notes: row.get(3)?,
            services: services_json_to_text(&services_json),
            status: derive_status(snapshot.as_ref()),
            cpu: find_number(
                snapshot.as_ref(),
                &["cpu_percent", "cpu_usage", "cpu_load", "cpu"],
            ),
            memory: find_number(
                snapshot.as_ref(),
                &[
                    "memory_percent",
                    "memory_usage",
                    "memory_used_percent",
                    "memory",
                ],
            ),
            disk: find_worst_disk(snapshot.as_ref()),
            uptime: find_string(
                snapshot.as_ref(),
                &["uptime", "uptime_human", "uptime_text"],
            ),
            last_checked: row.get(6)?,
        })
    })?;

    rows.collect()
}

fn normalize_os_type(os_type: &str) -> &'static str {
    if os_type.eq_ignore_ascii_case("linux") {
        "Linux"
    } else {
        "Windows"
    }
}

fn empty_to_null(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn services_text_to_json(value: &str) -> Result<String, String> {
    let services: Vec<String> = value
        .split(',')
        .map(str::trim)
        .filter(|service| !service.is_empty())
        .map(ToString::to_string)
        .collect();

    serde_json::to_string(&services).map_err(|err| err.to_string())
}

fn services_json_to_text(value: &str) -> String {
    serde_json::from_str::<Vec<String>>(value)
        .map(|services| services.join(", "))
        .unwrap_or_default()
}

fn derive_status(snapshot: Option<&Value>) -> String {
    let Some(snapshot) = snapshot else {
        return "Unknown".to_string();
    };

    if let Some(status) = find_string(Some(snapshot), &["status", "probe_status", "health_status"])
    {
        return status;
    }

    if find_string(Some(snapshot), &["error", "last_error", "message"]).is_some() {
        return "Failed".to_string();
    }

    "OK".to_string()
}

fn find_worst_disk(value: Option<&Value>) -> Option<f64> {
    let Some(value) = value else {
        return None;
    };

    let mut numbers = Vec::new();
    collect_numbers_by_key(
        value,
        &["disk_percent", "disk_usage", "used_percent", "percent_used"],
        &mut numbers,
    );
    numbers.into_iter().reduce(f64::max)
}

fn find_number(value: Option<&Value>, keys: &[&str]) -> Option<f64> {
    let Some(value) = value else {
        return None;
    };

    let mut numbers = Vec::new();
    collect_numbers_by_key(value, keys, &mut numbers);
    numbers.into_iter().next()
}

fn collect_numbers_by_key(value: &Value, keys: &[&str], numbers: &mut Vec<f64>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let normalized = key.to_lowercase();
                if keys.iter().any(|candidate| normalized.contains(candidate)) {
                    if let Some(number) = child.as_f64() {
                        numbers.push(number);
                    }
                }
                collect_numbers_by_key(child, keys, numbers);
            }
        }
        Value::Array(items) => {
            for child in items {
                collect_numbers_by_key(child, keys, numbers);
            }
        }
        _ => {}
    }
}

fn find_string(value: Option<&Value>, keys: &[&str]) -> Option<String> {
    let value = value?;
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let normalized = key.to_lowercase();
                if keys.iter().any(|candidate| normalized.contains(candidate)) {
                    if let Some(text) = child.as_str() {
                        return Some(text.to_string());
                    }
                }
                if let Some(found) = find_string(Some(child), keys) {
                    return Some(found);
                }
            }
            None
        }
        Value::Array(items) => items
            .iter()
            .find_map(|child| find_string(Some(child), keys)),
        _ => None,
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(APP_TITLE)
            .with_inner_size([1280.0, 760.0]),
        ..Default::default()
    };

    eframe::run_native(
        APP_TITLE,
        options,
        Box::new(|_cc| Ok(Box::<ConsoleApp>::default())),
    )
}
