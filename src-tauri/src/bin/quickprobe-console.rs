use eframe::egui;
use egui_extras::{Column, TableBuilder};
use quickprobe::db;
use rusqlite::Connection;
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

#[derive(Clone, Debug, Default)]
struct HostRow {
    server_name: String,
    group_name: String,
    os_type: String,
    notes: String,
    status: String,
    cpu: Option<f64>,
    memory: Option<f64>,
    disk: Option<f64>,
    uptime: Option<String>,
    last_checked: Option<String>,
}

struct ConsoleApp {
    hosts: Vec<HostRow>,
    filter: String,
    sort_column: SortColumn,
    sort_direction: SortDirection,
    selected_host: Option<String>,
    last_error: Option<String>,
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
}

impl eframe::App for ConsoleApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading(APP_TITLE);
                ui.separator();

                let search = egui::TextEdit::singleline(&mut self.filter)
                    .hint_text("Filter hosts, groups, status, OS...")
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

fn query_hosts(conn: &Connection) -> rusqlite::Result<Vec<HostRow>> {
    let mut stmt = conn.prepare(
        "SELECT
            h.server_name,
            COALESCE(h.group_name, ''),
            COALESCE(h.os_type, 'Windows'),
            COALESCE(h.notes, ''),
            hh.snapshot_json,
            hh.last_probed_at
         FROM hosts h
         LEFT JOIN host_health hh ON UPPER(h.server_name) = UPPER(hh.server_name)
         ORDER BY h.server_name COLLATE NOCASE",
    )?;

    let rows = stmt.query_map([], |row| {
        let snapshot_json: Option<String> = row.get(4)?;
        let snapshot = snapshot_json
            .as_deref()
            .and_then(|json| serde_json::from_str::<Value>(json).ok());

        Ok(HostRow {
            server_name: row.get(0)?,
            group_name: row.get(1)?,
            os_type: row.get(2)?,
            notes: row.get(3)?,
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
            last_checked: row.get(5)?,
        })
    })?;

    rows.collect()
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
