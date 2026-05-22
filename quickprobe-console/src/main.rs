#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use egui_extras::{Column, TableBuilder};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::Ordering;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

include!(concat!(env!("OUT_DIR"), "/quickprobe_console_font.rs"));

const APP_TITLE: &str = "QuickProbe Console";
const APP_NAME: &str = "QuickProbe";
const DB_FILE_NAME: &str = "quickprobe.db";
const CONSOLE_SETTINGS_FILE_NAME: &str = "quickprobe-console.json";
const CONSOLE_FONT_NAME: &str = "MesloLGS NF";

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
    Services,
    Notes,
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum ManualColor {
    Green,
    Orange,
    Red,
    Blue,
    White,
    Gray,
}

impl ManualColor {
    fn label(self) -> &'static str {
        match self {
            ManualColor::Green => "Green",
            ManualColor::Orange => "Orange",
            ManualColor::Red => "Red",
            ManualColor::Blue => "Blue",
            ManualColor::White => "White",
            ManualColor::Gray => "Gray",
        }
    }

    fn color(self) -> egui::Color32 {
        match self {
            ManualColor::Green => egui::Color32::from_rgb(64, 190, 110),
            ManualColor::Orange => egui::Color32::from_rgb(230, 165, 55),
            ManualColor::Red => egui::Color32::from_rgb(220, 75, 75),
            ManualColor::Blue => egui::Color32::from_rgb(80, 155, 230),
            ManualColor::White => egui::Color32::from_rgb(235, 235, 235),
            ManualColor::Gray => egui::Color32::from_rgb(150, 150, 150),
        }
    }
}

const MANUAL_COLORS: [ManualColor; 6] = [
    ManualColor::Green,
    ManualColor::Orange,
    ManualColor::Red,
    ManualColor::Blue,
    ManualColor::White,
    ManualColor::Gray,
];

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct ColumnColorOverrides {
    status: Option<ManualColor>,
    host: Option<ManualColor>,
    os: Option<ManualColor>,
    group: Option<ManualColor>,
    cpu: Option<ManualColor>,
    memory: Option<ManualColor>,
    disk: Option<ManualColor>,
    uptime: Option<ManualColor>,
    services: Option<ManualColor>,
    notes: Option<ManualColor>,
    last_checked: Option<ManualColor>,
}

impl ColumnColorOverrides {
    fn get(&self, column: SortColumn) -> Option<ManualColor> {
        match column {
            SortColumn::Status => self.status,
            SortColumn::Host => self.host,
            SortColumn::Os => self.os,
            SortColumn::Group => self.group,
            SortColumn::Cpu => self.cpu,
            SortColumn::Memory => self.memory,
            SortColumn::Disk => self.disk,
            SortColumn::Uptime => self.uptime,
            SortColumn::Services => self.services,
            SortColumn::Notes => self.notes,
            SortColumn::LastChecked => self.last_checked,
        }
    }

    fn set(&mut self, column: SortColumn, color: Option<ManualColor>) {
        match column {
            SortColumn::Status => self.status = color,
            SortColumn::Host => self.host = color,
            SortColumn::Os => self.os = color,
            SortColumn::Group => self.group = color,
            SortColumn::Cpu => self.cpu = color,
            SortColumn::Memory => self.memory = color,
            SortColumn::Disk => self.disk = color,
            SortColumn::Uptime => self.uptime = color,
            SortColumn::Services => self.services = color,
            SortColumn::Notes => self.notes = color,
            SortColumn::LastChecked => self.last_checked = color,
        }
    }
}

#[derive(Clone, Debug, Default)]
struct HostRow {
    server_name: String,
    group_name: String,
    os_type: String,
    notes: String,
    services: String,
    service_states: Vec<ServiceState>,
    status: String,
    cpu: Option<f64>,
    memory: Option<f64>,
    disk: Option<f64>,
    uptime: Option<String>,
    uptime_hours: Option<f64>,
    last_checked: Option<String>,
}

#[derive(Clone, Debug, Default)]
struct ServiceState {
    name: String,
    status: String,
}

impl HostRow {
    fn field_text(&self, column: SortColumn) -> String {
        match column {
            SortColumn::Status => self.status.clone(),
            SortColumn::Host => self.server_name.clone(),
            SortColumn::Os => self.os_type.clone(),
            SortColumn::Group => self.group_name.clone(),
            SortColumn::Cpu => format_percent(self.cpu),
            SortColumn::Memory => format_percent(self.memory),
            SortColumn::Disk => format_percent(self.disk),
            SortColumn::Uptime => self.uptime.clone().unwrap_or_else(|| "-".to_string()),
            SortColumn::Services => self.service_summary_text(),
            SortColumn::Notes => self.notes.clone(),
            SortColumn::LastChecked => self.last_checked.clone().unwrap_or_else(|| "-".to_string()),
        }
    }

    fn service_summary_text(&self) -> String {
        let monitored = split_services(&self.services);
        if monitored.is_empty() {
            return String::new();
        }

        monitored
            .into_iter()
            .map(|service| {
                let status = self
                    .service_states
                    .iter()
                    .find(|state| state.name.eq_ignore_ascii_case(&service))
                    .map(|state| state.status.as_str())
                    .unwrap_or("No status");
                format!("{service}: {status}")
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn matches_global_filter(&self, filter: &str) -> bool {
        filter.is_empty()
            || ALL_COLUMNS
                .iter()
                .any(|column| text_matches(&self.field_text(*column), filter))
    }
}

#[derive(Clone, Debug, Default)]
struct ColumnFilters {
    status: String,
    host: String,
    os: String,
    group: String,
    cpu: String,
    memory: String,
    disk: String,
    uptime: String,
    services: String,
    notes: String,
    last_checked: String,
}

impl ColumnFilters {
    fn clear(&mut self) {
        *self = Self::default();
    }

    fn has_any(&self) -> bool {
        self.values().iter().any(|value| !value.trim().is_empty())
    }

    fn values(&self) -> [&String; 11] {
        [
            &self.status,
            &self.host,
            &self.os,
            &self.group,
            &self.cpu,
            &self.memory,
            &self.disk,
            &self.uptime,
            &self.services,
            &self.notes,
            &self.last_checked,
        ]
    }

    fn matches(&self, host: &HostRow) -> bool {
        ALL_COLUMNS
            .iter()
            .zip(self.values())
            .all(|(column, filter)| text_matches(&host.field_text(*column), filter))
    }
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
    global_filter: String,
    column_filters: ColumnFilters,
    show_column_filters: bool,
    sort_column: SortColumn,
    sort_direction: SortDirection,
    selected_host: Option<String>,
    last_error: Option<String>,
    last_status: Option<String>,
    theme_mode: ThemeMode,
    host_editor: Option<HostEditor>,
    confirm_delete_host: Option<String>,
    probing_host: Option<String>,
    probe_receiver: Option<Receiver<ProbeResult>>,
    column_colors: ColumnColorOverrides,
}

type ProbeResult = Result<String, String>;

#[derive(Clone, Debug)]
struct ProbeRequest {
    server_name: String,
    os_type: String,
    services: Vec<String>,
}

const ALL_COLUMNS: [SortColumn; 11] = [
    SortColumn::Status,
    SortColumn::Host,
    SortColumn::Os,
    SortColumn::Group,
    SortColumn::Cpu,
    SortColumn::Memory,
    SortColumn::Disk,
    SortColumn::Uptime,
    SortColumn::Services,
    SortColumn::Notes,
    SortColumn::LastChecked,
];

impl Default for ConsoleApp {
    fn default() -> Self {
        let mut app = Self {
            hosts: Vec::new(),
            global_filter: String::new(),
            column_filters: ColumnFilters::default(),
            show_column_filters: true,
            sort_column: SortColumn::Host,
            sort_direction: SortDirection::Asc,
            selected_host: None,
            last_error: None,
            last_status: None,
            theme_mode: ThemeMode::Dark,
            host_editor: None,
            confirm_delete_host: None,
            probing_host: None,
            probe_receiver: None,
            column_colors: load_column_color_overrides(),
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

    fn poll_probe_result(&mut self) {
        let Some(receiver) = &self.probe_receiver else {
            return;
        };

        match receiver.try_recv() {
            Ok(Ok(server_name)) => {
                self.probing_host = None;
                self.probe_receiver = None;
                self.reload_hosts();
                self.last_status = Some(format!("Full probe completed for {server_name}."));
                self.last_error = None;
            }
            Ok(Err(err)) => {
                let host = self
                    .probing_host
                    .as_deref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "selected host".to_string());
                self.last_error = Some(format!("Full probe failed for {host}: {err}"));
                self.last_status = None;
                self.probing_host = None;
                self.probe_receiver = None;
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                self.last_error =
                    Some("Full probe worker stopped before returning a result.".to_string());
                self.last_status = None;
                self.probing_host = None;
                self.probe_receiver = None;
            }
        }
    }

    fn visible_hosts(&self) -> Vec<HostRow> {
        let global_filter = self.global_filter.trim().to_lowercase();
        let mut rows: Vec<_> = self
            .hosts
            .iter()
            .filter(|host| host.matches_global_filter(&global_filter))
            .filter(|host| self.column_filters.matches(host))
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

    fn show_top_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.heading(APP_TITLE);
                ui.separator();

                ui.label("Search");
                ui.add(
                    egui::TextEdit::singleline(&mut self.global_filter)
                        .hint_text("Filter across all columns...")
                        .desired_width(300.0),
                );

                if ui.button("Refresh").clicked() {
                    self.reload_hosts();
                }

                if ui
                    .add_enabled(self.selected_host.is_some(), egui::Button::new("Connect"))
                    .clicked()
                {
                    self.launch_selected();
                }

                ui.separator();

                if ui.button("Add").clicked() {
                    self.open_add_host();
                }

                if ui
                    .add_enabled(self.selected_host.is_some(), egui::Button::new("Edit"))
                    .clicked()
                {
                    self.open_edit_selected();
                }

                if ui
                    .add_enabled(self.selected_host.is_some(), egui::Button::new("Delete"))
                    .clicked()
                {
                    self.request_delete_selected();
                }

                ui.separator();
                ui.checkbox(&mut self.show_column_filters, "Column filters");

                let filters_active =
                    !self.global_filter.is_empty() || self.column_filters.has_any();
                if ui
                    .add_enabled(filters_active, egui::Button::new("Clear filters"))
                    .clicked()
                {
                    self.global_filter.clear();
                    self.column_filters.clear();
                }

                let theme_label = match self.theme_mode {
                    ThemeMode::Dark => "Light mode",
                    ThemeMode::Light => "Dark mode",
                };
                if ui.button(theme_label).clicked() {
                    self.toggle_theme();
                }
            });
        });
    }

    fn show_status_bar(&self, ui: &mut egui::Ui, visible_count: usize) {
        let ok = self
            .hosts
            .iter()
            .filter(|host| host.status.eq_ignore_ascii_case("ok"))
            .count();
        let other = self.hosts.len().saturating_sub(ok);
        let monitored_services: usize = self
            .hosts
            .iter()
            .map(|host| split_services(&host.services).len())
            .sum();
        let hosts_with_uptime = self
            .hosts
            .iter()
            .filter(|host| host.uptime.is_some())
            .count();

        ui.horizontal(|ui| {
            ui.strong(format!("{visible_count} shown"));
            ui.label(format!("{} total", self.hosts.len()));
            ui.separator();
            ui.label(format!("{ok} OK"));
            ui.label(format!("{other} other"));
            ui.separator();
            ui.label(format!("{monitored_services} monitored services"));
            ui.label(format!("{hosts_with_uptime} with uptime"));
            if let Some(selected) = &self.selected_host {
                ui.separator();
                ui.label(format!("Selected: {selected}"));
            }
        });
    }

    fn show_details_panel(&mut self, ctx: &egui::Context) {
        let mut full_probe_request = None;

        egui::SidePanel::right("host_details")
            .resizable(true)
            .default_width(320.0)
            .width_range(260.0..=460.0)
            .show(ctx, |ui| {
                ui.heading("Host details");
                ui.separator();

                let Some(selected) = self.selected_host.as_deref() else {
                    ui.label("Select a host to see uptime and monitored services.");
                    return;
                };

                let Some(host) = self.hosts.iter().find(|host| host.server_name == selected) else {
                    ui.label("Selected host is no longer available.");
                    return;
                };

                ui.strong(&host.server_name);
                ui.label(format!("Status: {}", host.status));
                if !host.group_name.is_empty() {
                    ui.label(format!("Group: {}", host.group_name));
                }
                ui.label(format!("OS: {}", host.os_type));
                ui.add_space(8.0);

                detail_row(ui, "Uptime", host.uptime.as_deref().unwrap_or("Unknown"));
                detail_row(
                    ui,
                    "Last probe",
                    host.last_checked.as_deref().unwrap_or("Never"),
                );
                let is_probing = self.probing_host.as_deref() == Some(host.server_name.as_str());
                let probe_label = if is_probing {
                    "Full probe running..."
                } else {
                    "Full probe"
                };
                if ui
                    .add_enabled(self.probing_host.is_none(), egui::Button::new(probe_label))
                    .clicked()
                {
                    full_probe_request = Some(host.server_name.clone());
                }

                ui.separator();
                ui.strong("Monitored services");
                let monitored = split_services(&host.services);
                if monitored.is_empty() {
                    ui.label("No services configured for monitoring.");
                } else {
                    for service in monitored {
                        let status = host
                            .service_states
                            .iter()
                            .find(|state| state.name.eq_ignore_ascii_case(&service))
                            .map(|state| state.status.as_str())
                            .unwrap_or("No latest status");
                        ui.horizontal_wrapped(|ui| {
                            ui.monospace(&service);
                            ui.label(status);
                        });
                    }
                }

                if !host.notes.is_empty() {
                    ui.separator();
                    ui.strong("Notes");
                    ui.label(&host.notes);
                }

                ui.separator();
                ui.strong("Column text colors");
                ui.small("Default keeps health-based coloring where available.");
                let mut colors_changed = false;
                for column in ALL_COLUMNS {
                    colors_changed |= column_color_picker(ui, column, &mut self.column_colors);
                }
                if ui.button("Reset column colors").clicked() {
                    self.column_colors = ColumnColorOverrides::default();
                    colors_changed = true;
                }
                if colors_changed {
                    if let Err(err) = save_column_color_overrides(&self.column_colors) {
                        self.last_error = Some(err);
                    }
                }
            });

        if let Some(server_name) = full_probe_request {
            self.launch_full_probe(&server_name);
        }
    }

    fn launch_full_probe(&mut self, server_name: &str) {
        if self.probing_host.is_some() {
            return;
        }

        let Some(host) = self
            .hosts
            .iter()
            .find(|host| host.server_name == server_name)
        else {
            self.last_error = Some(format!("Host not found: {server_name}"));
            return;
        };

        let request = ProbeRequest {
            server_name: host.server_name.clone(),
            os_type: host.os_type.clone(),
            services: split_services(&host.services),
        };
        let (sender, receiver) = mpsc::channel();
        self.probing_host = Some(request.server_name.clone());
        self.probe_receiver = Some(receiver);
        self.last_error = None;
        self.last_status = Some(format!("Full probe started for {}.", request.server_name));

        thread::spawn(move || {
            let result = run_full_probe(request);
            let _ = sender.send(result);
        });
    }

    fn show_table(&mut self, ui: &mut egui::Ui, rows: &[HostRow]) {
        let header_height = if self.show_column_filters { 52.0 } else { 26.0 };
        let filters = self.column_filters.values();
        let mut header_filters = filters.map(String::clone);
        let mut sort_request = None;
        let mut selected_request = None;
        let mut connect_request = None;

        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::auto().at_least(86.0))
            .column(Column::remainder().at_least(180.0))
            .column(Column::auto().at_least(80.0))
            .column(Column::auto().at_least(130.0))
            .column(Column::auto().at_least(76.0))
            .column(Column::auto().at_least(90.0))
            .column(Column::auto().at_least(76.0))
            .column(Column::auto().at_least(90.0))
            .column(Column::auto().at_least(150.0))
            .column(Column::auto().at_least(180.0))
            .column(Column::auto().at_least(150.0))
            .header(header_height, |mut header| {
                for (index, column) in ALL_COLUMNS.iter().enumerate() {
                    header.col(|ui| {
                        if column_header(
                            ui,
                            column_label(*column),
                            *column,
                            self.show_column_filters,
                            self.sort_column,
                            self.sort_direction,
                            &mut header_filters[index],
                        ) {
                            sort_request = Some(*column);
                        }
                    });
                }
            })
            .body(|body| {
                body.rows(25.0, rows.len(), |mut row| {
                    let host = &rows[row.index()];
                    let selected = self.selected_host.as_deref() == Some(host.server_name.as_str());

                    for column in ALL_COLUMNS {
                        row.col(|ui| {
                            row_label(
                                ui,
                                selected,
                                &host.field_text(column),
                                column,
                                host,
                                &self.column_colors,
                                &mut selected_request,
                                &mut connect_request,
                            );
                        });
                    }
                });
            });

        self.column_filters = ColumnFilters::from_values(header_filters);

        if let Some(column) = sort_request {
            self.set_sort(column);
        }
        if let Some(server_name) = selected_request {
            self.selected_host = Some(server_name);
        }
        if let Some(server_name) = connect_request {
            self.selected_host = Some(server_name);
            self.launch_selected();
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
            .default_width(460.0)
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
            .default_width(380.0)
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

impl ColumnFilters {
    fn from_values(values: [String; 11]) -> Self {
        let [status, host, os, group, cpu, memory, disk, uptime, services, notes, last_checked] =
            values;

        Self {
            status,
            host,
            os,
            group,
            cpu,
            memory,
            disk,
            uptime,
            services,
            notes,
            last_checked,
        }
    }
}

impl eframe::App for ConsoleApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_probe_result();
        self.apply_theme(ctx);
        self.show_top_bar(ctx);
        self.show_details_panel(ctx);

        egui::CentralPanel::default().show(ctx, |ui| {
            if let Some(status) = &self.last_status {
                ui.colored_label(egui::Color32::from_rgb(64, 190, 110), status);
                ui.separator();
            }
            if let Some(error) = &self.last_error {
                ui.colored_label(egui::Color32::from_rgb(180, 50, 50), error);
                ui.separator();
            }

            let rows = self.visible_hosts();
            self.show_status_bar(ui, rows.len());
            ui.separator();
            self.show_table(ui, &rows);
        });

        self.show_host_editor(ctx);
        self.show_delete_confirmation(ctx);
    }
}

fn configure_fonts(ctx: &egui::Context) {
    let Some(font_bytes) = QUICKPROBE_CONSOLE_FONT_BYTES else {
        return;
    };

    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        CONSOLE_FONT_NAME.to_string(),
        egui::FontData::from_static(font_bytes).into(),
    );

    for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
        fonts
            .families
            .entry(family)
            .or_default()
            .insert(0, CONSOLE_FONT_NAME.to_string());
    }

    ctx.set_fonts(fonts);
}

fn load_window_icon() -> egui::IconData {
    eframe::icon_data::from_png_bytes(include_bytes!("../../src-tauri/icons/icon.png"))
        .unwrap_or_default()
}

fn column_header(
    ui: &mut egui::Ui,
    label: &str,
    column: SortColumn,
    show_filter: bool,
    sort_column: SortColumn,
    sort_direction: SortDirection,
    filter: &mut String,
) -> bool {
    let sort_marker = if sort_column == column {
        match sort_direction {
            SortDirection::Asc => " +",
            SortDirection::Desc => " -",
        }
    } else {
        ""
    };

    let clicked = ui.button(format!("{label}{sort_marker}")).clicked();

    if show_filter {
        ui.add(
            egui::TextEdit::singleline(filter)
                .hint_text("filter")
                .desired_width(f32::INFINITY),
        );
    }

    clicked
}

fn row_label(
    ui: &mut egui::Ui,
    selected: bool,
    text: &str,
    column: SortColumn,
    host: &HostRow,
    column_colors: &ColumnColorOverrides,
    selected_request: &mut Option<String>,
    connect_request: &mut Option<String>,
) {
    let mut text = egui::RichText::new(text);
    if let Some(color) = cell_color(host, column, column_colors) {
        text = text.color(color);
    }
    let response = ui
        .selectable_label(selected, text)
        .on_hover_text(host.field_text(column));
    if response.clicked() {
        *selected_request = Some(host.server_name.clone());
    }
    if response.double_clicked() {
        *connect_request = Some(host.server_name.clone());
    }
}

fn column_color_picker(
    ui: &mut egui::Ui,
    column: SortColumn,
    overrides: &mut ColumnColorOverrides,
) -> bool {
    let mut changed = false;
    ui.horizontal(|ui| {
        ui.label(column_label(column));
        let selected = overrides
            .get(column)
            .map(ManualColor::label)
            .unwrap_or("Default");
        egui::ComboBox::from_id_salt(format!("column_color_{}", column_label(column)))
            .selected_text(selected)
            .show_ui(ui, |ui| {
                if ui
                    .selectable_label(overrides.get(column).is_none(), "Default")
                    .clicked()
                {
                    overrides.set(column, None);
                    changed = true;
                }
                for color in MANUAL_COLORS {
                    let selected = overrides.get(column) == Some(color);
                    let label = egui::RichText::new(color.label()).color(color.color());
                    if ui.selectable_label(selected, label).clicked() {
                        overrides.set(column, Some(color));
                        changed = true;
                    }
                }
            });
    });
    changed
}

fn cell_color(
    host: &HostRow,
    column: SortColumn,
    column_colors: &ColumnColorOverrides,
) -> Option<egui::Color32> {
    if let Some(color) = column_colors.get(column) {
        return Some(color.color());
    }

    match column {
        SortColumn::Status => Some(status_color(&host.status)),
        SortColumn::Cpu => Some(percent_color(host.cpu, 85.0, 70.0)),
        SortColumn::Memory => Some(percent_color(host.memory, 90.0, 75.0)),
        SortColumn::Disk => Some(percent_color(host.disk, 90.0, 80.0)),
        SortColumn::Services => Some(services_color(host)),
        _ => None,
    }
}

fn status_color(status: &str) -> egui::Color32 {
    let status = status.to_lowercase();
    if status.contains("ok") || status.contains("running") || status.contains("online") {
        egui::Color32::from_rgb(64, 190, 110)
    } else if status.contains("unknown")
        || status.contains("cached")
        || status.contains("warn")
        || status.contains("no status")
    {
        egui::Color32::from_rgb(230, 165, 55)
    } else {
        egui::Color32::from_rgb(220, 75, 75)
    }
}

fn percent_color(value: Option<f64>, red_at: f64, orange_at: f64) -> egui::Color32 {
    match value {
        Some(value) if value >= red_at => egui::Color32::from_rgb(220, 75, 75),
        Some(value) if value >= orange_at => egui::Color32::from_rgb(230, 165, 55),
        Some(_) => egui::Color32::from_rgb(64, 190, 110),
        None => egui::Color32::from_rgb(230, 165, 55),
    }
}

fn services_color(host: &HostRow) -> egui::Color32 {
    let monitored = split_services(&host.services);
    if monitored.is_empty() {
        return egui::Color32::from_rgb(230, 165, 55);
    }

    let mut has_unknown = false;
    for service in monitored {
        let Some(state) = host
            .service_states
            .iter()
            .find(|state| state.name.eq_ignore_ascii_case(&service))
        else {
            has_unknown = true;
            continue;
        };

        if !state.status.eq_ignore_ascii_case("running") {
            return egui::Color32::from_rgb(220, 75, 75);
        }
    }

    if has_unknown {
        egui::Color32::from_rgb(230, 165, 55)
    } else {
        egui::Color32::from_rgb(64, 190, 110)
    }
}

fn detail_row(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.horizontal_wrapped(|ui| {
        ui.label(label);
        ui.strong(value);
    });
}

fn column_label(column: SortColumn) -> &'static str {
    match column {
        SortColumn::Status => "Status",
        SortColumn::Host => "Host",
        SortColumn::Os => "OS",
        SortColumn::Group => "Group",
        SortColumn::Cpu => "CPU",
        SortColumn::Memory => "Memory",
        SortColumn::Disk => "Disk",
        SortColumn::Uptime => "Uptime",
        SortColumn::Services => "Services",
        SortColumn::Notes => "Notes",
        SortColumn::LastChecked => "Last checked",
    }
}

fn text_matches(value: &str, filter: &str) -> bool {
    let filter = filter.trim().to_lowercase();
    filter.is_empty() || value.to_lowercase().contains(&filter)
}

fn format_percent(value: Option<f64>) -> String {
    value
        .map(|number| format!("{number:.0}%"))
        .unwrap_or_else(|| "-".to_string())
}

fn compare_hosts(left: &HostRow, right: &HostRow, column: SortColumn) -> Ordering {
    match column {
        SortColumn::Cpu => cmp_opt_f64(left.cpu, right.cpu),
        SortColumn::Memory => cmp_opt_f64(left.memory, right.memory),
        SortColumn::Disk => cmp_opt_f64(left.disk, right.disk),
        SortColumn::Uptime => cmp_opt_f64(left.uptime_hours, right.uptime_hours),
        _ => cmp_text(&left.field_text(column), &right.field_text(column)),
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

fn get_appdata_dir() -> Result<PathBuf, String> {
    let app_data = std::env::var("APPDATA")
        .map_err(|_| "APPDATA environment variable not found".to_string())?;
    let target = PathBuf::from(app_data).join(APP_NAME);
    fs::create_dir_all(&target).map_err(|err| err.to_string())?;
    Ok(target)
}

fn get_db_path() -> Result<PathBuf, String> {
    Ok(get_appdata_dir()?.join(DB_FILE_NAME))
}

fn get_console_settings_path() -> Result<PathBuf, String> {
    Ok(get_appdata_dir()?.join(CONSOLE_SETTINGS_FILE_NAME))
}

fn load_column_color_overrides() -> ColumnColorOverrides {
    let Ok(path) = get_console_settings_path() else {
        return ColumnColorOverrides::default();
    };
    let Ok(text) = fs::read_to_string(path) else {
        return ColumnColorOverrides::default();
    };

    serde_json::from_str(&text).unwrap_or_default()
}

fn save_column_color_overrides(overrides: &ColumnColorOverrides) -> Result<(), String> {
    let path = get_console_settings_path()?;
    let text = serde_json::to_string_pretty(overrides)
        .map_err(|err| format!("Failed to serialize console settings: {err}"))?;
    fs::write(path, text).map_err(|err| format!("Failed to save console settings: {err}"))
}

fn open_db() -> Result<Connection, String> {
    let db_path = get_db_path()?;
    let conn = Connection::open(db_path).map_err(|err| err.to_string())?;
    conn.busy_timeout(Duration::from_millis(5_000))
        .map_err(|err| err.to_string())?;
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(|err| err.to_string())?;
    conn.pragma_update(None, "synchronous", "FULL")
        .map_err(|err| err.to_string())?;
    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(|err| err.to_string())?;
    Ok(conn)
}

fn run_full_probe(request: ProbeRequest) -> ProbeResult {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|err| format!("Failed to start probe runtime: {err}"))?;
    runtime.block_on(run_full_probe_async(request))
}

async fn run_full_probe_async(request: ProbeRequest) -> ProbeResult {
    let summary = if request.os_type.eq_ignore_ascii_case("linux") {
        run_linux_full_probe(&request).await?
    } else {
        run_windows_full_probe(&request).await?
    };

    let snapshot_json = serde_json::to_string(&summary)
        .map_err(|err| format!("Failed to serialize probe result: {err}"))?;
    let conn = open_db()?;
    init_schema(&conn)?;
    quickprobe::db::save_health_snapshot(&conn, &request.server_name, &snapshot_json)
        .map_err(|err| format!("Failed to save probe result: {err}"))?;
    Ok(request.server_name)
}

#[cfg(windows)]
async fn run_windows_full_probe(
    request: &ProbeRequest,
) -> Result<quickprobe::core::SystemHealthSummary, String> {
    let credentials = resolve_probe_credentials(&request.server_name).await?;
    let session = quickprobe::platform::WindowsRemoteSession::connect(
        request.server_name.clone(),
        credentials,
    )
    .await?;
    let services = if request.services.is_empty() {
        None
    } else {
        Some(request.services.as_slice())
    };

    session.collect_system_health(services, 10.0).await
}

#[cfg(not(windows))]
async fn run_windows_full_probe(
    _request: &ProbeRequest,
) -> Result<quickprobe::core::SystemHealthSummary, String> {
    Err("Windows probing is only available on Windows.".to_string())
}

#[cfg(windows)]
async fn run_linux_full_probe(
    request: &ProbeRequest,
) -> Result<quickprobe::core::SystemHealthSummary, String> {
    let credentials = resolve_probe_credentials(&request.server_name).await?;
    let session =
        quickprobe::platform::LinuxRemoteSession::connect(request.server_name.clone(), credentials)
            .await?;
    let services = if request.services.is_empty() {
        None
    } else {
        Some(request.services.as_slice())
    };

    quickprobe::core::system_health_probe(&session, services, 10.0).await
}

#[cfg(not(windows))]
async fn run_linux_full_probe(
    _request: &ProbeRequest,
) -> Result<quickprobe::core::SystemHealthSummary, String> {
    Err("Linux probing is only available in Windows console builds for now.".to_string())
}

#[cfg(windows)]
async fn resolve_probe_credentials(server_name: &str) -> Result<quickprobe::Credentials, String> {
    use quickprobe::CredentialStore;

    let store = quickprobe::platform::WindowsCredentialManager::new();
    for profile in credential_profiles(server_name) {
        if let Some(credentials) = store
            .retrieve(&profile)
            .await
            .map_err(|err| format!("Failed to retrieve credentials: {err}"))?
        {
            return Ok(credentials);
        }
    }

    Err(format!(
        "No credentials found for {server_name}. Save host, RDP, or default QuickProbe credentials first."
    ))
}

#[cfg(windows)]
fn credential_profiles(server_name: &str) -> Vec<quickprobe::CredentialProfile> {
    let normalized = server_name.trim().to_uppercase();
    let short = normalized.split('.').next().unwrap_or(&normalized);
    let mut profiles = Vec::new();
    let mut seen = Vec::<String>::new();

    for target in [
        format!("QuickProbe:HOST/{short}"),
        format!("TERMSRV/{server_name}"),
        format!("TERMSRV/{short}"),
        format!("TERMSRV/{short}:3389"),
        quickprobe::CredentialProfile::DEFAULT.to_string(),
    ] {
        let key = target.to_lowercase();
        if !seen.iter().any(|existing| existing == &key) {
            seen.push(key);
            profiles.push(quickprobe::CredentialProfile::new(target));
        }
    }

    profiles
}

fn init_schema(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS hosts (
            server_name TEXT PRIMARY KEY,
            notes TEXT,
            group_name TEXT,
            os_type TEXT NOT NULL DEFAULT 'Windows',
            services TEXT
        );

        CREATE TABLE IF NOT EXISTS host_health (
            server_name TEXT PRIMARY KEY,
            snapshot_json TEXT NOT NULL,
            last_probed_at TEXT NOT NULL
        );
        ",
    )
    .map_err(|err| err.to_string())
}

fn load_hosts() -> Result<Vec<HostRow>, String> {
    let conn = open_db()?;
    init_schema(&conn)?;
    query_hosts(&conn).map_err(|err| err.to_string())
}

fn save_host(editor: &HostEditor) -> Result<String, String> {
    let server_name = editor.server_name.trim();
    if server_name.is_empty() {
        return Err("Host name is required".to_string());
    }

    let os_type = normalize_os_type(&editor.os_type);
    let services_value = services_text_to_storage(&editor.services)?;
    let mut conn = open_db()?;
    init_schema(&conn)?;

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
                services_value,
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
                services_value
            ],
        )
        .map_err(|err| err.to_string())?;
    }

    tx.commit().map_err(|err| err.to_string())?;
    Ok(server_name.to_string())
}

fn delete_host(server_name: &str) -> Result<(), String> {
    let mut conn = open_db()?;
    init_schema(&conn)?;

    let tx = conn.transaction().map_err(|err| err.to_string())?;
    tx.execute(
        "DELETE FROM host_health WHERE UPPER(server_name) = UPPER(?1)",
        params![server_name],
    )
    .map_err(|err| err.to_string())?;
    tx.execute(
        "DELETE FROM hosts WHERE server_name = ?1",
        params![server_name],
    )
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
        let services_value: String = row.get(4)?;

        Ok(HostRow {
            server_name: row.get(0)?,
            group_name: row.get(1)?,
            os_type: row.get(2)?,
            notes: row.get(3)?,
            services: services_to_text(&services_value),
            service_states: collect_service_states(snapshot.as_ref()),
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
            uptime: find_uptime(snapshot.as_ref()),
            uptime_hours: find_number(snapshot.as_ref(), &["uptime_hours"]),
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

fn services_text_to_storage(value: &str) -> Result<String, String> {
    Ok(parse_services(value).join(";"))
}

fn services_to_text(value: &str) -> String {
    parse_services(value).join(", ")
}

fn split_services(value: &str) -> Vec<String> {
    parse_services(value)
}

fn parse_services(value: &str) -> Vec<String> {
    if let Ok(services) = serde_json::from_str::<Vec<String>>(value) {
        return clean_services(services);
    }

    clean_services(
        value
            .split([';', ',', '\n'])
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
    )
}

fn clean_services<I>(services: I) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    let mut seen = Vec::<String>::new();
    services
        .into_iter()
        .map(|service| service.trim().to_string())
        .filter(|service| !service.is_empty())
        .map(|service| service.to_uppercase())
        .filter(|service| {
            let key = service.to_lowercase();
            if seen.iter().any(|existing| existing == &key) {
                false
            } else {
                seen.push(key);
                true
            }
        })
        .collect()
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

fn find_uptime(value: Option<&Value>) -> Option<String> {
    if let Some(text) = find_string(value, &["uptime_display", "uptime_human", "uptime_text"]) {
        return Some(text);
    }

    if let Some(hours) = find_number(value, &["uptime_hours"]) {
        return Some(format_uptime_hours(hours));
    }

    find_string(value, &["uptime"])
}

fn format_uptime_hours(hours: f64) -> String {
    if !hours.is_finite() || hours < 0.0 {
        return "Unknown".to_string();
    }

    if hours < 1.0 {
        let minutes = (hours * 60.0).round().max(1.0) as u64;
        return format!("{minutes}m");
    }

    let total_hours = hours.round() as u64;
    let days = total_hours / 24;
    let remainder_hours = total_hours % 24;

    if days > 0 {
        format!("{days}d {remainder_hours}h")
    } else {
        format!("{remainder_hours}h")
    }
}

fn collect_service_states(value: Option<&Value>) -> Vec<ServiceState> {
    let Some(value) = value else {
        return Vec::new();
    };

    let mut states = Vec::new();
    collect_service_states_from_value(value, &mut states);
    states
}

fn collect_service_states_from_value(value: &Value, states: &mut Vec<ServiceState>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if key.eq_ignore_ascii_case("service_status") {
                    if let Value::Array(items) = child {
                        for item in items {
                            if let Some(state) = service_state_from_value(item) {
                                states.push(state);
                            }
                        }
                    }
                }
                collect_service_states_from_value(child, states);
            }
        }
        Value::Array(items) => {
            for child in items {
                collect_service_states_from_value(child, states);
            }
        }
        _ => {}
    }
}

fn service_state_from_value(value: &Value) -> Option<ServiceState> {
    let Value::Object(map) = value else {
        return None;
    };

    let name = map
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();

    if name.is_empty() {
        return None;
    }

    Some(ServiceState {
        name,
        status: map
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("Unknown")
            .to_string(),
    })
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
            .with_icon(load_window_icon())
            .with_inner_size([1480.0, 820.0]),
        ..Default::default()
    };

    eframe::run_native(
        APP_TITLE,
        options,
        Box::new(|cc| {
            configure_fonts(&cc.egui_ctx);
            Ok(Box::<ConsoleApp>::default())
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_services_accepts_main_app_semicolon_storage() {
        assert_eq!(
            parse_services("NETLOGON;DNS;KDC;NTDS;DFSR;W32TIME;WINRM"),
            vec!["NETLOGON", "DNS", "KDC", "NTDS", "DFSR", "W32TIME", "WINRM"]
        );
    }

    #[test]
    fn parse_services_accepts_json_array_storage() {
        assert_eq!(
            parse_services(r#"["WinRM","dns","WinRM"]"#),
            vec!["WINRM", "DNS"]
        );
    }

    #[test]
    fn format_uptime_keeps_short_uptimes_visible() {
        assert_eq!(format_uptime_hours(0.17), "10m");
        assert_eq!(format_uptime_hours(4.31), "4h");
        assert_eq!(format_uptime_hours(641.9), "26d 18h");
    }
}
