// Copyright 2021-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use crate::remote_config::TracerFlareConfigCallback;
use arc_swap::{ArcSwap, ArcSwapOption};
use libdd_common::Endpoint;
use libdd_common_ffi::slice::AsBytes;
use libdd_common_ffi::CharSlice;
use libdd_remote_config::RemoteConfigParsed;
use libdd_tracer_flare::{FlareAction, LogLevel, TracerFlareManager};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashSet};
use std::ffi::c_void;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Write};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use tracing::{debug, error, info};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

#[derive(Clone)]
struct LogSettings {
    level: String,
    once: bool,
}

struct CaptureFile {
    file: File,
    write_lock: Mutex<()>,
}

struct FlareState {
    agent_url: String,
    manager: TracerFlareManager,
    original_log_settings: Option<LogSettings>,
    effective_log_level: Option<String>,
    active_config_ids: HashSet<String>,
    handled_uuids: HashSet<String>,
    flare_dir: Option<PathBuf>,
}

impl FlareState {
    fn new(agent_url: String) -> Self {
        Self {
            manager: TracerFlareManager::new(&agent_url, "php"),
            agent_url,
            original_log_settings: None,
            effective_log_level: None,
            active_config_ids: HashSet::new(),
            handled_uuids: HashSet::new(),
            flare_dir: None,
        }
    }
}

static FLARE_STATE: OnceLock<ArcSwap<Mutex<FlareState>>> = OnceLock::new();
static FLARE_AGENT_URL: OnceLock<ArcSwapOption<String>> = OnceLock::new();
static CAPTURE_FILE: OnceLock<ArcSwapOption<CaptureFile>> = OnceLock::new();
static CAPTURE_ACTIVE: AtomicBool = AtomicBool::new(false);
static CAPTURE_WRITERS: AtomicUsize = AtomicUsize::new(0);
static FLARE_STATE_PID: AtomicU32 = AtomicU32::new(0);

fn state_slot() -> &'static ArcSwap<Mutex<FlareState>> {
    FLARE_STATE.get_or_init(|| ArcSwap::from_pointee(Mutex::new(FlareState::new(String::new()))))
}

fn agent_url_slot() -> &'static ArcSwapOption<String> {
    FLARE_AGENT_URL.get_or_init(|| ArcSwapOption::from(None))
}

fn capture_file_slot() -> &'static ArcSwapOption<CaptureFile> {
    CAPTURE_FILE.get_or_init(|| ArcSwapOption::from(None))
}

fn current_state() -> Arc<Mutex<FlareState>> {
    let pid = std::process::id();
    if FLARE_STATE_PID.load(Ordering::Acquire) != pid {
        after_fork();
    }
    state_slot().load_full()
}

pub fn initialize(endpoint: &Endpoint) {
    let (Some(scheme), Some(authority)) = (endpoint.url.scheme_str(), endpoint.url.authority())
    else {
        debug!("Unable to derive tracer flare agent URL from remote config endpoint");
        return;
    };
    let agent_url = format!("{scheme}://{authority}");
    if FLARE_STATE_PID.load(Ordering::Acquire) != std::process::id() {
        after_fork();
    }
    if agent_url_slot()
        .load_full()
        .is_some_and(|current| current.as_str() == agent_url.as_str())
    {
        return;
    }
    process_unset(None);
    agent_url_slot().store(Some(Arc::new(agent_url.clone())));
    state_slot().store(Arc::new(Mutex::new(FlareState::new(agent_url))));
    FLARE_STATE_PID.store(std::process::id(), Ordering::Release);
}

extern "C" fn collect_config_entry(
    name: CharSlice<'_>,
    value: CharSlice<'_>,
    context: *mut c_void,
) {
    if context.is_null() {
        return;
    }
    let values = unsafe { &mut *context.cast::<BTreeMap<String, String>>() };
    values.insert(
        name.to_utf8_lossy().into_owned(),
        value.to_utf8_lossy().into_owned(),
    );
}

fn collect_config(callback: TracerFlareConfigCallback) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    callback(
        collect_config_entry,
        (&mut values as *mut BTreeMap<String, String>).cast(),
    );
    values
}

pub fn process_add(
    data: &RemoteConfigParsed,
    config_id: &str,
    callback: TracerFlareConfigCallback,
) {
    let action = {
        let state = current_state();
        let state = state.lock().unwrap_or_else(|error| error.into_inner());
        match state.manager.handle_remote_config_data(data.deref()) {
            Ok(action) => action,
            Err(error) => {
                debug!("Ignoring invalid tracer flare remote config: {error}");
                return;
            }
        }
    };
    let action_name = match &action {
        FlareAction::Send(_) => "Send",
        FlareAction::Set(_) => "Set",
        FlareAction::Unset => "Unset",
        FlareAction::None => "None",
    };
    debug!("Processing tracer flare remote config action {action_name}");
    match action {
        FlareAction::Set(level) => process_set(config_id, level, collect_config(callback)),
        FlareAction::Unset => process_unset(None),
        FlareAction::Send(task) if is_tracer_flare_task(&task) => {
            process_send(task, collect_config(callback))
        }
        FlareAction::Send(_) | FlareAction::None => {}
    }
}

pub fn process_agent_config_remove(config_id: &str) {
    process_unset(Some(config_id));
}

fn process_set(config_id: &str, requested_level: LogLevel, values: BTreeMap<String, String>) {
    let current = current_log_settings(&values);
    let current_state = current_state();
    let mut state = current_state
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let effective = begin_log_capture(&mut state.original_log_settings, &current, requested_level);
    if state.flare_dir.is_none() {
        match create_flare_dir(std::process::id(), "collect")
            .and_then(|directory| open_capture_file(&directory).map(|file| (directory, file)))
        {
            Ok((directory, file)) => {
                capture_file_slot().store(Some(Arc::new(file)));
                CAPTURE_ACTIVE.store(true, Ordering::Release);
                state.flare_dir = Some(directory);
            }
            Err(error) => {
                state.original_log_settings = None;
                state.effective_log_level = None;
                state.manager = TracerFlareManager::new(&state.agent_url, "php");
                debug!("Unable to start tracer flare log capture: {error}");
                return;
            }
        }
    }
    state.active_config_ids.insert(config_id.to_owned());
    state.effective_log_level = Some(effective.level.clone());
    let original_level = state
        .original_log_settings
        .as_ref()
        .map(|settings| effective_level(&settings.level).to_string())
        .unwrap_or_else(|| "error".to_owned());
    let _ = state.manager.set_original_log_level(&original_level);
    let _ = state.manager.set_current_log_level(&effective.level);
    drop(state);
    set_runtime_log_level(&effective);
}

fn process_unset(config_id: Option<&str>) {
    let (original, directory) = {
        let current_state = current_state();
        let mut state = current_state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(config_id) = config_id {
            if !state.active_config_ids.remove(config_id) {
                return;
            }
        }
        state.active_config_ids.clear();
        state.effective_log_level = None;
        state.manager = TracerFlareManager::new(&state.agent_url, "php");
        (state.original_log_settings.take(), state.flare_dir.take())
    };
    stop_capture();
    if let Some(directory) = directory {
        if let Err(error) = fs::remove_dir_all(directory) {
            debug!("Unable to remove cancelled tracer flare directory: {error}");
        }
    }
    if let Some(original) = original {
        set_runtime_log_level(&original);
    }
}

fn process_send(
    task: libdd_remote_config::config::agent_task::AgentTaskFile,
    values: BTreeMap<String, String>,
) {
    let current = current_log_settings(&values);
    let (directory, agent_url, level, original) = {
        let current_state = current_state();
        let mut state = current_state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        match claim_task_uuid(&task.uuid, &mut state.handled_uuids, &std::env::temp_dir()) {
            Ok(true) => {}
            Ok(false) => {
                debug!("Ignoring duplicate tracer flare task {}", task.uuid);
                return;
            }
            Err(error) => {
                debug!("Unable to claim tracer flare task {}: {error}", task.uuid);
                return;
            }
        }
        let directory = match state.flare_dir.take() {
            Some(directory) => directory,
            None => match create_flare_dir(std::process::id(), &task.uuid) {
                Ok(directory) => directory,
                Err(error) => {
                    debug!("Unable to create tracer flare directory: {error}");
                    return;
                }
            },
        };
        let level = state
            .effective_log_level
            .take()
            .unwrap_or_else(|| current.level.clone());
        state.active_config_ids.clear();
        state.manager = TracerFlareManager::new(&state.agent_url, "php");
        (
            directory,
            state.agent_url.clone(),
            level,
            state.original_log_settings.take(),
        )
    };

    stop_capture();
    let original_level = original
        .as_ref()
        .map(|settings| effective_level(&settings.level).to_string())
        .unwrap_or_else(|| effective_level(&current.level).to_string());
    if let Some(original) = original {
        set_runtime_log_level(&original);
    }

    if let Err(error) = write_tracer_config(&directory, &values) {
        error!("Unable to write tracer flare configuration: {error}");
        remove_flare_directory(&directory);
        return;
    }

    let cleanup_directory = directory.clone();
    let spawn_result = thread::Builder::new()
        .name("dd-tracer-flare".to_owned())
        .spawn(move || {
            let manager = TracerFlareManager::new(&agent_url, "php");
            if let Err(error) = manager.set_original_log_level(&original_level) {
                error!("Unable to set tracer flare upload original log level: {error}");
            }
            if let Err(error) = manager.set_current_log_level(&level) {
                error!("Unable to set tracer flare upload log level: {error}");
            }
            match manager.zip_and_send_sync(
                vec![directory.to_string_lossy().into_owned()],
                FlareAction::Send(task),
            ) {
                Ok(()) => {
                    info!("Tracer flare uploaded successfully");
                }
                Err(error) => {
                    error!("Unable to upload tracer flare: {error}");
                }
            }
            remove_flare_directory(&directory);
        });
    if let Err(error) = spawn_result {
        error!("Unable to start tracer flare upload thread: {error}");
        remove_flare_directory(&cleanup_directory);
    }
}

fn remove_flare_directory(directory: &Path) {
    if let Err(error) = fs::remove_dir_all(directory) {
        if error.kind() != io::ErrorKind::NotFound {
            debug!("Unable to remove tracer flare directory: {error}");
        }
    }
}

fn is_tracer_flare_task(task: &libdd_remote_config::config::agent_task::AgentTaskFile) -> bool {
    task.task_type == "tracer_flare"
}

fn current_log_settings(values: &BTreeMap<String, String>) -> LogSettings {
    let debug_enabled = values
        .get("DD_TRACE_DEBUG")
        .map(|value| is_truthy(value))
        .unwrap_or(false)
        || values
            .get("datadog.trace.debug")
            .map(|value| is_truthy(value))
            .unwrap_or(false);
    let level = if debug_enabled {
        "debug".to_owned()
    } else {
        values
            .get("DD_TRACE_LOG_LEVEL")
            .filter(|value| !value.is_empty())
            .or_else(|| {
                values
                    .get("datadog.trace.log_level")
                    .filter(|value| !value.is_empty())
            })
            .cloned()
            .unwrap_or_else(|| "error".to_owned())
    };
    let once = values
        .get("datadog.trace.once_logs")
        .map(|value| is_truthy(value))
        .unwrap_or(true);
    LogSettings { level, once }
}

fn is_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn begin_log_capture(
    original: &mut Option<LogSettings>,
    current: &LogSettings,
    requested: LogLevel,
) -> LogSettings {
    let original_level = effective_level(&current.level);
    let effective_level = original_level.min(requested);
    if original.is_none() {
        *original = Some(current.clone());
    }
    LogSettings {
        level: effective_level.to_string(),
        once: current.once,
    }
}

fn effective_level(level: &str) -> LogLevel {
    let level = level.trim();
    let directive = level
        .split(',')
        .map(str::trim)
        .find(|directive| directive.starts_with("ddtrace="))
        .map(|directive| directive.trim_start_matches("ddtrace="))
        .or_else(|| {
            level
                .split(',')
                .map(str::trim)
                .find(|directive| !directive.contains('='))
        })
        .unwrap_or(level);
    match directive.to_ascii_lowercase().as_str() {
        "warning" => LogLevel::Warn,
        _ => LogLevel::try_from(directive).unwrap_or(LogLevel::Error),
    }
}

fn set_runtime_log_level(settings: &LogSettings) {
    set_runtime_log_level_with(settings, |filter_level, once| unsafe {
        crate::log::ddog_set_log_level(CharSlice::from_bytes(filter_level.as_bytes()), once);
    });
}

fn set_runtime_log_level_with(settings: &LogSettings, set_log_level: impl FnOnce(&str, bool)) {
    apply_log_settings(settings, set_log_level);
}

fn apply_log_settings(settings: &LogSettings, set_log_level: impl FnOnce(&str, bool)) {
    let filter_level = if settings.level == "critical" {
        "error"
    } else {
        &settings.level
    };
    set_log_level(filter_level, settings.once);
}

fn create_flare_dir(pid: u32, suffix: &str) -> io::Result<PathBuf> {
    let suffix = safe_path_component(suffix);
    let directory = std::env::temp_dir().join(format!("dd-php-tracer-flare-{pid}-{suffix}"));
    match create_private_dir(&directory) {
        Ok(()) => Ok(directory),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let unique = std::env::temp_dir().join(format!(
                "dd-php-tracer-flare-{pid}-{suffix}-{}",
                uuid::Uuid::new_v4()
            ));
            create_private_dir(&unique)?;
            Ok(unique)
        }
        Err(error) => Err(error),
    }
}

fn safe_path_component(value: &str) -> String {
    let component: String = value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || *character == '-')
        .collect();
    if component.is_empty() {
        uuid::Uuid::new_v4().to_string()
    } else {
        component
    }
}

fn create_private_dir(directory: &Path) -> io::Result<()> {
    let mut builder = DirBuilder::new();
    #[cfg(unix)]
    builder.mode(0o700);
    builder.create(directory)
}

fn open_capture_file(directory: &Path) -> io::Result<CaptureFile> {
    let mut options = OpenOptions::new();
    options.create(true).append(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    Ok(CaptureFile {
        file: options.open(directory.join(format!("tracer_php_{}.log", std::process::id())))?,
        write_lock: Mutex::new(()),
    })
}

fn stop_capture() {
    CAPTURE_ACTIVE.store(false, Ordering::Release);
    while CAPTURE_WRITERS.load(Ordering::Acquire) != 0 {
        thread::yield_now();
    }
    capture_file_slot().store(None);
}

pub fn capture_log(message: &str) {
    if !CAPTURE_ACTIVE.load(Ordering::Acquire) {
        return;
    }
    CAPTURE_WRITERS.fetch_add(1, Ordering::AcqRel);
    if !CAPTURE_ACTIVE.load(Ordering::Acquire) {
        CAPTURE_WRITERS.fetch_sub(1, Ordering::Release);
        return;
    }
    let file = capture_file_slot().load();
    if let Some(file) = file.as_ref() {
        let mut line = message.as_bytes().to_vec();
        line.push(b'\n');
        let _lock = file
            .write_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut handle = &file.file;
        let _ = handle.write_all(&line);
    }
    CAPTURE_WRITERS.fetch_sub(1, Ordering::Release);
}

#[no_mangle]
pub extern "C" fn ddog_tracer_flare_after_fork() {
    CAPTURE_ACTIVE.store(false, Ordering::Release);
    CAPTURE_WRITERS.store(0, Ordering::Release);
    capture_file_slot().store(None);
    let agent_url = agent_url_slot()
        .load_full()
        .map(|url| url.as_str().to_owned())
        .unwrap_or_default();
    state_slot().store(Arc::new(Mutex::new(FlareState::new(agent_url))));
    FLARE_STATE_PID.store(std::process::id(), Ordering::Release);
}

fn claim_task_uuid(uuid: &str, handled: &mut HashSet<String>, lock_dir: &Path) -> io::Result<bool> {
    let uuid = safe_path_component(uuid);
    if !handled.insert(uuid.clone()) {
        return Ok(false);
    }
    let path = lock_dir.join(format!("dd-php-tracer-flare-{uuid}.lock"));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    match options.open(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => {
            handled.remove(&uuid);
            Err(error)
        }
    }
}

fn write_tracer_config(directory: &Path, values: &BTreeMap<String, String>) -> io::Result<()> {
    let configuration = values
        .iter()
        .filter(|(name, _)| name.starts_with("datadog."))
        .map(|(name, value)| (name.clone(), redact_config_value(name, value)))
        .collect::<Map<String, Value>>();
    let json = json!({
        "tracer_version": include_str!("../VERSION").trim(),
        "php_version": values.get("php_version").map(String::as_str).unwrap_or(""),
        "sapi": values.get("sapi").map(String::as_str).unwrap_or(""),
        "pid": std::process::id(),
        "configs": configuration,
    });
    let path = directory.join(format!("tracer_config_{}.json", std::process::id()));
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path)?;
    let json = serde_json::to_vec_pretty(&json)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    file.write_all(&json)
}

fn redact_config_value(name: &str, value: &str) -> Value {
    let lower_name = name.to_ascii_lowercase();
    if !(lower_name.contains("api_key") || lower_name.contains("app_key")) {
        return Value::String(value.to_owned());
    }
    let characters: Vec<char> = value.chars().collect();
    let visible = characters.len().min(4);
    Value::String(format!(
        "{}{}",
        "*".repeat(characters.len() - visible),
        characters[characters.len() - visible..]
            .iter()
            .collect::<String>()
    ))
}

fn after_fork() {
    ddog_tracer_flare_after_fork();
}

#[cfg(test)]
mod tests {
    use super::*;
    use libdd_remote_config::config::agent_task::{AgentTask, AgentTaskFile};
    use std::io::Read;
    use std::net::{TcpListener, TcpStream};
    use std::time::Duration;
    use zip::ZipArchive;

    #[test]
    fn redact_sensitive_configuration_values() {
        assert_eq!(
            redact_config_value("datadog.api_key", "secret-value"),
            Value::String("********alue".to_owned())
        );
        assert_eq!(
            redact_config_value("datadog.trace.app_key", "abcd"),
            Value::String("abcd".to_owned())
        );
        assert_eq!(
            redact_config_value("datadog.service", "checkout"),
            Value::String("checkout".to_owned())
        );
    }

    #[test]
    fn tracer_config_is_nonempty_and_redacts_keys() {
        let directory = tempfile::tempdir().expect("tempdir");
        let values = BTreeMap::from([
            ("datadog.api_key".to_owned(), "secret-value".to_owned()),
            ("datadog.service".to_owned(), "checkout".to_owned()),
            ("php_version".to_owned(), "8.2.0".to_owned()),
            ("sapi".to_owned(), "cli".to_owned()),
        ]);

        write_tracer_config(directory.path(), &values).expect("write config");
        let path = directory
            .path()
            .join(format!("tracer_config_{}.json", std::process::id()));
        let config: Value =
            serde_json::from_slice(&fs::read(path).expect("read config")).expect("valid JSON");
        assert_eq!(config["configs"]["datadog.api_key"], "********alue");
        assert_eq!(config["configs"]["datadog.service"], "checkout");
        assert_eq!(config["php_version"], "8.2.0");
        assert_eq!(config["sapi"], "cli");
        assert!(config["pid"].as_u64().is_some());
        assert!(!config["tracer_version"]
            .as_str()
            .unwrap_or_default()
            .is_empty());
    }

    #[test]
    fn debug_configuration_overrides_requested_log_level() {
        let values = BTreeMap::from([
            ("DD_TRACE_DEBUG".to_owned(), "1".to_owned()),
            ("datadog.trace.log_level".to_owned(), "error".to_owned()),
        ]);
        let current = current_log_settings(&values);
        assert_eq!(current.level, "debug");
        let mut original = None;
        assert_eq!(
            begin_log_capture(&mut original, &current, LogLevel::Info).level,
            "debug"
        );
    }

    #[test]
    fn set_then_unset_restores_original_log_settings() {
        let current = LogSettings {
            level: "warn".to_owned(),
            once: false,
        };
        let mut original = None;
        let effective = begin_log_capture(&mut original, &current, LogLevel::Debug);
        assert_eq!(effective.level, "debug");
        assert!(!effective.once);
        assert_eq!(
            original.as_ref().map(|value| value.level.as_str()),
            Some("warn")
        );

        let restored = original.take().expect("set captured original settings");
        let mut applied = Vec::new();
        set_runtime_log_level_with(&effective, |level, once| {
            applied.push((level.to_owned(), once))
        });
        set_runtime_log_level_with(&restored, |level, once| {
            applied.push((level.to_owned(), once))
        });
        assert_eq!(
            applied,
            [("debug".to_owned(), false), ("warn".to_owned(), false)]
        );
    }

    #[test]
    fn flare_task_uuid_is_deduplicated_by_process_and_lockfile() {
        let directory = tempfile::tempdir().expect("tempdir");
        let mut handled = HashSet::new();
        assert!(claim_task_uuid("case-uuid", &mut handled, directory.path()).unwrap());
        assert!(!claim_task_uuid("case-uuid", &mut handled, directory.path()).unwrap());

        let mut another_process = HashSet::new();
        assert!(!claim_task_uuid("case-uuid", &mut another_process, directory.path()).unwrap());
    }

    #[test]
    fn only_tracer_flare_tasks_are_accepted() {
        let task = |task_type: &str| AgentTaskFile {
            args: AgentTask {
                case_id: "case".to_owned(),
                hostname: "host".to_owned(),
                user_handle: "user@example.com".to_owned(),
            },
            task_type: task_type.to_owned(),
            uuid: "uuid".to_owned(),
        };
        assert!(is_tracer_flare_task(&task("tracer_flare")));
        assert!(!is_tracer_flare_task(&task("other_task")));
    }

    #[test]
    fn flare_upload_contains_multipart_fields_and_valid_zip() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock agent");
        let address = listener.local_addr().expect("mock agent address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept upload");
            let request = read_http_request(&mut stream);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .expect("respond to upload");
            request
        });

        let directory = tempfile::tempdir().expect("tempdir");
        fs::write(directory.path().join("config.json"), b"{\"enabled\":true}")
            .expect("write fixture");
        let task = AgentTaskFile {
            args: AgentTask {
                case_id: "case-id".to_owned(),
                hostname: "flare-host".to_owned(),
                user_handle: "user@example.com".to_owned(),
            },
            task_type: "tracer_flare".to_owned(),
            uuid: "flare-uuid".to_owned(),
        };
        let manager = TracerFlareManager::new(&format!("http://{address}"), "php");
        manager
            .set_current_log_level("debug")
            .expect("set upload log level");
        manager
            .zip_and_send_sync(
                vec![directory.path().to_string_lossy().into_owned()],
                FlareAction::Send(task),
            )
            .expect("upload flare");

        let request = server.join().expect("mock agent thread");
        let request_text = String::from_utf8_lossy(&request);
        assert!(request_text.starts_with("POST /tracer_flare/v1 "));
        for field in [
            "source",
            "case_id",
            "hostname",
            "email",
            "uuid",
            "flare_file",
        ] {
            assert!(
                request_text.contains(&format!("name=\"{field}\"")),
                "missing {field}"
            );
        }
        assert!(request_text.contains("case-id"));
        assert!(request_text.contains("flare-host"));
        assert!(request_text.contains("flare-uuid"));
        assert!(request_text.contains("tracer_php"));
        assert!(request_text.contains("user@example.com"));

        let raw = request.as_slice();
        let marker = b"name=\"flare_file\"";
        let field_start = raw
            .windows(marker.len())
            .position(|window| window == marker)
            .expect("flare file multipart field");
        let content_type = request_text
            .lines()
            .find(|line| line.to_ascii_lowercase().starts_with("content-type:"))
            .expect("multipart content type");
        let boundary = content_type
            .split_once("boundary=")
            .expect("multipart boundary")
            .1
            .trim()
            .trim_matches('"');
        let data_start = raw[field_start..]
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("multipart file content start")
            + field_start
            + 4;
        let delimiter = format!("\r\n--{boundary}");
        let boundary_end = raw[data_start..]
            .windows(delimiter.len())
            .position(|window| window == delimiter.as_bytes())
            .expect("multipart file content end")
            + data_start;
        let archive = ZipArchive::new(std::io::Cursor::new(&raw[data_start..boundary_end]))
            .expect("valid flare zip");
        assert!(!archive.is_empty());
    }

    fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("set socket timeout");
        let mut request = Vec::new();
        let mut chunk = [0; 4096];
        loop {
            let read = stream.read(&mut chunk).expect("read request");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
            let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n")
            else {
                continue;
            };
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let chunked = headers.lines().any(|line| {
                line.split_once(':')
                    .map(|(name, value)| {
                        name.eq_ignore_ascii_case("transfer-encoding")
                            && value.trim().eq_ignore_ascii_case("chunked")
                    })
                    .unwrap_or(false)
            });
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or_default();
            if (chunked && request.windows(5).any(|window| window == b"0\r\n\r\n"))
                || (!chunked && request.len() >= header_end + 4 + content_length)
            {
                break;
            }
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .expect("respond");
        request
    }
}
