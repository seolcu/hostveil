use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const HOSTVEIL_CONFIG_DIR_ENV: &str = "HOSTVEIL_CONFIG_DIR";
const XDG_CONFIG_HOME_ENV: &str = "XDG_CONFIG_HOME";
const HOME_ENV: &str = "HOME";
const CONFIG_FILE_NAME: &str = "config.json";

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AppSettings {
    pub locale: Option<String>,
    pub theme: Option<String>,
    pub layout: Option<String>,
    pub ui_borders: Option<bool>,
    pub severity_filter: Option<String>,
    pub source_filter: Option<String>,
    pub service_filter: Option<String>,
    pub remediation_filter: Option<String>,
    pub sort_mode: Option<String>,
}

pub fn load() -> AppSettings {
    load_with_path_result(config_file_path())
}

pub fn persist_locale(locale: &str) -> io::Result<()> {
    let mut settings = load();
    settings.locale = Some(locale.to_owned());
    save(&settings)
}

pub fn persist_theme(theme: &str) -> io::Result<()> {
    let mut settings = load();
    settings.theme = Some(theme.to_owned());
    save(&settings)
}

pub fn persist_layout(layout: &str) -> io::Result<()> {
    let mut settings = load();
    settings.layout = Some(layout.to_owned());
    save(&settings)
}

pub fn persist_ui_borders(enabled: bool) -> io::Result<()> {
    let mut settings = load();
    settings.ui_borders = Some(enabled);
    save(&settings)
}

pub fn persist_findings_view(
    severity_filter: Option<&str>,
    source_filter: Option<&str>,
    service_filter: Option<&str>,
    remediation_filter: Option<&str>,
    sort_mode: Option<&str>,
) -> io::Result<()> {
    let mut settings = load();
    settings.severity_filter = severity_filter.map(str::to_owned);
    settings.source_filter = source_filter.map(str::to_owned);
    settings.service_filter = service_filter.map(str::to_owned);
    settings.remediation_filter = remediation_filter.map(str::to_owned);
    settings.sort_mode = sort_mode.map(str::to_owned);
    save(&settings)
}

fn save(settings: &AppSettings) -> io::Result<()> {
    let path = config_file_path()?;
    save_to_path(&path, settings)
}

fn load_from_path(path: &Path) -> io::Result<AppSettings> {
    let text = fs::read_to_string(path)?;
    serde_json::from_str(&text).map_err(|error| io::Error::other(error.to_string()))
}

fn load_with_path_result(path_result: io::Result<PathBuf>) -> AppSettings {
    match path_result {
        Ok(path) => match load_from_path(&path) {
            Ok(settings) => settings,
            Err(error) if error.kind() == io::ErrorKind::NotFound => AppSettings::default(),
            Err(error) => {
                #[cfg(debug_assertions)]
                eprintln!(
                    "hostveil: failed to load settings from {}: {}",
                    path.display(),
                    error
                );
                AppSettings::default()
            }
        },
        Err(error) => {
            #[cfg(debug_assertions)]
            eprintln!("hostveil: failed to resolve config directory: {}", error);
            AppSettings::default()
        }
    }
}

fn save_to_path(path: &Path, settings: &AppSettings) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let text = serde_json::to_string_pretty(settings)
        .map_err(|error| io::Error::other(error.to_string()))?;
    fs::write(path, text + "\n")
}

fn config_file_path() -> io::Result<PathBuf> {
    resolve_config_dir(
        env::var(HOSTVEIL_CONFIG_DIR_ENV).ok().as_deref(),
        env::var(XDG_CONFIG_HOME_ENV).ok().as_deref(),
        env::var(HOME_ENV).ok().as_deref(),
    )
    .map(|dir| dir.join(CONFIG_FILE_NAME))
    .ok_or_else(|| io::Error::other("failed to resolve a hostveil config directory"))
}

pub fn resolve_config_dir(
    explicit_dir: Option<&str>,
    xdg_config_home: Option<&str>,
    home: Option<&str>,
) -> Option<PathBuf> {
    explicit_dir
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            xdg_config_home
                .filter(|value| !value.trim().is_empty())
                .map(PathBuf::from)
                .map(|path| path.join("hostveil"))
        })
        .or_else(|| {
            home.filter(|value| !value.trim().is_empty())
                .map(PathBuf::from)
                .map(|path| path.join(".config").join("hostveil"))
        })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use super::{
        AppSettings, load_from_path, load_with_path_result, resolve_config_dir, save_to_path,
    };

    fn temp_settings_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should move forward")
            .as_nanos();
        std::env::temp_dir()
            .join(format!(
                "hostveil-settings-{name}-{}-{nanos}",
                std::process::id()
            ))
            .join("config.json")
    }

    #[test]
    fn prefers_explicit_config_dir() {
        let dir = resolve_config_dir(Some("/tmp/hostveil"), Some("/xdg"), Some("/home/user"))
            .expect("dir should resolve");

        assert_eq!(dir, PathBuf::from("/tmp/hostveil"));
    }

    #[test]
    fn falls_back_to_xdg_config_home() {
        let dir =
            resolve_config_dir(None, Some("/xdg"), Some("/home/user")).expect("dir should resolve");

        assert_eq!(dir, PathBuf::from("/xdg/hostveil"));
    }

    #[test]
    fn falls_back_to_home_config_dir() {
        let dir = resolve_config_dir(None, None, Some("/home/user")).expect("dir should resolve");

        assert_eq!(dir, PathBuf::from("/home/user/.config/hostveil"));
    }

    #[test]
    fn returns_none_when_no_config_base_exists() {
        assert!(resolve_config_dir(None, None, None).is_none());
    }

    #[test]
    fn saves_settings_as_json() {
        let path = temp_settings_path("save");
        let settings = AppSettings {
            locale: Some(String::from("ko")),
            theme: Some(String::from("nord")),
            layout: Some(String::from("balanced")),
            ..Default::default()
        };

        save_to_path(&path, &settings).expect("settings should save");

        let written = fs::read_to_string(&path).expect("settings file should exist");
        assert!(written.contains("\"locale\": \"ko\""));
        assert!(written.contains("\"theme\": \"nord\""));
        assert!(written.contains("\"layout\": \"balanced\""));

        fs::remove_dir_all(path.parent().expect("config dir should exist"))
            .expect("temp dir should be removed");
    }

    #[test]
    fn loads_saved_theme_and_locale_round_trip() {
        let path = temp_settings_path("roundtrip");
        let settings = AppSettings {
            locale: Some(String::from("en")),
            theme: Some(String::from("tokyo_night")),
            layout: Some(String::from("wide")),
            ..Default::default()
        };

        save_to_path(&path, &settings).expect("settings should save");

        let loaded = load_from_path(&path).expect("settings should load");
        assert_eq!(loaded, settings);

        fs::remove_dir_all(path.parent().expect("config dir should exist"))
            .expect("temp dir should be removed");
    }

    #[test]
    fn load_from_path_returns_default_for_malformed_json() {
        let path = temp_settings_path("malformed");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("parent dir should be created");
        }
        fs::write(&path, "not json at all").expect("write should succeed");

        let loaded = load_from_path(&path);
        assert!(loaded.is_err(), "malformed JSON should produce an error");

        fs::remove_dir_all(path.parent().expect("config dir should exist"))
            .expect("temp dir should be removed");
    }

    #[test]
    fn load_from_path_returns_default_for_missing_file() {
        let path = temp_settings_path("missing");

        let loaded = load_from_path(&path);
        assert!(loaded.is_err(), "missing file should produce an error");

        // clean up parent dir if it was created
        if let Some(parent) = path.parent() {
            let _ = fs::remove_dir_all(parent);
        }
    }

    #[test]
    fn load_returns_default_for_missing_file_without_error() {
        let path = temp_settings_path("load-missing-default");

        let loaded = load_with_path_result(Ok(path));
        assert_eq!(loaded, AppSettings::default());
    }

    #[test]
    fn load_returns_default_for_malformed_json() {
        let path = temp_settings_path("load-malformed-default");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("parent dir should be created");
        }
        fs::write(&path, "not json at all").expect("write should succeed");

        let loaded = load_with_path_result(Ok(path.clone()));
        assert_eq!(loaded, AppSettings::default());

        fs::remove_dir_all(path.parent().expect("config dir should exist"))
            .expect("temp dir should be removed");
    }

    #[test]
    fn load_returns_default_for_path_resolution_failure() {
        let loaded = load_with_path_result(Err(io::Error::other("boom")));
        assert_eq!(loaded, AppSettings::default());
    }

    #[cfg(unix)]
    #[test]
    fn save_to_path_returns_error_for_unwritable_dir() {
        let root = std::env::temp_dir().join(format!(
            "hostveil-settings-unwritable-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time should move forward")
                .as_nanos()
        ));
        fs::create_dir_all(&root).expect("temp dir should be created");
        let path = root.join("config.json");
        let settings = AppSettings {
            locale: Some(String::from("en")),
            ..Default::default()
        };

        let original_permissions = fs::metadata(&root)
            .expect("dir metadata should exist")
            .permissions();
        let mut read_only_permissions = original_permissions.clone();
        read_only_permissions.set_mode(0o555);
        fs::set_permissions(&root, read_only_permissions).expect("dir should become read-only");

        let result = save_to_path(&path, &settings);

        fs::set_permissions(&root, original_permissions).expect("dir permissions should restore");
        fs::remove_dir_all(&root).expect("temp dir should be removed");

        assert!(result.is_err(), "save should fail for unwritable dir");
    }

    #[test]
    fn persist_theme_updates_and_roundtrips() {
        let path = temp_settings_path("persist-theme");
        let settings = AppSettings {
            theme: Some(String::from("monokai")),
            ..Default::default()
        };
        save_to_path(&path, &settings).expect("save should succeed");

        let loaded = load_from_path(&path).expect("load should succeed");
        assert_eq!(loaded.theme.as_deref(), Some("monokai"));

        fs::remove_dir_all(path.parent().expect("has parent")).ok();
    }

    #[test]
    fn persist_locale_updates_and_roundtrips() {
        let path = temp_settings_path("persist-locale");
        let settings = AppSettings {
            locale: Some(String::from("ko")),
            ..Default::default()
        };
        save_to_path(&path, &settings).expect("save should succeed");

        let loaded = load_from_path(&path).expect("load should succeed");
        assert_eq!(loaded.locale.as_deref(), Some("ko"));

        fs::remove_dir_all(path.parent().expect("has parent")).ok();
    }

    #[test]
    fn persist_ui_borders_roundtrips() {
        let path = temp_settings_path("persist-borders");
        let settings = AppSettings {
            ui_borders: Some(true),
            ..Default::default()
        };
        save_to_path(&path, &settings).expect("save should succeed");

        let loaded = load_from_path(&path).expect("load should succeed");
        assert_eq!(loaded.ui_borders, Some(true));

        // Toggle off
        let settings_off = AppSettings {
            ui_borders: Some(false),
            ..Default::default()
        };
        save_to_path(&path, &settings_off).expect("save should succeed");
        let loaded_off = load_from_path(&path).expect("load should succeed");
        assert_eq!(loaded_off.ui_borders, Some(false));

        fs::remove_dir_all(path.parent().expect("has parent")).ok();
    }

    #[test]
    fn persist_findings_view_roundtrips() {
        let path = temp_settings_path("persist-findings-view");
        let settings = AppSettings {
            severity_filter: Some(String::from("critical")),
            source_filter: Some(String::from("dockle")),
            service_filter: Some(String::from("web")),
            remediation_filter: Some(String::from("auto")),
            sort_mode: Some(String::from("severity")),
            ..Default::default()
        };
        save_to_path(&path, &settings).expect("save should succeed");

        let loaded = load_from_path(&path).expect("load should succeed");
        assert_eq!(loaded.severity_filter.as_deref(), Some("critical"));
        assert_eq!(loaded.source_filter.as_deref(), Some("dockle"));
        assert_eq!(loaded.service_filter.as_deref(), Some("web"));
        assert_eq!(loaded.remediation_filter.as_deref(), Some("auto"));
        assert_eq!(loaded.sort_mode.as_deref(), Some("severity"));

        fs::remove_dir_all(path.parent().expect("has parent")).ok();
    }

    #[test]
    fn persist_empty_findings_view_clears_all_filters() {
        let path = temp_settings_path("persist-findings-clear");
        let settings = AppSettings {
            severity_filter: Some(String::from("high")),
            source_filter: Some(String::from("lynis")),
            ..Default::default()
        };
        save_to_path(&path, &settings).expect("save should succeed");

        // Now save with all None — should clear
        let cleared = AppSettings::default();
        save_to_path(&path, &cleared).expect("save should succeed");

        let loaded = load_from_path(&path).expect("load should succeed");
        assert!(loaded.severity_filter.is_none());
        assert!(loaded.source_filter.is_none());
        assert!(loaded.service_filter.is_none());

        fs::remove_dir_all(path.parent().expect("has parent")).ok();
    }

    #[test]
    fn resolve_config_dir_returns_none_for_empty_strings() {
        assert_eq!(resolve_config_dir(Some(""), None, None), None);
        assert_eq!(resolve_config_dir(Some("  "), None, None), None);
        assert!(resolve_config_dir(Some("valid"), None, None).is_some());
    }
}
